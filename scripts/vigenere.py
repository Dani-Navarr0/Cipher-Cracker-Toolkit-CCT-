from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
import time
from functools import lru_cache
import os
import random
import math
import re
from pathlib import Path
from collections import Counter
from utils.utils import get_input_ciphertexts
from ngram_scoring import (
    DEFAULT_NGRAM_PATH,
    DEFAULT_NGRAM_SIZE,
    NGRAM_DIRECTORY,
    _NGRAM_FILES,
    add_spaces,
    available_spacing_models,
    load_spacing_model,
    load_ngram_scores,
    resolve_ngram_path,
    score_text,
)

# --- KASISKI IMPORT ---
try:
    from scripts.kasiski import analyze_kasiski
except ImportError:
    try:
        from kasiski import analyze_kasiski
    except ImportError:
        analyze_kasiski = None

# --- DUMMY UTILS CLASS ---
class DummyUtils:
    def calculate_ioc(self, text: str) -> float:
        text = text.upper()
        text = ''.join(filter(str.isalpha, text))
        n = len(text)
        if n < 2: return 0.0
        freqs = {}
        for char in text:
            freqs[char] = freqs.get(char, 0) + 1
        numerator = sum(count * (count - 1) for count in freqs.values())
        denominator = n * (n - 1)
        return numerator / denominator if denominator > 0 else 0.0

    def save_results_to_file(self, results: List[Dict], filename: str, include_phrases: bool = True):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("Vigenere Cipher Brute-Force Results\n")
                f.write("=====================================\n\n")
                for result in results:
                    f.write(f"Key: {result['key']}\n")
                    if 'key_length' in result:
                        f.write(f"Key Length: {result['key_length']}\n")
                    if 'alphabet_used' in result:
                        f.write(f"Alphabet: {result['alphabet_used']}\n")
                    if 'ioc' in result:
                        f.write(f"IoC Score: {result.get('ioc', 0):.4f}\n")
                    if 'bigram_score' in result:
                        f.write(f"Fitness Score: {result.get('bigram_score', 0):.2f}\n")
                    if include_phrases and result.get('is_phrase_match'):
                        f.write(f"Matched Phrases: {', '.join(result.get('matched_phrases', []))}\n")
                    f.write(f"Plaintext: {result['plaintext']}\n")
                    f.write("-" * 20 + "\n")
            print(f"{GREEN}Results successfully saved to {filename}{RESET}")
        except IOError as e:
            print(f"{RED}Error saving file: {e}{RESET}")

utils = DummyUtils()

# --- COLOR CODES AND PATHS ---
RESET = '\033[0m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[31m'
BLUE = '\033[34m'
CYAN = '\033[36m'
WHITE = '\033[37m'
GREY = '\033[90m'

data_dir = os.path.join(os.path.dirname(__file__), "data")
dictionary_path = os.path.join(data_dir, "words_alpha.txt")
ngram_path = DEFAULT_NGRAM_PATH

# --- SCORING & MODEL SELECTION FUNCTIONS ---

@lru_cache(maxsize=None)
def load_bigram_frequencies(file_path: str) -> Dict[str, float]:
    return load_ngram_scores(file_path)

def calculate_bigram_score(text: str, expected_freqs: Dict[str, float]) -> float:
    return score_text(text, expected_freqs)

def parse_key_length_input(user_input: str, default: int = 5) -> Tuple[int, int]:
    """Parses single integer '5' or range '3-10'."""
    user_input = user_input.strip()
    if not user_input:
        return default, default
    if "-" in user_input:
        parts = user_input.split("-")
        try:
            k1, k2 = int(parts[0].strip()), int(parts[1].strip())
            return max(1, min(k1, k2)), max(1, max(k1, k2))
        except ValueError:
            pass
    elif user_input.isdigit():
        val = int(user_input)
        return max(1, val), max(1, val)
    return default, default

def select_ngram_path() -> Path:
    """Prompts user to select N-gram size or custom path."""
    print(f"\n{GREY}Select N-gram Model:{RESET}")
    sizes = sorted(_NGRAM_FILES.keys())
    for sz in sizes:
        default_tag = " (DEFAULT)" if sz == 5 else ""
        filename = _NGRAM_FILES[sz]
        print(f"  [{sz}] {sz}-gram -> {filename}{default_tag}")

    other_files = []
    if NGRAM_DIRECTORY.exists():
        other_files = [
            f for f in NGRAM_DIRECTORY.iterdir()
            if f.is_file() and f.name not in _NGRAM_FILES.values()
        ]

    if other_files:
        print("\nAdditional N-gram files found:")
        for idx, fpath in enumerate(other_files, start=7):
            print(f"  [{idx}] {fpath.name}")

    choice = input(f"\nEnter size (2-6), file number, or custom path (default: {YELLOW}5{RESET}): ").strip()

    if not choice:
        return DEFAULT_NGRAM_PATH

    if choice.isdigit():
        val = int(choice)
        if val in _NGRAM_FILES:
            return resolve_ngram_path(val)
        if 7 <= val < 7 + len(other_files):
            return other_files[val - 7]

    custom_path = Path(choice)
    if custom_path.exists():
        return custom_path

    rel_path = NGRAM_DIRECTORY / choice
    if rel_path.exists():
        return rel_path

    print(f"{YELLOW}File/size '{choice}' not found. Falling back to default (5-gram).{RESET}")
    return DEFAULT_NGRAM_PATH


def select_spacing_model_path(ngram_path_input: Path) -> Path:
    models = available_spacing_models()
    if not models:
        raise FileNotFoundError(f"No spacing n-gram models found under {NGRAM_DIRECTORY / 'Spaces'}")

    normalized_ngram_name = re.sub(r"[^a-z0-9]", "", ngram_path_input.name.casefold())
    default_index = next(
        (
            index for index, model_path in enumerate(models)
            if re.sub(r"[^a-z0-9]", "", model_path.parent.name.casefold()) in normalized_ngram_name
        ),
        0,
    )

    print(f"\n{GREY}Select spacing language:{RESET}")
    for index, model_path in enumerate(models):
        default_tag = " (DEFAULT)" if index == default_index else ""
        print(f"  [{index + 1}] {model_path.parent.name}{default_tag}")

    while True:
        choice = input(f"Language number (default {default_index + 1}): ").strip()
        if not choice:
            return models[default_index]
        if choice.isdigit() and 1 <= int(choice) <= len(models):
            return models[int(choice) - 1]
        print(f"{YELLOW}Choose a number from 1 to {len(models)}.{RESET}")


def calculate_fitness(text: str, ngram_model, ent_weight: float) -> float:
    scores = ngram_model.scores
    ngram_size = ngram_model.size
    
    letters = "".join(char for char in text.upper() if "A" <= char <= "Z")
    al = len(letters) - ngram_size + 1
    if al <= 0:
        return 0.0

    total_score = 0
    if isinstance(scores, (bytes, bytearray)):
        for index in range(al):
            ngram_index = 0
            for char in letters[index:index + ngram_size]:
                ngram_index = ngram_index * 26 + ord(char) - ord("A")
            total_score += scores[ngram_index]
    else:
        for index in range(al):
            total_score += scores.get(letters[index:index + ngram_size], 0)

    L = len(letters)
    freqs = Counter(letters)
    entropy = 0.0
    for count in freqs.values():
        p = count / L
        entropy += abs(math.log2(p) * p)

    mean_score = total_score / al
    return mean_score * (entropy ** ent_weight)

# --- VIGENERE CORE FUNCTIONS ---

@lru_cache(maxsize=None)
def get_alphabet(alphabet_str: str):
    alphabet = alphabet_str.upper()
    alphabet_dict = {char: i for i, char in enumerate(alphabet)}
    return alphabet, alphabet_dict

def decrypt_vigenere(ciphertext: str, key: str, alphabet_str: str) -> str:
    alphabet, alphabet_dict = get_alphabet(alphabet_str)
    alphabet_length = len(alphabet)
    key_shifts = [alphabet_dict.get(k, 0) for k in key.upper() if k in alphabet_dict]
    if not key_shifts: return ciphertext
    plaintext = []
    key_index = 0
    for char in ciphertext:
        char_upper = char.upper()
        if char_upper in alphabet_dict:
            char_index = alphabet_dict[char_upper]
            shift = key_shifts[key_index % len(key_shifts)]
            decrypted_char = alphabet[(char_index - shift + alphabet_length) % alphabet_length]
            plaintext.append(decrypted_char.lower())
            key_index += 1
        else:
            plaintext.append(char.lower())
    return ''.join(plaintext)

def load_dictionary(file_path: str, alphabet_str: str, min_length: int = 3, max_length: int = 15, allowed_lengths: List[int] = None) -> List[str]:
    alphabet, _ = get_alphabet(alphabet_str)
    alphabet_set = set(alphabet)
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            if allowed_lengths:
                return [word.strip().upper() for word in file
                        if set(word.strip().upper()).issubset(alphabet_set)
                        and len(word.strip()) in allowed_lengths]
            else:
                return [word.strip().upper() for word in file
                        if set(word.strip().upper()).issubset(alphabet_set)
                        and min_length <= len(word.strip()) <= max_length]
    except FileNotFoundError:
        print(f"{RED}Error: {file_path} not found{RESET}")
        return []

def contains_all_phrases(text: str, phrases: List[str]) -> bool:
    if not phrases: return False
    return all(phrase.upper() in text.upper().replace(" ", "") for phrase in phrases)

def highlight_phrases(text: str, phrases: List[str]) -> str:
    highlighted_text = text.lower()
    if not phrases: return highlighted_text
    for phrase in phrases:
        phrase_lower = phrase.lower().replace(" ", "")
        highlighted_text = highlighted_text.replace(phrase_lower, f"{RED}{phrase_lower}{RESET}")
    return highlighted_text

# --- ATTACK FUNCTIONS ---

def process_batch(args: Tuple) -> List[Dict]:
    word_batch, ciphertext, target_phrases, alphabet_str, expected_freqs, min_ioc, max_ioc = args
    results = []
    
    for word in word_batch:
        plaintext = decrypt_vigenere(ciphertext, word, alphabet_str)
        is_phrase_match = contains_all_phrases(plaintext, target_phrases)
        
        ioc = utils.calculate_ioc(plaintext)
        
        if is_phrase_match or (min_ioc <= ioc <= max_ioc):
            bigram_score = calculate_bigram_score(plaintext, expected_freqs)
            
            results.append({
                'key': word, 'plaintext': plaintext, 'ioc': ioc, 'bigram_score': bigram_score,
                'is_phrase_match': is_phrase_match,
                'matched_phrases': target_phrases if is_phrase_match else []
            })
            
    return results

def batch_words(words: List[str], batch_size: int = 500) -> List[List[str]]:
    return [words[i:i + batch_size] for i in range(0, len(words), batch_size)]

def run_dictionary_attack(ciphertext: str, alphabet_str: str, expected_freqs: Dict, config: Dict):
    target_phrases = config.get('target_phrases', [])
    specific_keys = config.get('specific_keys', [])
    min_ioc = config.get('min_ioc', 0.065)
    max_ioc = config.get('max_ioc', 0.070)
    allowed_lengths = config.get('allowed_lengths', None)
    
    all_results = []
    
    if config.get('use_kasiski') and analyze_kasiski:
        print(f"\n{CYAN}Running Kasiski Analysis to determine key length...{RESET}")
        likely_lengths = analyze_kasiski(ciphertext)
        if likely_lengths:
            allowed_lengths = likely_lengths[:3]
            print(f"{GREEN}Filtering dictionary to words of length: {allowed_lengths}{RESET}")
        else:
            print(f"{YELLOW}Kasiski did not find reliable lengths. Testing all dictionary words.{RESET}")
    
    if specific_keys:
        print(f"\n{YELLOW}Checking specific keys...{RESET}")
        for key in specific_keys:
            plaintext = decrypt_vigenere(ciphertext, key, alphabet_str)
            is_phrase_match = contains_all_phrases(plaintext, target_phrases)
            ioc = utils.calculate_ioc(plaintext)
            if is_phrase_match or (min_ioc <= ioc <= max_ioc):
                bigram_score = calculate_bigram_score(plaintext, expected_freqs)
                all_results.append({
                    'key': key, 'plaintext': plaintext, 'ioc': ioc, 'bigram_score': bigram_score,
                    'is_phrase_match': is_phrase_match, 'matched_phrases': target_phrases if is_phrase_match else []
                })
                if is_phrase_match: print(f"Phrase match found with specific key: {RED}{key}{RESET}")
            
    print(f"{YELLOW}Loading dictionary for alphabet {alphabet_str[:10]}...{RESET}")
    dictionary = load_dictionary(dictionary_path, alphabet_str, allowed_lengths=allowed_lengths)
    
    if dictionary:
        word_batches = batch_words(dictionary)
        num_processes = max(1, os.cpu_count() - 1)
        total_batches = len(word_batches)
        
        print(f"Processing {YELLOW}{len(dictionary):,}{RESET} words with {YELLOW}{num_processes}{RESET} processes...")
        start_time = time.time()
        
        with ProcessPoolExecutor(max_workers=num_processes) as executor:
            futures = [executor.submit(process_batch, (b, ciphertext, target_phrases, alphabet_str, expected_freqs, min_ioc, max_ioc)) for b in word_batches]
            for i, future in enumerate(as_completed(futures)):
                all_results.extend(future.result())
                if total_batches > 10:
                    print(f"Progress: {(i + 1) / total_batches:.1%}", end='\r')
        print(f"\nDictionary search complete in {time.time() - start_time:.2f} seconds.{RESET}")
    
    filtered_results = all_results 
    filtered_results.sort(key=lambda x: (
        0 if x['is_phrase_match'] else 1, 
        0 if min_ioc <= x['ioc'] <= max_ioc else 1,
        x['bigram_score'], 
        -x['ioc']
    ))

    if filtered_results:
        print(f"\n{YELLOW}--- TOP 5 MATCHES ---{RESET}")
        for i, result in enumerate(filtered_results[:5]):
            range_marker = GREEN + " (IoC Match)" + RESET if min_ioc <= result['ioc'] <= max_ioc else ""
            phrase_marker = YELLOW + " (Phrase Match)" + RESET if result['is_phrase_match'] else ""
            highlighted = highlight_phrases(result['plaintext'], result['matched_phrases'])
            print(f"Rank #{i+1}: Key: {YELLOW}{result['key']}{RESET}{phrase_marker}")
            print(f"Scores: IoC: {YELLOW}{result['ioc']:.4f}{RESET}{range_marker} | N-gram: {YELLOW}{result['bigram_score']:.2f}{RESET}")
            print(f"Text: {highlighted[:100]}...")
            print(f"{GREY}-{'':-^30}{RESET}")
    else:
        print(f"{RED}NO SOLUTIONS FOUND in specified IoC range.{RESET}")
        
    return filtered_results


def modify_vigenere_key(key: str, alphabet: str) -> str:
    key_list = list(key)
    idx = random.randrange(len(key_list))
    current_char = key_list[idx]
    if len(alphabet) > 1:
        choices = [c for c in alphabet if c != current_char]
        key_list[idx] = random.choice(choices) if choices else random.choice(alphabet)
    else:
        key_list[idx] = random.choice(alphabet)
    return "".join(key_list)


def run_simulated_annealing_pass(
    ciphertext: str,
    alphabet_str: str,
    key_length: int,
    ngram_model,
    starting_temp: float,
    cooling_rate: float,
    steps_per_temp: int,
    ent_weight: float,
) -> Tuple[str, float, str]:
    alphabet, _ = get_alphabet(alphabet_str)
    current_key = "".join(random.choice(alphabet) for _ in range(key_length))
    current_text = decrypt_vigenere(ciphertext, current_key, alphabet_str)
    current_score = calculate_fitness(current_text, ngram_model, ent_weight)
    
    best_key = current_key
    best_score = current_score
    
    temp = starting_temp
    iteration = 0
    start_time = time.time()
    
    try:
        while temp > 0.1:
            for _ in range(steps_per_temp):
                new_key = modify_vigenere_key(current_key, alphabet)
                new_text = decrypt_vigenere(ciphertext, new_key, alphabet_str)
                new_score = calculate_fitness(new_text, ngram_model, ent_weight)
                
                score_diff = new_score - current_score
                
                if score_diff > 0:
                    current_key = new_key
                    current_score = new_score
                    
                    if new_score > best_score:
                        best_score = new_score
                        best_key = new_key
                        
                elif temp > 0:
                    probability = math.exp(score_diff / temp)
                    if random.random() < probability:
                        current_key = new_key
                        current_score = new_score
            
            temp *= cooling_rate
            iteration += 1
            
            if iteration % 10 == 0:
                best_text_sample = decrypt_vigenere(ciphertext, best_key, alphabet_str).replace('\n', ' ')[:40]
                print(f"Temp: {temp:>5.2f} | Best Score: {GREEN}{best_score:>8.2f}{RESET} | Text: {best_text_sample}...", end='\r')
    except KeyboardInterrupt:
        print("\nPass manually interrupted.")

    time_taken = time.time() - start_time
    best_text = decrypt_vigenere(ciphertext, best_key, alphabet_str)
    print(f"\n{GREEN}Pass Complete in {time_taken:.2f}s! Best Score: {best_score:.2f}{RESET}")
    return best_key, best_score, best_text


def run_simulated_annealing_attack(ciphertext: str, alphabet_str: str, expected_freqs_default: Dict, config: Dict):
    min_kl = config.get('min_key_length', 5)
    max_kl = config.get('max_key_length', 5)
    starting_temp = config.get('starting_temp', 20.0)
    cooling_rate = config.get('cooling_rate', 0.995)
    steps_per_temp = config.get('steps_per_temp', 1000)
    runs = config.get('runs', 3)
    ent_weight = config.get('ent_weight', 0.5)
    selected_ngram_path = config.get('ngram_path', ngram_path)
    enable_spacing = config.get('enable_spacing', False)
    spacing_model = config.get('spacing_model', None)

    if isinstance(selected_ngram_path, (str, Path)):
        print(f"\n{BLUE}--- Simulated Annealing Engine (Vigenère) ---{RESET}")
        print(f"{GREY}Loading N-gram model from: {YELLOW}{Path(selected_ngram_path).name}{RESET}")
        ngram_model = load_ngram_scores(selected_ngram_path)
    else:
        ngram_model = selected_ngram_path

    print(f"{GREY}Key Range: {min_kl}-{max_kl} | Starting Temp: {starting_temp} | Cooling Rate: {cooling_rate} | Steps/Temp: {steps_per_temp} | Passes/Len: {runs} | Ent Weight: {ent_weight}{RESET}\n")

    overall_best_key = ""
    overall_best_score = float('-inf')
    overall_best_text = ""
    overall_best_kl = min_kl
    all_pass_results = []

    for kl in range(min_kl, max_kl + 1):
        if min_kl != max_kl:
            print(f"\n{CYAN}================ KEY LENGTH {kl} (Range: {min_kl}-{max_kl}) ================{RESET}")
        
        for i in range(runs):
            print(f"\n{YELLOW}--- KEY LENGTH {kl} | PASS {i+1} OF {runs} ---{RESET}")
            key, score, text = run_simulated_annealing_pass(
                ciphertext, alphabet_str, kl, ngram_model, starting_temp, cooling_rate, steps_per_temp, ent_weight
            )
            
            all_pass_results.append({'key': key, 'score': score, 'text': text, 'key_length': kl})

            if score > overall_best_score:
                overall_best_score = score
                overall_best_key = key
                overall_best_text = text
                overall_best_kl = kl

    final_ioc = utils.calculate_ioc(overall_best_text)

    print(f"\n{YELLOW}================ FINAL BEST RESULT ================{RESET}")
    print(f"Key:           {YELLOW}{overall_best_key}{RESET} (Length: {overall_best_kl})")
    print(f"Fitness Score: {GREEN}{overall_best_score:.2f}{RESET}")
    print(f"Final IoC:     {GREEN}{final_ioc:.4f}{RESET}")
    print(f"\nPlaintext (Raw):\n{GREEN}{overall_best_text}{RESET}")

    if enable_spacing and spacing_model:
        spaced_text = add_spaces(overall_best_text, spacing_model)
        print(f"\nPlaintext (Spaced):\n{CYAN}{spaced_text}{RESET}")

    all_pass_results.sort(key=lambda x: x['score'], reverse=True)

    return [
        {
            'key': res['key'],
            'key_length': res['key_length'],
            'plaintext': res['text'],
            'bigram_score': res['score'],
            'ioc': utils.calculate_ioc(res['text']),
            'alphabet_used': alphabet_str
        }
        for res in all_pass_results
    ]


def run_direct_decrypt(ciphertext: str, alphabet_str: str, config: Dict):
    key = config.get('key', '')
    if not key:
        print(f"{RED}Key not provided.{RESET}")
        return []
    
    plaintext = decrypt_vigenere(ciphertext, key, alphabet_str)
    print(f"\nKey: {YELLOW}{key}{RESET}")
    print(f"Plaintext: {plaintext}")
    
    return [{'key': key, 'plaintext': plaintext}]

# --- MAIN APPLICATION ---

def run():
    print(f"{GREY}================================{RESET}")
    print(f"{RED}VIGENERE SOLVER{RESET}")
    print(f"{GREY}================================{RESET}")
    
    # 1. Get Initial Inputs
    ciphertexts = get_input_ciphertexts(prompt="Enter ciphertext")
    if not ciphertexts:
        print(f"{RED}No input provided.{RESET}")
        return

    alphabet_input = input(f"Enter alphabet(s) separated by commas (default: {RED}A-Z{RESET}): ").upper()
    if alphabet_input:
        alphabet_strs = [a.strip() for a in alphabet_input.split(",") if a.strip()]
    else:
        alphabet_strs = ["ABCDEFGHIJKLMNOPQRSTUVWXYZ"]

    expected_freqs = load_bigram_frequencies(ngram_path)
    if not expected_freqs:
        print(f"{RED}Warning: Bigram file not found.{RESET}")

    # 2. Main Persistent Loop
    while True:
        print(f"\n{GREY}Current Configuration:{RESET}")
        print(f"  Ciphertexts loaded: {YELLOW}{len(ciphertexts)}{RESET}")
        print(f"  Active Alphabet(s): {YELLOW}{', '.join(alphabet_strs)}{RESET}")
        
        print(f"\n{GREY}Select Action:{RESET}")
        print(f"  ({YELLOW}1{RESET}) Direct Decryption (Known Key)")
        print(f"  ({YELLOW}2{RESET}) Dictionary Attack (Key is an English word)")
        print(f"  ({YELLOW}3{RESET}) Simulated Annealing (Unknown Key of exact length or range)")
        print(f"  ({YELLOW}C{RESET}) Change Ciphertext(s)")
        print(f"  ({YELLOW}A{RESET}) Change/Add Alphabet(s)")
        print(f"  ({YELLOW}Q{RESET}) Quit to Main Menu")
        mode = input(">> ").strip().upper()

        if mode == 'Q':
            print(f"{YELLOW}Returning to main menu...{RESET}")
            break
            
        elif mode == 'C':
            new_ciphers = get_input_ciphertexts(prompt="Enter new ciphertext")
            if new_ciphers:
                ciphertexts = new_ciphers
            continue
            
        elif mode == 'A':
            new_alphas = input(f"Enter alphabet(s) separated by commas: ").upper()
            if new_alphas:
                alphabet_strs = [a.strip() for a in new_alphas.split(",") if a.strip()]
            continue
            
        elif mode not in ['1', '2', '3']:
            print(f"{RED}Invalid selection.{RESET}")
            continue

        # 3. Gather Configuration for specific attack
        config = {}
        if mode == '1':
            config['key'] = input("Enter the decryption key: ").upper().strip()
            
        elif mode == '2':
            phrases_in = input("Enter required plaintext words/phrases (comma-separated, optional): ").upper()
            config['target_phrases'] = [p.strip() for p in phrases_in.split(",")] if phrases_in else []
            
            keys_in = input("Enter specific keys to prioritize (comma-separated, optional): ").upper()
            config['specific_keys'] = [k.strip() for k in keys_in.split(",")] if keys_in else []
            
            min_ioc = input(f"Enter min IoC (default: {YELLOW}0.065{RESET}): ")
            config['min_ioc'] = float(min_ioc) if min_ioc else 0.065
            
            max_ioc = input(f"Enter max IoC (default: {YELLOW}0.070{RESET}): ")
            config['max_ioc'] = float(max_ioc) if max_ioc else 0.070
            
            len_filter = input(f"Enter exact key lengths to test (comma-separated), '{YELLOW}K{RESET}' to auto-detect with Kasiski, or blank for all: ").strip().upper()
            if len_filter == 'K':
                config['use_kasiski'] = True
            elif len_filter:
                try:
                    config['allowed_lengths'] = [int(x.strip()) for x in len_filter.split(",")]
                except ValueError:
                    print(f"{RED}Invalid lengths. Will test all dictionary words.{RESET}")
            
        elif mode == '3':
            try:
                kl_in = input(f"Enter exact key length (e.g. {YELLOW}5{RESET}) or range min-max (e.g. {YELLOW}3-10{RESET}) [default {YELLOW}5{RESET}]: ")
                min_kl, max_kl = parse_key_length_input(kl_in, default=5)
                config['min_key_length'] = min_kl
                config['max_key_length'] = max_kl

                selected_ngram_path = select_ngram_path()
                config['ngram_path'] = selected_ngram_path

                print(f"\n{GREY}Configure Simulated Annealing Parameters:{RESET}")
                
                t_in = input(f"Starting Temperature (default {YELLOW}20.0{RESET}): ")
                config['starting_temp'] = float(t_in) if t_in else 20.0
                
                c_in = input(f"Cooling Rate (default {YELLOW}0.995{RESET}): ")
                config['cooling_rate'] = float(c_in) if c_in else 0.995
                
                s_in = input(f"Steps per temperature (default {YELLOW}1000{RESET}): ")
                config['steps_per_temp'] = int(s_in) if s_in else 1000
                
                r_in = input(f"Number of passes per key length (default {YELLOW}3{RESET}): ")
                config['runs'] = int(r_in) if r_in else 3
                
                ew_in = input(f"Entropy Weight (AZDecrypt default ~{YELLOW}0.5{RESET}): ")
                config['ent_weight'] = float(ew_in) if ew_in else 0.5

                sp_in = input(f"Automatically insert spaces into output? ([Y]/n): ").strip().lower()
                config['enable_spacing'] = sp_in != 'n'
                if config['enable_spacing']:
                    spacing_path = select_spacing_model_path(selected_ngram_path)
                    print(f"{GREY}Loading spacing model from: {YELLOW}{spacing_path.name}{RESET}")
                    config['spacing_model'] = load_spacing_model(spacing_path)
                    _ = config['spacing_model'].scores
                else:
                    config['spacing_model'] = None

            except ValueError:
                print(f"{RED}Invalid numerical input.{RESET}")
                continue

        # 4. Execute Batch for every cipher across every alphabet
        print(f"\n{BLUE}=== Starting Batch Processing ({len(ciphertexts)} item(s), {len(alphabet_strs)} alphabet(s)) ==={RESET}")
        
        for i, ciphertext in enumerate(ciphertexts):
            display_sample = ciphertext.replace("\n", "")[:40]
            print(f"\n{GREY}Input #{i+1}: {display_sample}...{RESET}")
            
            all_results_for_input = []
            
            for alphabet_str in alphabet_strs:
                if len(alphabet_strs) > 1:
                    print(f"\n{CYAN}>>> Testing Alphabet: {alphabet_str} <<<{RESET}")
                    
                results = None
                if mode == '1':
                    results = run_direct_decrypt(ciphertext, alphabet_str, config)
                elif mode == '2':
                    results = run_dictionary_attack(ciphertext, alphabet_str, expected_freqs, config)
                elif mode == '3':
                    results = run_simulated_annealing_attack(ciphertext, alphabet_str, expected_freqs, config)
                    
                if results:
                    for r in results:
                        r['alphabet_used'] = alphabet_str
                    all_results_for_input.extend(results)
                    
            # 5. File Saving Logic
            if all_results_for_input:
                save = input(f"\nSave {len(all_results_for_input)} results for Input #{i+1} to a .txt file? ({YELLOW}Y/N{RESET}): ").strip().upper()
                if save == 'Y':
                    filename = input(f"Enter filename (default: vigenere_results_{i+1}.txt): ").strip()
                    if not filename:
                        filename = f"vigenere_results_{i+1}.txt"
                    if not filename.endswith('.txt'):
                        filename += '.txt'
                    utils.save_results_to_file(all_results_for_input, filename)
                
        print(f"\n{GREY}Batch processing complete.{RESET}")

if __name__ == "__main__":
    run()