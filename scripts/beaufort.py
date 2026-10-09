from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
import time
from functools import lru_cache
import os
import random
import math
from utils.utils import get_input_ciphertexts
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores, score_text

# --- KASISKI IMPORT ---
try:
    from scripts.kasiski import analyze_kasiski
except ImportError:
    try:
        from kasiski import analyze_kasiski
    except ImportError:
        analyze_kasiski = None

# --- DUMMY UTILS CLASS (Maintained for standalone scoring compatibility) ---
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
                f.write("Beaufort Cipher Brute-Force Results\n")
                f.write("=====================================\n\n")
                for result in results:
                    f.write(f"Key: {result['key']}\n")
                    if 'alphabet_used' in result:
                        f.write(f"Alphabet: {result['alphabet_used']}\n")
                    if 'ioc' in result:
                        f.write(f"IoC Score: {result.get('ioc', 0):.4f}\n")
                    if 'bigram_score' in result:
                        f.write(f"N-gram Score: {result.get('bigram_score', 0):.2f}\n")
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
GREY = '\033[90m'

data_dir = os.path.join(os.path.dirname(__file__), "data")
dictionary_path = os.path.join(data_dir, "words_alpha.txt")
ngram_path = DEFAULT_NGRAM_PATH

# --- SCORING FUNCTIONS ---
@lru_cache(maxsize=None)
def load_bigram_frequencies(file_path: str) -> Dict[str, float]:
    return load_ngram_scores(file_path)

def calculate_bigram_score(text: str, expected_freqs: Dict[str, float]) -> float:
    return score_text(text, expected_freqs)

# --- BEAUFORT CORE FUNCTIONS ---
@lru_cache(maxsize=None)
def get_alphabet(alphabet_str: str):
    alphabet = alphabet_str.upper()
    alphabet_dict = {char: i for i, char in enumerate(alphabet)}
    return alphabet, alphabet_dict

def decrypt_beaufort(ciphertext: str, key: str, alphabet_str: str) -> str:
    """
    Beaufort Decryption: P = (K - C) mod 26
    Notice this is different from Vigenere where P = (C - K) mod 26
    """
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
            # THE CORE MATH DIFFERENCE FOR BEAUFORT:
            decrypted_char = alphabet[(shift - char_index + alphabet_length) % alphabet_length]
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
        plaintext = decrypt_beaufort(ciphertext, word, alphabet_str)
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
            plaintext = decrypt_beaufort(ciphertext, key, alphabet_str)
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

def generate_neighbor_key(key: str, alphabet: str) -> str:
    key_list = list(key)
    pos = random.randint(0, len(key_list) - 1)
    key_list[pos] = random.choice(alphabet)
    return "".join(key_list)

def run_simulated_annealing_attack(ciphertext: str, alphabet_str: str, expected_freqs: Dict, config: Dict):
    key_length = config.get('key_length', 5)
    iterations = config.get('iterations', 200000)
    initial_temp = 1000.0

    print(f"\n{BLUE}--- Simulated Annealing (Key Len: {key_length}) ---{RESET}")
    alphabet, _ = get_alphabet(alphabet_str)
    
    current_key = "".join(random.choice(alphabet) for _ in range(key_length))
    plaintext = decrypt_beaufort(ciphertext, current_key, alphabet_str)
    current_score = calculate_bigram_score(plaintext, expected_freqs)

    best_key, best_score = current_key, current_score
    
    try:
        for i in range(iterations):
            temp = initial_temp * (1.0 - (i + 1) / iterations)
            if temp <= 0: break

            neighbor_key = generate_neighbor_key(current_key, alphabet)
            plaintext = decrypt_beaufort(ciphertext, neighbor_key, alphabet_str)
            neighbor_score = calculate_bigram_score(plaintext, expected_freqs)
            
            delta = neighbor_score - current_score
            if delta < 0 or random.random() < math.exp(-delta / temp):
                current_key, current_score = neighbor_key, neighbor_score
                if current_score < best_score:
                    best_key, best_score = current_key, current_score
                    best_text = decrypt_beaufort(ciphertext, best_key, alphabet_str).upper()
                    print(f"Score: {best_score:8.2f} | Key: {best_key} | Text: {best_text[:30]}...", end='\r')

    except KeyboardInterrupt:
        print("\nSkipping to next result...")
    
    print("\n" + "="*60)
    best_plaintext = decrypt_beaufort(ciphertext, best_key, alphabet_str).upper()
    print(f"Final Best Key: {YELLOW}{best_key}{RESET}")
    print(f"N-gram Score: {YELLOW}{best_score:.2f}{RESET}")
    print(f"IoC: {YELLOW}{utils.calculate_ioc(best_plaintext):.4f}{RESET}")
    print(f"Text: {best_plaintext}")
    
    return [{'key': best_key, 'plaintext': best_plaintext, 'bigram_score': best_score}]

def run_direct_decrypt(ciphertext: str, alphabet_str: str, config: Dict):
    key = config.get('key', '')
    if not key:
        print(f"{RED}Key not provided.{RESET}")
        return []
    
    plaintext = decrypt_beaufort(ciphertext, key, alphabet_str)
    print(f"\nKey: {YELLOW}{key}{RESET}")
    print(f"Plaintext: {plaintext}")
    
    return [{'key': key, 'plaintext': plaintext}]

# --- MAIN APPLICATION ---
def run():
    print(f"{GREY}================================{RESET}")
    print(f"{RED}BEAUFORT SOLVER{RESET}")
    print(f"{GREY}================================{RESET}")
    
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
        print(f"{RED}Warning: N-gram scores could not be loaded.{RESET}")

    while True:
        print(f"\n{GREY}Current Configuration:{RESET}")
        print(f"  Ciphertexts loaded: {YELLOW}{len(ciphertexts)}{RESET}")
        print(f"  Active Alphabet(s): {YELLOW}{', '.join(alphabet_strs)}{RESET}")
        
        print(f"\n{GREY}Select Action:{RESET}")
        print(f"  ({YELLOW}1{RESET}) Direct Decryption (Known Key)")
        print(f"  ({YELLOW}2{RESET}) Dictionary Attack (Key is an English word)")
        print(f"  ({YELLOW}3{RESET}) Simulated Annealing (Unknown Key of known length)")
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
                kl = input("Enter exact key length: ")
                config['key_length'] = int(kl)
                iters = input(f"Enter iterations (default: {YELLOW}200,000{RESET}): ")
                config['iterations'] = int(iters) if iters else 200000
            except ValueError:
                print(f"{RED}Invalid integer input.{RESET}")
                continue

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
                    
            if all_results_for_input:
                save = input(f"\nSave {len(all_results_for_input)} results for Input #{i+1} to a .txt file? ({YELLOW}Y/N{RESET}): ").strip().upper()
                if save == 'Y':
                    filename = input(f"Enter filename (default: beaufort_results_{i+1}.txt): ").strip()
                    if not filename:
                        filename = f"beaufort_results_{i+1}.txt"
                    if not filename.endswith('.txt'):
                        filename += '.txt'
                    utils.save_results_to_file(all_results_for_input, filename)
                
        print(f"\n{GREY}Batch processing complete.{RESET}")

if __name__ == "__main__":
    run()