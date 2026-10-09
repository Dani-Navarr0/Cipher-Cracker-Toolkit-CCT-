from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Dict, Tuple
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores, score_text
import time
from functools import lru_cache
import os
import math 
import random 
import string 

# Dummy utils for standalone execution
class DummyUtils:
    def calculate_ioc(self, text: str) -> float:
        text = text.upper()
        text = ''.join(filter(str.isalpha, text))
        n = len(text)
        if n < 2:
            return 0.0
        
        freqs = {}
        for char in text:
            freqs[char] = freqs.get(char, 0) + 1
            
        numerator = sum(count * (count - 1) for count in freqs.values())
        denominator = n * (n - 1)
        
        return numerator / denominator if denominator > 0 else 0.0

    def save_results_to_file(self, results: List[Dict], filename: str, include_phrases: bool = True):
        with open(filename, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(f"Key: {result['key']}\n")
                if 'ioc' in result:
                    f.write(f"IoC: {result['ioc']:.6f}\n")
                if 'score' in result:
                    f.write(f"Fitness Score: {result['score']:.2f}\n")
                if include_phrases and 'matched_phrases' in result:
                    f.write(f"Matched Phrases: {', '.join(result['matched_phrases'])}\n")
                f.write(f"Plaintext: {result['plaintext']}\n")
                f.write("-" * 20 + "\n")
        print(f"Results saved to {filename}")

utils = DummyUtils()

# ANSI color codes for terminal output
RED = '\033[38;5;88m'
YELLOW = '\033[38;5;3m'
GREY = '\033[38;5;238m'
RESET = '\033[0m'
GREEN = '\033[38;5;2m'

# Default Playfair alphabet
DEFAULT_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
dictionary_path = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")
ngram_path = DEFAULT_NGRAM_PATH


# --- CORE UTILITIES ---

def deduplicate_results(results: List[Dict]) -> List[Dict]:
    """Filters out duplicate plaintexts (caused by keys that reduce to the same Playfair matrix)."""
    unique_results = []
    seen_plaintexts = set()
    for res in results:
        if res['plaintext'] not in seen_plaintexts:
            seen_plaintexts.add(res['plaintext'])
            unique_results.append(res)
    return unique_results

@lru_cache(maxsize=None)
def load_bigram_frequencies(file_path: str) -> Dict[str, float]:
    return load_ngram_scores(file_path)

def calculate_fitness_score(text: str, expected_freqs: Dict[str, float]) -> float:
    return score_text(text, expected_freqs)

# --- FUNCTIONS FOR BIGRAM FREQUENCY ATTACK ---

def process_batch_frequency(args: Tuple) -> List[Dict]:
    word_batch, ciphertext, expected_freqs, alphabet = args
    results = []
    
    for word in word_batch:
        try:
            plaintext = decrypt_playfair(ciphertext, word, alphabet)
            score = calculate_fitness_score(plaintext, expected_freqs)
            ioc = utils.calculate_ioc(plaintext) 
            results.append({
                'key': word,
                'plaintext': plaintext,
                'score': score,
                'ioc': ioc 
            })
        except Exception:
            continue
    return results

def crack_playfair_by_frequency(ciphertext: str, dictionary_path: str, bigram_path: str, alphabet: str) -> List[Dict]:
    expected_freqs = load_bigram_frequencies(bigram_path)
    if not expected_freqs: return []

    dictionary = load_dictionary(dictionary_path, alphabet)
    if not dictionary: return []

    word_batches = batch_words(dictionary)
    num_processes = max(1, os.cpu_count() - 1 if os.cpu_count() else 1)
    total_batches = len(word_batches)
    
    print(f"\n{YELLOW}Starting dictionary attack with bigram fitness scoring...{RESET}")
    start_time = time.time()
    
    all_results = []
    processed_batches = 0
    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = [executor.submit(process_batch_frequency, (batch, ciphertext, expected_freqs, alphabet)) for batch in word_batches]
        
        for future in as_completed(futures):
            try:
                batch_results = future.result()
                all_results.extend(batch_results)
                processed_batches += 1
                print(f"Progress: {processed_batches}/{total_batches} batches ({(processed_batches / total_batches) * 100:.1f}%)", end='\r')
            except Exception:
                processed_batches += 1
                continue
    
    print("\n") 
    end_time = time.time()
    print(f"{YELLOW}Cracking complete in {end_time - start_time:.2f} seconds{RESET}")
    
    all_results = deduplicate_results(all_results) 
    all_results.sort(key=lambda x: x['score'])
    print(f"Found {RED}{len(all_results)}{RESET} UNIQUE potential solutions.")
    return all_results

# --- MEMETIC ALGORITHM FUNCTIONS ---

def generate_random_key(alphabet: str) -> str:
    key_list = list(alphabet)
    random.shuffle(key_list)
    return "".join(key_list)

def crossover(parent1: str, parent2: str, alpha_len: int) -> str:
    child = [''] * alpha_len
    start, end = sorted(random.sample(range(alpha_len), 2))
    p1_slice = parent1[start:end+1]
    child[start:end+1] = p1_slice
    p2_chars = [char for char in parent2 if char not in p1_slice]
    
    child_idx = 0
    for i in range(alpha_len):
        if child[i] == '':
            child[i] = p2_chars[child_idx]
            child_idx += 1
            
    return "".join(child)

def mutate(key: str, mutation_rate: float, alpha_len: int) -> str:
    key_list = list(key)
    if random.random() < mutation_rate:
        idx1, idx2 = random.sample(range(alpha_len), 2)
        key_list[idx1], key_list[idx2] = key_list[idx2], key_list[idx1]
    return "".join(key_list)

def crack_playfair_memetic(ciphertext: str, bigram_path: str, pop_size: int, generations: int, mutation_rate: float, alphabet: str) -> List[Dict]:
    expected_freqs = load_bigram_frequencies(bigram_path)
    if not expected_freqs: return []
    
    print(f"\n{YELLOW}Starting Memetic Algorithm Attack...{RESET}")
    
    alpha_len = len(alphabet)
    population = [generate_random_key(alphabet) for _ in range(pop_size)]
    
    best_key_overall = ""
    best_score_overall = float('inf')
    start_time = time.time()

    for gen in range(generations):
        scores = []
        for key in population:
            plaintext = decrypt_playfair(ciphertext, key, alphabet)
            score = calculate_fitness_score(plaintext, expected_freqs)
            scores.append((score, key))
        
        scores.sort(key=lambda x: x[0]) 
        
        if scores[0][0] < best_score_overall:
            best_score_overall = scores[0][0]
            best_key_overall = scores[0][1]
            elapsed = time.time() - start_time
            print(f"Gen {gen+1}/{generations} | Score: {GREEN}{best_score_overall:.2f}{RESET} | Key: {best_key_overall[:15]}... | Time: {elapsed:.1f}s")

        elite_count = max(2, int(pop_size * 0.2))
        elites = [key for score, key in scores[:elite_count]]
        next_generation = elites
        
        while len(next_generation) < pop_size:
            parent1, parent2 = random.choices(elites, k=2) 
            child = crossover(parent1, parent2, alpha_len)
            child = mutate(child, mutation_rate, alpha_len)
            next_generation.append(child)
            
        population = next_generation

    end_time = time.time()
    print(f"\n{YELLOW}Algorithm finished in {end_time - start_time:.2f} seconds.{RESET}")
    final_plaintext = decrypt_playfair(ciphertext, best_key_overall, alphabet)
    final_ioc = utils.calculate_ioc(final_plaintext) 
    
    return [{'key': best_key_overall, 'plaintext': final_plaintext, 'score': best_score_overall, 'ioc': final_ioc}]


# --- CORE PLAYFAIR AND UTILITY FUNCTIONS ---

@lru_cache(maxsize=None)
def create_playfair_matrix(key: str, alphabet: str) -> List[List[str]]:
    matrix_chars = []
    normalized_key = "".join(char for char in key.upper() if char in alphabet)
    
    if len(alphabet) == 25 and 'J' not in alphabet and 'J' in key.upper():
         normalized_key = normalized_key.replace('J', 'I')

    for char in normalized_key:
        if char not in matrix_chars:
            matrix_chars.append(char)
            
    for char in alphabet:
        if char not in matrix_chars:
            matrix_chars.append(char)
            
    dim = math.isqrt(len(alphabet))
    if dim * dim != len(alphabet):
        dim = math.ceil(math.sqrt(len(alphabet))) 

    matrix = [matrix_chars[i:i + dim] for i in range(0, len(matrix_chars), dim)]
    return matrix

@lru_cache(maxsize=None)
def get_char_map(matrix: Tuple[Tuple[str, ...], ...]) -> Dict[str, Tuple[int, int]]:
    return {char: (r, c) for r, row in enumerate(matrix) for c, char in enumerate(row)}

def decrypt_playfair(ciphertext: str, key: str, alphabet: str) -> str:
    matrix = create_playfair_matrix(key, alphabet)
    matrix_tuple = tuple(tuple(row) for row in matrix)
    char_map = get_char_map(matrix_tuple)
    
    plaintext = []
    normalized_text = "".join(char for char in ciphertext.upper() if char in alphabet)
    
    if len(alphabet) == 25 and 'J' not in alphabet:
         normalized_text = normalized_text.replace('J', 'I')
    
    if len(normalized_text) % 2 != 0:
        normalized_text = normalized_text[:-1]

    digraphs = [normalized_text[i:i+2] for i in range(0, len(normalized_text), 2)]
    dim = len(matrix[0])

    for char1, char2 in digraphs:
        if char1 not in char_map or char2 not in char_map:
            plaintext.append(char1.lower())
            plaintext.append(char2.lower())
            continue

        r1, c1 = char_map[char1]
        r2, c2 = char_map[char2]

        if r1 == r2: 
            p1 = matrix[r1][(c1 - 1 + dim) % dim]
            p2 = matrix[r2][(c2 - 1 + dim) % dim]
        elif c1 == c2: 
            p1 = matrix[(r1 - 1 + dim) % dim][c1]
            p2 = matrix[(r2 - 1 + dim) % dim][c2]
        else: 
            p1 = matrix[r1][c2]
            p2 = matrix[r2][c1]
            
        plaintext.append(p1)
        plaintext.append(p2)
        
    return ''.join(plaintext)

def load_dictionary(file_path: str, alphabet: str, min_length: int = 3, max_length: int = 15) -> List[str]:
    alphabet_set = set(alphabet)
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            allow_j = len(alphabet) == 25 and 'J' not in alphabet
            words = []
            for word in file:
                w = word.strip().upper()
                if allow_j: w = w.replace('J', 'I')
                if set(w).issubset(alphabet_set) and min_length <= len(w) <= max_length:
                    words.append(w)
            return words
    except FileNotFoundError:
        print(f"{RED}Error: {file_path} not found.{RESET}")
        return []

def contains_all_phrases(text: str, phrases: List[str]) -> bool:
    if not phrases: return True
    if not any(char.isalnum() for phrase in phrases for char in phrase): return False
    return all(phrase.upper().replace(" ", "") in text.upper() for phrase in phrases)

def highlight_match(text: str, phrases: List[str]) -> str:
    display_text = text
    for phrase in phrases:
        phrase_upper = phrase.upper().replace(" ", "")
        start_index = 0
        while True:
            text_upper = display_text.upper().replace(RED, "").replace(RESET, "")
            found_pos = text_upper.find(phrase_upper, start_index)
            if found_pos == -1: break
            
            plain_text_count, actual_start, i, in_escape = 0, -1, 0, False
            while i < len(display_text):
                if display_text[i] == '\033': in_escape = True
                elif in_escape and display_text[i] == 'm': in_escape = False
                elif not in_escape:
                    if plain_text_count == found_pos:
                        actual_start = i
                        break
                    plain_text_count += 1
                i += 1
            
            if actual_start != -1:
                end = actual_start + len(phrase_upper)
                display_text = display_text[:actual_start] + f"{RED}{display_text[actual_start:end]}{RESET}" + display_text[end:]
                start_index = found_pos + 1 
            else: break
    return display_text

def process_batch(args: Tuple) -> Tuple[List[Dict], List[Dict]]:
    word_batch, ciphertext, target_phrases, min_ioc, max_ioc, expected_freqs, alphabet = args
    phrase_matches = []
    ioc_matches = []
    
    for word in word_batch:
        try:
            plaintext = decrypt_playfair(ciphertext, word, alphabet)
            ioc = utils.calculate_ioc(plaintext)
            score = calculate_fitness_score(plaintext, expected_freqs) if expected_freqs else float('inf')
            
            is_ioc_match = min_ioc <= ioc <= max_ioc
            is_phrase_match = contains_all_phrases(plaintext, target_phrases)

            if is_ioc_match:
                ioc_matches.append({'key': word, 'plaintext': plaintext, 'ioc': ioc, 'score': score})
            if is_phrase_match:
                phrase_matches.append({'key': word, 'plaintext': plaintext, 'matched_phrases': target_phrases, 'ioc': ioc, 'score': score})
        except Exception:
            continue
    return phrase_matches, ioc_matches

def crack_playfair(ciphertext: str, target_phrases: List[str], dictionary_path: str, 
                   specific_keys: List[str] = None, min_ioc: float = 0.065, max_ioc: float = 0.07,
                   bigram_path: str = None, alphabet: str = DEFAULT_ALPHABET) -> Tuple[List[Dict], List[Dict]]:
    phrase_results = []
    ioc_results = []
    expected_freqs = load_bigram_frequencies(bigram_path) if bigram_path else {}
    
    if specific_keys:
        for key in specific_keys:
            plaintext = decrypt_playfair(ciphertext, key, alphabet)
            ioc = utils.calculate_ioc(plaintext)
            score = calculate_fitness_score(plaintext, expected_freqs) if expected_freqs else 0.0
            
            if min_ioc <= ioc <= max_ioc:
                ioc_results.append({'key': key, 'plaintext': plaintext, 'ioc': ioc, 'score': score})
            if contains_all_phrases(plaintext, target_phrases):
                phrase_results.append({'key': key, 'plaintext': plaintext, 'matched_phrases': target_phrases, 'ioc': ioc, 'score': score})
    
    print(f"\n{YELLOW}Loading dictionary...{RESET}")
    dictionary = load_dictionary(dictionary_path, alphabet)
    if not dictionary: return phrase_results, ioc_results

    word_batches = batch_words(dictionary)
    num_processes = max(1, os.cpu_count() - 1 if os.cpu_count() else 1)
    total_batches = len(word_batches)
    
    start_time = time.time()
    processed_batches = 0
    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = [executor.submit(process_batch, (batch, ciphertext, target_phrases, min_ioc, max_ioc, expected_freqs, alphabet)) for batch in word_batches]
        
        for future in as_completed(futures):
            try:
                batch_phrase_results, batch_ioc_results = future.result()
                phrase_results.extend(batch_phrase_results)
                ioc_results.extend(batch_ioc_results)
                processed_batches += 1
                print(f"Progress: {processed_batches}/{total_batches} batches ({(processed_batches / total_batches) * 100:.1f}%)", end='\r')
            except Exception:
                processed_batches += 1
                continue
    
    print("\n") 
    print(f"{YELLOW}Cracking complete in {time.time() - start_time:.2f} seconds{RESET}")
    
    phrase_results = deduplicate_results(phrase_results)
    ioc_results = deduplicate_results(ioc_results)
    
    phrase_results.sort(key=lambda x: x['score'])
    ioc_results.sort(key=lambda x: x['score'])
    
    print(f"Found {RED}{len(phrase_results)}{RESET} UNIQUE phrase-matching solutions")
    print(f"Found {RED}{len(ioc_results)}{RESET} UNIQUE English-like IoC solutions")
    
    return phrase_results, ioc_results

def batch_words(words: List[str], batch_size: int = 500) -> List[List[str]]:
    return [words[i:i + batch_size] for i in range(0, len(words), batch_size)]

def run_direct_decrypt(ciphertext: str, alphabet: str):
    print(f"\n{YELLOW}--- Direct Playfair Decryption ---{RESET}")
    key = input(f"{GREY}Enter the key: {RESET}").upper()

    if not key:
        print(f"{RED}Error: Key cannot be empty.{RESET}")
        return

    try:
        plaintext = decrypt_playfair(ciphertext, key, alphabet)
        print(f"\n{GREEN}Plaintext:{RESET}\n{plaintext}")
    except Exception as e:
        print(f"{RED}Decryption Error: {e}{RESET}")

def run():
    print(f"""{GREY} 
    Playfair Cipher{RESET}""")
    print(f"{GREY}-{RESET}" * 50)
    
    # 1. Ask for Alphabet
    use_custom = input(f"Use custom alphabet? ({YELLOW}Y/N{RESET}): ").upper() == 'Y'
    current_alphabet = DEFAULT_ALPHABET
    if use_custom:
        custom_input = input(f"{GREY}Enter custom alphabet (must form a perfect square grid, e.g. 25 or 36 chars): {RESET}").upper()
        if len(custom_input) in [25, 36]:
            current_alphabet = custom_input
        else:
            print(f"{RED}Invalid length ({len(custom_input)}). Using default 25-letter alphabet.{RESET}")
    
    print(f"Active Alphabet: {YELLOW}{current_alphabet}{RESET} (Length: {len(current_alphabet)})\n")

    # 2. Ask for Ciphertext once
    ciphertext = ""
    while not ciphertext:
        ciphertext = input(f"{GREY}Enter ciphertext to analyze: {RESET}").upper()
        if not ciphertext:
            print(f"{RED}Ciphertext cannot be empty.{RESET}")

    # 3. Main Action Loop
    while True:
        print(f"\n{GREY}Current Ciphertext: {RESET}{ciphertext[:40]}...")
        mode = input(f"Choose a mode:\n({YELLOW}1{RESET}) Brute Force w/ Crib\n({YELLOW}2{RESET}) Direct Decrypt\n({YELLOW}3{RESET}) Dictionary Attack (N-gram Fitness)\n({YELLOW}4{RESET}) Memetic Algorithm Attack\n({YELLOW}N{RESET}) Enter New Ciphertext\n({YELLOW}Q{RESET}) Quit to Main Menu\n{GREY}Selection: {RESET}").upper()
        
        if mode == 'Q':
            print(f"{YELLOW}Returning to main menu...{RESET}")
            break
            
        elif mode == 'N':
            new_ct = input(f"{GREY}Enter new ciphertext: {RESET}").upper()
            if new_ct:
                ciphertext = new_ct
            continue

        elif mode == '2':
            run_direct_decrypt(ciphertext, current_alphabet)
        
        elif mode == '3':
            print(f"\n{YELLOW}--- Dictionary Attack (N-gram Fitness) ---{RESET}")
            results = crack_playfair_by_frequency(ciphertext, dictionary_path, ngram_path, current_alphabet)
            
            if results:
                best_result = results[0]
                print(f"\n{YELLOW}BEST SOLUTION FOUND{RESET}")
                print(f"{GREY}-{RESET}" * 50)
                print(f"Key: {YELLOW}{best_result['key']}{RESET} | IoC: {YELLOW}{best_result.get('ioc', 0.0):.6f}{RESET} | Score: {YELLOW}{best_result['score']:.2f}{RESET}")
                print(f"Plaintext: {best_result['plaintext']}\n{GREY}-{RESET}" * 50)

                save_results = input(f"\nSave all {len(results)} UNIQUE results to file? ({YELLOW}Y/N{RESET}): ").upper() == 'Y'
                if save_results:
                    filename = input("Enter filename for results: ") or "playfair_freq_results"
                    utils.save_results_to_file(results, f"{filename}.txt")
        
        elif mode == '4':
            print(f"\n{YELLOW}--- Memetic Algorithm Attack ---{RESET}")
            
            pop_size = input(f"Enter population size (default 100): ")
            pop_size = int(pop_size) if pop_size else 100
            
            generations = input(f"Enter number of generations (default 200): ")
            generations = int(generations) if generations else 200
            
            mutation_rate = input(f"Enter mutation rate (default 0.2): ")
            mutation_rate = float(mutation_rate) if mutation_rate else 0.2

            results = crack_playfair_memetic(ciphertext, ngram_path, pop_size, generations, mutation_rate, current_alphabet)
            
            if results:
                best_result = results[0]
                print(f"\n{YELLOW}BEST SOLUTION FOUND{RESET}")
                print(f"{GREY}-{RESET}" * 50)
                print(f"Key: {YELLOW}{best_result['key']}{RESET} | IoC: {YELLOW}{best_result.get('ioc', 0.0):.6f}{RESET} | Score: {YELLOW}{best_result['score']:.2f}{RESET}")
                print(f"Plaintext: {best_result['plaintext']}")

                save_results = input(f"\nSave best result to file? ({YELLOW}Y/N{RESET}): ").upper() == 'Y'
                if save_results:
                    filename = input("Enter filename for result: ") or "playfair_memetic_result"
                    utils.save_results_to_file(results, f"{filename}.txt")

        elif mode == '1':
            print(f"\n{YELLOW}--- Brute Force with Crib/IoC ---{RESET}")
            
            target_phrases_input = input(f"Enter known plaintext words (comma-separated, optional): ").upper()
            target_phrases = [p.strip() for p in target_phrases_input.split(",") if p.strip()] if target_phrases_input else []
            
            specific_keys_input = input(f"Enter specific keys to try first (comma-separated, optional): ").upper()
            specific_keys = [k.strip() for k in specific_keys_input.split(",") if k.strip()] if specific_keys_input else []
            
            min_ioc, max_ioc = 0.065, 0.07
            if input(f"Use default English IoC range ({YELLOW}0.065-0.07{RESET})? (Y/N): ").upper() == 'N':
                min_ioc = float(input("Enter min IoC: "))
                max_ioc = float(input("Enter max IoC: "))
            
            phrase_results, ioc_results = crack_playfair(
                ciphertext, target_phrases, dictionary_path, specific_keys, min_ioc, max_ioc, ngram_path, current_alphabet
            )
            
            if phrase_results:
                best_phrase = phrase_results[0]
                print(f"\n{YELLOW}BEST PHRASE-MATCHING RESULT{RESET}")
                print(f"{GREY}-{RESET}" * 50)
                print(f"Key: {YELLOW}{best_phrase['key']}{RESET} | IoC: {YELLOW}{best_phrase['ioc']:.6f}{RESET} | Score: {YELLOW}{best_phrase['score']:.2f}{RESET}")
                print(f"Matched phrases: {YELLOW}{', '.join(best_phrase['matched_phrases'])}{RESET}")
                print(f"Plaintext: {highlight_match(best_phrase['plaintext'], best_phrase['matched_phrases'])}\n{GREY}-{RESET}" * 50)

                save_phrase = input(f"\nSave all {len(phrase_results)} UNIQUE phrase-matching results to file? ({YELLOW}Y/N{RESET}): ").upper() == 'Y'
                if save_phrase:
                    phrase_filename = input("Enter filename for phrase results: ") or "playfair_phrase_results"
                    utils.save_results_to_file(phrase_results, f"{phrase_filename}.txt")

            if ioc_results:
                best_ioc = ioc_results[0]
                print(f"\n{YELLOW}BEST ENGLISH-LIKE IoC RESULT{RESET}")
                print(f"{GREY}-{RESET}" * 50)
                print(f"Key: {YELLOW}{best_ioc['key']}{RESET} | IoC: {YELLOW}{best_ioc['ioc']:.6f}{RESET} | Score: {YELLOW}{best_ioc['score']:.2f}{RESET}")
                print(f"Plaintext: {best_ioc['plaintext']}\n{GREY}-{RESET}" * 50)

                save_ioc = input(f"\nSave all {len(ioc_results)} UNIQUE IoC-based results to file? ({YELLOW}Y/N{RESET}): ").upper() == 'Y'
                if save_ioc:
                    ioc_filename = input("Enter filename for IoC results: ") or "playfair_ioc_results"
                    utils.save_results_to_file(ioc_results, f"{ioc_filename}.txt", include_phrases=False)
                    
        else:
            print(f"{RED}Invalid selection. Please enter a valid menu option.{RESET}")

if __name__ == "__main__":
    run()