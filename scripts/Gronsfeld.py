import itertools
from concurrent.futures import ProcessPoolExecutor, as_completed
import os
from typing import List, Dict, Tuple
from functools import lru_cache
import random
import math
import time
from collections import Counter
from annealing import Schedule
from periodic_solver import solve_periodic
from ngram_scoring import DEFAULT_NGRAM_PATH, DEFAULT_NGRAM_SIZE, load_ngram_scores, resolve_ngram_path, score_text

# --- DUMMY UTILS CLASS ---
class DummyUtils:
    def calculate_ioc(self, text: str) -> float:
        text = text.upper()
        text = ''.join(filter(str.isalpha, text))
        n = len(text)
        if n < 2: return 0.0
        freqs = Counter(text)
        numerator = sum(count * (count - 1) for count in freqs.values())
        denominator = n * (n - 1)
        return numerator / denominator if denominator > 0 else 0.0

    def save_results_to_file(self, results: List[Dict], filename: str):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("Gronsfeld Cipher Brute-Force Results\n")
                f.write("=====================================\n\n")
                for result in results:
                    f.write(f"Key: {result['key']}\n")
                    f.write(f"IoC Score: {result.get('ioc', 0):.4f}\n")
                    f.write(f"Fitness Score: {result.get('score', 0):.2f}\n")
                    if result.get('matched_phrases'):
                        f.write(f"Matched Phrases: {', '.join(result['matched_phrases'])}\n")
                    f.write(f"Decrypted: {result.get('decrypted', result.get('text', ''))}\n")
                    f.write("-" * 20 + "\n")
            print(f"{GREEN}Results successfully saved to {filename}{RESET}")
        except IOError as e:
            print(f"{RED}Error saving file: {e}{RESET}")

    def analyze_frequency_vg(self, text: str):
        print("\n--- Frequency Analysis ---")
        text = ''.join(filter(str.isalpha, text.upper()))
        total = len(text)
        if total == 0:
            print("No alphabetic characters to analyze.")
            return
        freqs = Counter(text)
        sorted_freqs = sorted(freqs.items(), key=lambda item: item[1], reverse=True)
        print("Character Frequencies:")
        for char, count in sorted_freqs:
            percentage = (count / total) * 100
            print(f"{char}: {count:<4} ({percentage:.2f}%)")
        print("-" * 25)

utils = DummyUtils()

# --- COLOR CODES AND PATHS ---
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

data_dir = os.path.join(os.path.dirname(__file__), "data")
ngram_path = DEFAULT_NGRAM_PATH

# --- SCORING FUNCTIONS ---
@lru_cache(maxsize=None)
def load_ngram_frequencies(file_path: str) -> Dict[str, float]:
    return load_ngram_scores(file_path)

def calculate_ngram_score(text: str, expected_freqs: Dict[str, float], n: int) -> float:
    return score_text(text, expected_freqs)

# --- GRONSFELD CORE FUNCTIONS ---
def highlight_phrases(text: str, phrases: list) -> str:
    highlighted_text = text.lower()
    for phrase in phrases:
        phrase_lower = phrase.lower()
        highlighted_text = highlighted_text.replace(phrase_lower, f"{RED}{phrase_lower}{RESET}")
    return highlighted_text

def gronsfeld_decrypt(ciphertext: str, key: str, alphabet: str) -> str:
    decrypted_text = []
    key_length = len(key)
    alphabet_length = len(alphabet)
    key_digits = [int(d) for d in key]

    key_position = 0  # Advances only on enciphered letters, not spaces/punctuation.
    for char in ciphertext:
        char_upper = char.upper()
        if char_upper in alphabet:
            char_index = alphabet.index(char_upper)
            shift = key_digits[key_position % key_length]
            key_position += 1
            decrypted_index = (char_index - shift + alphabet_length) % alphabet_length
            decrypted_char = alphabet[decrypted_index]
            decrypted_text.append(decrypted_char.lower())
        else:
            decrypted_text.append(char.lower())
    return ''.join(decrypted_text)

# --- EXHAUSTIVE ATTACK ---
def process_exhaustive_batch(args):
    ciphertext, alphabet, keys_batch, expected_freqs = args
    results = []
    for key in keys_batch:
        try:
            decrypted = gronsfeld_decrypt(ciphertext, key, alphabet)
            ioc = utils.calculate_ioc(decrypted)
            score = calculate_ngram_score(decrypted, expected_freqs, 2)
            results.append({'key': key, 'decrypted': decrypted, 'ioc': ioc, 'score': score})
        except (ValueError, IndexError):
            continue
    return results

def run_exhaustive_attack(ciphertext: str, alphabet: str, expected_freqs: Dict):
    print(f"\n{BLUE}--- Exhaustive Brute-Force Attack ---{RESET}")
    try:
        key_length = int(input("Enter the exact key length to test (e.g., 5): "))
        if key_length <= 0 or key_length > 8:
            print(f"{RED}Key length must be between 1 and 8.{RESET}")
            return
    except ValueError:
        return

    known_text = input(f"Enter known plaintext words for sorting/highlighting (comma-separated): ").upper()
    known_plaintexts = [word.strip() for word in known_text.split(',')] if known_text.strip() else []

    total_combinations = 10 ** key_length
    print(f"\n{YELLOW}Trying all {total_combinations:,} possible {key_length}-digit keys...{RESET}")
    
    batch_size = max(1000, total_combinations // 100)
    num_processes = max(1, os.cpu_count() - 1)

    results = []
    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = []
        for start in range(0, total_combinations, batch_size):
            end = min(start + batch_size, total_combinations)
            batch = [str(i).zfill(key_length) for i in range(start, end)]
            futures.append(executor.submit(process_exhaustive_batch, (ciphertext, alphabet, batch, expected_freqs)))
        
        for i, future in enumerate(as_completed(futures)):
            results.extend(future.result())
            print(f"Progress: {((i + 1) * batch_size) / total_combinations:.1%}", end='\r')
    
    if results:
        for r in results: r['matched_phrases'] = [w for w in known_plaintexts if w.lower() in r['decrypted']]
        results.sort(key=lambda x: (-(len(x['matched_phrases'])), x['score'], -x['ioc']))
        
        print(f"\n{YELLOW}--- TOP 10 RANKED SOLUTIONS ---{RESET}")
        for i, result in enumerate(results[:10]):
            phrase_marker = f" {GREEN}({len(result['matched_phrases'])} words matched){RESET}" if result['matched_phrases'] else ""
            highlighted = highlight_phrases(result['decrypted'], result['matched_phrases'])
            print(f"{GREY}-{'':-^50}{RESET}")
            print(f"Rank #{i+1}: Key: {YELLOW}{result['key']}{RESET}{phrase_marker}")
            print(f"Scores: N-gram: {YELLOW}{result['score']:.2f}{RESET} | IoC: {YELLOW}{result['ioc']:.4f}{RESET}")
            print(f"Decrypted: {highlighted}")
    else:
        print(f"\n{RED}NO SOLUTIONS FOUND{RESET}")

# --- SIMULATED ANNEALING ATTACK ---
def generate_neighbor_numeric_key(key: str) -> str:
    key_list = list(key)
    key_list[random.randint(0, len(key_list) - 1)] = str(random.randint(0, 9))
    return "".join(key_list)

def run_simulated_annealing_attack(ciphertext: str, alphabet: str, config: Dict):
    """Anneal the numeric key with the shared engine (geometric 20 -> 0.1).

    The previous loop started at temperature 1000 on a 0-255 cost scale, so
    most of its iterations were a random walk.
    """
    key_length = config.get('key_length', 5)
    iterations = config.get('iterations', 200000)
    restarts = config.get('restarts', 5)
    scoring_mode = config.get('scoring_mode', '3')
    ngram_size = config.get('ngram_size', DEFAULT_NGRAM_SIZE)
    ioc_range = (config.get('min_ioc', 0.060), config.get('max_ioc', 0.070))
    model = load_ngram_frequencies(resolve_ngram_path(ngram_size))

    label = 'Combined' if scoring_mode == '3' else 'IoC' if scoring_mode == '2' else 'N-Gram'
    print(f"\n{BLUE}--- Simulated Annealing Engine ({label} Scoring, {restarts} restarts x {iterations:,} steps) ---{RESET}")
    if scoring_mode in ['2', '3']:
        print(f"{GREY}Target IoC Range: {ioc_range[0]:.4f} - {ioc_range[1]:.4f}{RESET}")

    results = solve_periodic(
        ciphertext, alphabet, "0123456789", key_length,
        lambda c, d, m: (c - d) % m,            # Gronsfeld: P = C - digit
        model, Schedule(iterations), restarts=restarts,
        ioc_range=ioc_range, scoring_mode=scoring_mode,
    )
    if results is None:
        print(f"{RED}Annealing needs an alphabet that is a permutation of A-Z.{RESET}")
        return

    print("\n" + "="*80)
    print(f"\n{YELLOW}--- TOP RANKED SOLUTIONS (one per restart) ---{RESET}")
    seen = set()
    for rank, (key, fitness, _) in enumerate(results, start=1):
        if key in seen:
            continue
        seen.add(key)
        text = gronsfeld_decrypt(ciphertext, key, alphabet)
        print(f"Rank #{rank}: Key: {YELLOW}{key}{RESET} | Fitness: {YELLOW}{fitness:.2f}{RESET} (higher is better) | IoC: {YELLOW}{utils.calculate_ioc(text):.4f}{RESET}")
        print(f"Text: {text.lower()}")
        print("-" * 60)

# --- MAIN APPLICATION ---
def run_direct_decrypt(ciphertext: str, alphabet: str):
    print(f"\n{BLUE}--- Direct Decryption ---{RESET}")
    key = input("Enter the numeric key: ")
    if not key.isdigit():
        print(f"{RED}Invalid key.{RESET}")
        return
    print(f"\nKey: {YELLOW}{key}{RESET}\nDecrypted: {gronsfeld_decrypt(ciphertext, key, alphabet)}")

def run():
    banner("Gronsfeld Cipher", "Vigenere variant with a numeric key")
    ciphertext = input("\nEnter the ciphertext: ").upper()
    alphabet = input(f"Enter custom alphabet (default: {RED}A-Z{RESET}): ").upper() or "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    expected_freqs = load_ngram_frequencies(ngram_path)

    while True:
        print(f"\n{GREY}{'-'*50}{RESET}")
        print("Select an attack mode:")
        print(f"  ({YELLOW}1{RESET}) Direct Decryption (Known Key)")
        print(f"  ({YELLOW}2{RESET}) Exhaustive Attack (Key Length <= 8)")
        print(f"  ({YELLOW}3{RESET}) Simulated Annealing (Unknown Key of any length)")
        print(f"  ({YELLOW}4{RESET}) Exit")
        choice = input(">> ")

        if choice == '1':
            run_direct_decrypt(ciphertext, alphabet)
        elif choice == '2':
            run_exhaustive_attack(ciphertext, alphabet, expected_freqs)
        elif choice == '3':
            config = {}
            config['key_length'] = int(input("Enter exact key length: "))
            
            print(f"\n{GREY}Select Ranking/Optimization Metric:{RESET}")
            print(f"  ({YELLOW}1{RESET}) Pure N-Grams")
            print(f"  ({YELLOW}2{RESET}) Pure English IoC Range (Best for Outer-Layer Double Ciphers)")
            print(f"  ({YELLOW}3{RESET}) Combined (N-Grams weighted by IoC Range) [Recommended]")
            config['scoring_mode'] = input(">> ").strip() or '3'
            
            if config['scoring_mode'] in ['1', '3']:
                ng = input(f"Choose n-gram size (2-6, default {YELLOW}{DEFAULT_NGRAM_SIZE}{RESET}): ")
                config['ngram_size'] = int(ng) if ng else DEFAULT_NGRAM_SIZE
                
            if config['scoring_mode'] in ['2', '3']:
                config['min_ioc'] = float(input(f"Enter target MIN IoC (default {YELLOW}0.060{RESET}): ") or 0.060)
                config['max_ioc'] = float(input(f"Enter target MAX IoC (default {YELLOW}0.070{RESET}): ") or 0.070)
                
            config['iterations'] = int(input(f"Enter iterations (default {YELLOW}200,000{RESET}): ") or 200000)
            run_simulated_annealing_attack(ciphertext, alphabet, config)
        elif choice == '4':
            break

if __name__ == "__main__":
    run()