import itertools
from concurrent.futures import ProcessPoolExecutor, as_completed
import os
from typing import List, Dict, Tuple
from functools import lru_cache
import random
import math
import time
from collections import Counter
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
RESET, GREEN, YELLOW, RED, BLUE, CYAN, GREY = '\033[0m', '\033[32m', '\033[33m', '\033[31m', '\033[34m', '\033[36m', '\033[90m'

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

    for i, char in enumerate(ciphertext):
        char_upper = char.upper()
        if char_upper in alphabet:
            char_index = alphabet.index(char_upper)
            shift = key_digits[i % key_length]
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
    key_length = config.get('key_length', 5)
    iterations = config.get('iterations', 200000)
    initial_temp = config.get('temp', 1000.0)
    cooling_rate = config.get('cooling_rate', 0.99995)
    
    scoring_mode = config.get('scoring_mode', '3')
    ngram_size = config.get('ngram_size', DEFAULT_NGRAM_SIZE)
    target_min_ioc = config.get('min_ioc', 0.060)
    target_max_ioc = config.get('max_ioc', 0.070)
    
    freq_path = resolve_ngram_path(ngram_size)
    expected_freqs = load_ngram_frequencies(freq_path)

    # TOP 5 TRACKER
    top_results = []
    def add_to_top(k, s, t):
        if not any(r['key'] == k for r in top_results):
            top_results.append({'key': k, 'score': s, 'text': t})
            top_results.sort(key=lambda x: x['score'])
            if len(top_results) > 5:
                top_results.pop()

    # DYNAMIC FITNESS ENGINE
    def get_ioc_penalty(text_ioc: float) -> float:
        if target_min_ioc <= text_ioc <= target_max_ioc: return 0.0
        elif text_ioc < target_min_ioc: return target_min_ioc - text_ioc
        else: return text_ioc - target_max_ioc

    def evaluate_fitness(text: str) -> float:
        if scoring_mode == '1': 
            return calculate_ngram_score(text, expected_freqs, ngram_size)
            
        text_ioc = utils.calculate_ioc(text)
        ioc_penalty = get_ioc_penalty(text_ioc)

        if scoring_mode == '2': 
            return ioc_penalty * 1000 
        else: 
            ngram_score = calculate_ngram_score(text, expected_freqs, ngram_size)
            return ngram_score * (1.0 + (ioc_penalty * 50))

    print(f"\n{BLUE}--- Simulated Annealing Engine ({'Combined' if scoring_mode == '3' else 'IoC' if scoring_mode == '2' else 'N-Gram'} Scoring) ---{RESET}")
    if scoring_mode in ['2', '3']:
        print(f"{GREY}Target IoC Range: {target_min_ioc:.4f} - {target_max_ioc:.4f}{RESET}")

    current_key = "".join(str(random.randint(0, 9)) for _ in range(key_length))
    current_text = gronsfeld_decrypt(ciphertext, current_key, alphabet)
    current_score = evaluate_fitness(current_text)
    
    best_key, best_score = current_key, current_score
    add_to_top(current_key, current_score, current_text)
    
    try:
        temp = initial_temp
        for i in range(iterations):
            temp *= cooling_rate
            if temp <= 0: break
            
            neighbor_key = generate_neighbor_numeric_key(current_key)
            neighbor_text = gronsfeld_decrypt(ciphertext, neighbor_key, alphabet)
            neighbor_score = evaluate_fitness(neighbor_text)
            
            delta = neighbor_score - current_score
            if delta < 0 or random.random() < math.exp(-delta / temp):
                current_key, current_score, current_text = neighbor_key, neighbor_score, neighbor_text
                
                # Check if it makes the Top 5
                if len(top_results) < 5 or current_score < top_results[-1]['score']:
                    add_to_top(current_key, current_score, current_text)

                if current_score < best_score:
                    best_key, best_score = current_key, current_score
                    display_text = current_text.replace('\n', ' ')[:35]
                    print(f"Score: {best_score:<8.2f} | Key: {best_key} | Text: {display_text}...", end='\r')

        print("\n" + "="*80)
        print(f"\n{YELLOW}--- TOP 5 RANKED SOLUTIONS ---{RESET}")
        for i, res in enumerate(top_results):
            print(f"Rank #{i+1}: Key: {YELLOW}{res['key']}{RESET} | Score: {YELLOW}{res['score']:.2f}{RESET} | IoC: {YELLOW}{utils.calculate_ioc(res['text']):.4f}{RESET}")
            print(f"Text: {res['text'].lower()}")
            print("-" * 60)

    except KeyboardInterrupt:
        print("\n\nProcess interrupted by user.")

# --- MAIN APPLICATION ---
def run_direct_decrypt(ciphertext: str, alphabet: str):
    print(f"\n{BLUE}--- Direct Decryption ---{RESET}")
    key = input("Enter the numeric key: ")
    if not key.isdigit():
        print(f"{RED}Invalid key.{RESET}")
        return
    print(f"\nKey: {YELLOW}{key}{RESET}\nDecrypted: {gronsfeld_decrypt(ciphertext, key, alphabet)}")

def run():
    print(f"{RED}Gronsfeld Cipher Toolkit{RESET}")
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