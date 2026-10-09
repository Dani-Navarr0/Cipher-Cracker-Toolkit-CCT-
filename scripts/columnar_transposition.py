import os
import math
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Dict
from functools import lru_cache
from itertools import permutations
import random
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores, score_text

# --- DUMMY UTILS CLASS (to make script standalone) ---
class DummyUtils:
    """Provides utility functions to make the script standalone."""
    def save_results_to_file(self, results: List[Dict], filename: str):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("Columnar Transposition Brute-Force Results\n")
                f.write("==========================================\n\n")
                for result in results:
                    f.write(f"Key: {result['key']}\n")
                    f.write(f"IoC Score: {result.get('ioc', 0):.4f}\n")
                    f.write(f"N-gram Score: {result.get('bigram_score', 0):.2f}\n")
                    f.write(f"Decrypted: {result['plaintext']}\n")
                    f.write("-" * 20 + "\n")
            print(f"{GREEN}Results successfully saved to {filename}{RESET}")
        except IOError as e:
            print(f"{RED}Error saving file: {e}{RESET}")

    def analyze_frequency(self, text: str):
        print("\n--- Frequency Analysis ---")
        text = ''.join(filter(str.isalpha, text.upper()))
        total = len(text)
        if total == 0:
            print("No alphabetic characters to analyze.")
            return
        freqs = {char: text.count(char) for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
        sorted_freqs = sorted(freqs.items(), key=lambda item: item[1], reverse=True)
        print("Character Frequencies:")
        for char, count in sorted_freqs:
            percentage = (count / total) * 100
            print(f"{char}: {count:<4} ({percentage:.2f}%)")
        print("-" * 25)

utils = DummyUtils()

# --- COLOR CODES AND PATHS ---
RED = '\033[38;5;88m'
YELLOW = '\033[38;5;3m'
GREY = '\033[38;5;238m'
GREEN = '\033[38;5;2m'
BLUE = '\033[38;5;21m'
RESET = '\033[0m'

# Check if running in a standard terminal or an environment that might not have __file__
try:
    data_dir = os.path.join(os.path.dirname(__file__), "data")
except NameError:
    data_dir = os.path.join(os.getcwd(), "data")

dictionary_path = os.path.join(data_dir, "words_alpha.txt")
ngram_path = DEFAULT_NGRAM_PATH

# --- SCORING FUNCTIONS ---
def calculate_ioc(text: str) -> float:
    text = ''.join(filter(str.isalpha, text.upper()))
    n = len(text)
    if n < 2: return 0.0
    freqs = {char: text.count(char) for char in text}
    numerator = sum(count * (count - 1) for count in freqs.values())
    denominator = n * (n - 1)
    return numerator / denominator if denominator > 0 else 0.0

@lru_cache(maxsize=None)
def load_bigram_frequencies(file_path: str) -> Dict[str, float]:
    return load_ngram_scores(file_path)

def calculate_bigram_score(text: str, expected_freqs: Dict[str, float]) -> float:
    return score_text(text, expected_freqs)

# --- CORE DECRYPTION AND PROCESSING ---
def decrypt_columnar_transposition(ciphertext: str, key: str) -> str:
    key_map = sorted([(char, i) for i, char in enumerate(key)])
    key_len = len(key)
    if key_len == 0: return ""
    num_rows = math.ceil(len(ciphertext) / key_len)
    num_full_cols = len(ciphertext) % key_len or key_len
    
    grid = [['' for _ in range(key_len)] for _ in range(num_rows)]
    
    cipher_index = 0
    for _, original_index in key_map:
        num_chars_in_col = num_rows if original_index < num_full_cols else num_rows - 1
        for i in range(num_chars_in_col):
            if cipher_index < len(ciphertext):
                grid[i][original_index] = ciphertext[cipher_index]
                cipher_index += 1

    return ''.join([''.join(row) for row in grid])

def process_key_batch(args):
    keys, ciphertext, expected_freqs = args
    results = []
    for key in keys:
        decrypted = decrypt_columnar_transposition(ciphertext, key)
        ioc = calculate_ioc(decrypted)
        bigram_score = calculate_bigram_score(decrypted, expected_freqs)
        results.append({
            'key': key,
            'plaintext': decrypted,
            'ioc': ioc,
            'bigram_score': bigram_score
        })
    return results

def parallel_process_keys(keys: List[str], ciphertext: str, expected_freqs: Dict) -> List[Dict]:
    all_results = []
    num_processes = max(1, os.cpu_count() - 1)
    batch_size = max(1, len(keys) // (num_processes * 4))
    
    tasks = [(keys[i:i + batch_size], ciphertext, expected_freqs) for i in range(0, len(keys), batch_size)]
    total_batches = len(tasks)

    print(f"Processing {YELLOW}{len(keys):,}{RESET} keys in {YELLOW}{total_batches:,}{RESET} batches using {YELLOW}{num_processes}{RESET} processes.")

    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = [executor.submit(process_key_batch, task) for task in tasks]
        for i, future in enumerate(as_completed(futures)):
            try:
                all_results.extend(future.result())
                progress = (i + 1) / total_batches * 100
                print(f"Progress: {i + 1}/{total_batches} batches ({progress:.1f}%)", end='\r')
            except Exception as e:
                print(f"An error occurred in a worker process: {e}")
    print("\n")
    return all_results

# --- UI AND ATTACK MODE FUNCTIONS ---
def highlight_phrases(text: str, phrases: List[str]) -> str:
    if not phrases:
        return text
    
    phrases.sort(key=len, reverse=True)
    
    highlighted_text = text
    for phrase in phrases:
        if not phrase: continue
        escaped_phrase = re.escape(phrase)
        highlighted_text = re.sub(
            f'({escaped_phrase})', 
            f'{RED}\\1{RESET}', 
            highlighted_text, 
            flags=re.IGNORECASE
        )
    return highlighted_text

def run_bruteforce(keys_to_test: List[str], ciphertext: str, required_words: List[str]):
    if not keys_to_test:
        print(f"{RED}No keys to test based on the criteria.{RESET}")
        return

    expected_freqs = load_bigram_frequencies(ngram_path)
    all_results = parallel_process_keys(keys_to_test, ciphertext, expected_freqs)

    if all_results:
        all_results.sort(key=lambda x: (
            0 if all(word.lower() in x['plaintext'].lower() for word in required_words) else 1,
            x['bigram_score'], -x['ioc']
        ))
        
        print(f"\n{YELLOW}--- RANKED SOLUTIONS FOUND ---{RESET}")
        for result in all_results[:20]:
            plaintext_lower = result['plaintext'].lower()
            has_all_words = all(word.lower() in plaintext_lower for word in required_words)
            match_marker = GREEN + " (Plaintext Match)" + RESET if required_words and has_all_words else ""
            highlighted_decrypted = highlight_phrases(result['plaintext'], required_words)

            print(f"{GREY}-{RESET}" * 60)
            print(f"Key: {YELLOW}{result['key']}{RESET}{match_marker}")
            print(f"N-gram Score: {YELLOW}{result['bigram_score']:.2f}{RESET} (Lower is better), IoC: {YELLOW}{result['ioc']:.4f}{RESET}")
            print(f"Decrypted: {highlighted_decrypted}")

        save_option = input("\nEnter filename to save full results (or press Enter to skip): ")
        if save_option:
            utils.save_results_to_file(all_results, save_option)

        if input(f"Run frequency analysis on best match? ({YELLOW}Y/N{RESET}): ").upper() == 'Y':
            utils.analyze_frequency(all_results[0]['plaintext'])
    else:
        print(f"\n{RED}NO SOLUTIONS FOUND{RESET}")

def dictionary_attack():
    print(f"\n{BLUE}--- Dictionary Attack ---{RESET}")
    ciphertext = input("Enter ciphertext: ").upper().replace(" ", "")
    required_words_input = input("Enter known plaintext words to prioritize (comma-separated, optional): ")
    required_words = [word.strip() for word in required_words_input.split(",")] if required_words_input else []
    min_len = int(input(f"Enter minimum key length (default: {YELLOW}4{RESET}): ") or "4")
    max_len = int(input(f"Enter maximum key length (default: {YELLOW}12{RESET}): ") or "12")

    try:
        with open(dictionary_path, 'r') as f:
            wordlist = [word.strip().upper() for word in f if min_len <= len(word.strip()) <= max_len]
        print(f"\n{GREEN}Loaded {len(wordlist):,} words from dictionary matching length criteria.{RESET}")
        run_bruteforce(wordlist, ciphertext, required_words)
    except FileNotFoundError:
        print(f"{RED}Error: Dictionary not found at '{dictionary_path}'.{RESET}")

def exhaustive_attack():
    print(f"\n{BLUE}--- Exhaustive Permutation Attack ---{RESET}")
    ciphertext = input("Enter ciphertext: ").upper().replace(" ", "")
    required_words_input = input("Enter known plaintext words to prioritize (comma-separated, optional): ")
    required_words = [word.strip() for word in required_words_input.split(",")] if required_words_input else []
    
    try:
        key_len = int(input("Enter exact key length to test (e.g., 8): "))
        if key_len <= 1 or key_len > 12:
            print(f"{RED}Key length must be between 2 and 12 for practical performance.{RESET}")
            return
        
        num_perms = math.factorial(key_len)
        print(f"Generating {YELLOW}{num_perms:,}{RESET} permutations for key length {key_len}...")
        if key_len > 10:
            if input(f"{YELLOW}Warning: This will be very slow. Continue? (Y/N): {RESET}").upper() != 'Y': return
        
        cols = "0123456789AB"[:key_len]
        keys_to_test = ["".join(p) for p in permutations(cols)]
        run_bruteforce(keys_to_test, ciphertext, required_words)

    except ValueError:
        print(f"{RED}Invalid number.{RESET}")

def direct_decrypt():
    print(f"\n{BLUE}--- Direct Decrypt ---{RESET}")
    ciphertext = input("Enter ciphertext: ").upper().replace(" ", "")
    key = input("Enter key (e.g., 'SECRET' or '512634'): ").upper()
    required_words_input = input("Enter plaintext words to highlight (comma-separated, optional): ")
    required_words = [word.strip() for word in required_words_input.split(",")] if required_words_input else []
    
    if not key:
        print(f"{RED}Key cannot be empty.{RESET}")
        return

    plaintext = decrypt_columnar_transposition(ciphertext, key)
    highlighted_plaintext = highlight_phrases(plaintext, required_words)
    
    print(f"\n{GREY}---------------------------------{RESET}")
    print(f"Key: {YELLOW}{key}{RESET}")
    print(f"Plaintext: {GREEN}{highlighted_plaintext}{RESET}")
    print(f"{GREY}---------------------------------{RESET}")

def double_exhaustive_attack():
    """
    Performs an exhaustive search for a double columnar transposition cipher,
    allowing for two different key lengths.
    """
    print(f"\n{BLUE}--- Double Exhaustive Attack (Variable Length) ---{RESET}")
    ciphertext = input("Enter ciphertext: ").upper().replace(" ", "")
    required_words_input = input("Enter known plaintext words to highlight (comma-separated, optional): ")
    required_words = [word.strip() for word in required_words_input.split(",")] if required_words_input else []
    
    try:
        key_len1 = int(input(f"Enter length for the {YELLOW}first key{RESET} (e.g., 3): "))
        key_len2 = int(input(f"Enter length for the {YELLOW}second key{RESET} (e.g., 4): "))

        if not (2 <= key_len1 <= 8 and 2 <= key_len2 <= 8):
            print(f"{RED}Error: Key lengths must be between 2 and 8 for practical performance.{RESET}")
            return
            
        num_perms1 = math.factorial(key_len1)
        num_perms2 = math.factorial(key_len2)
        total_combinations = num_perms1 * num_perms2

        if total_combinations > 5_000_000: # Set a reasonable warning threshold
            if input(f"{YELLOW}Warning: Testing {total_combinations:,} combinations may be very slow. Continue? (Y/N): {RESET}").upper() != 'Y':
                return

    except ValueError:
        print(f"{RED}Invalid number.{RESET}")
        return

    expected_freqs = load_bigram_frequencies(ngram_path)
    if not expected_freqs:
        print(f"{YELLOW}Warning: Bigram frequency file not found. Scoring will be unreliable.{RESET}")
        return

    # Generate permutations for each key length
    cols1 = "01234567"[:key_len1]
    keys1 = ["".join(p) for p in permutations(cols1)]
    cols2 = "01234567"[:key_len2]
    keys2 = ["".join(p) for p in permutations(cols2)]
    
    print(f"Testing {YELLOW}{total_combinations:,}{RESET} key combinations ({num_perms1:,} for key1 x {num_perms2:,} for key2)...")

    best_score = float('inf')
    best_result = {}
    
    try:
        # Iterate through the two different sets of keys
        for i, key1 in enumerate(keys1):
            for j, key2 in enumerate(keys2):
                intermediate_text = decrypt_columnar_transposition(ciphertext, key2)
                final_plaintext = decrypt_columnar_transposition(intermediate_text, key1)
                
                current_score = calculate_bigram_score(final_plaintext, expected_freqs)
                
                if current_score < best_score:
                    best_score = current_score
                    best_result = {
                        'key1': key1, 'key2': key2, 'plaintext': final_plaintext,
                        'bigram_score': current_score, 'ioc': calculate_ioc(final_plaintext)
                    }
                    progress = ((i * len(keys2) + j + 1) / total_combinations) * 100
                    display_text = best_result['plaintext'].replace('\n', ' ').replace('\r', '')[:50]
                    print(f"\rProgress: {progress:6.2f}% | Best Score: {best_score:10.2f} | Keys: ({key1}, {key2}) | Text: {display_text}...", end="")

        print("\n" + "="*80)
        print(f"\n{YELLOW}--- FINAL BEST RESULT ---{RESET}")
        if best_result:
            highlighted_decrypted = highlight_phrases(best_result['plaintext'], required_words)
            print(f"Keys: {YELLOW}({best_result['key1']}, {best_result['key2']}){RESET}")
            print(f"N-gram Score: {YELLOW}{best_result['bigram_score']:.2f}{RESET} (Lower is better)")
            print(f"IoC: {YELLOW}{best_result['ioc']:.4f}{RESET}")
            print(f"Decrypted: {highlighted_decrypted}")
        else:
            print(f"{RED}No result found.{RESET}")

    except KeyboardInterrupt:
        print("\n\nProcess interrupted by user.")
        if best_result:
            print(f"\n{YELLOW}--- BEST RESULT FOUND BEFORE STOPPING ---{RESET}")
            highlighted_decrypted = highlight_phrases(best_result['plaintext'], required_words)
            print(f"Keys: {YELLOW}({best_result['key1']}, {best_result['key2']}){RESET}")
            print(f"N-gram Score: {YELLOW}{best_result['bigram_score']:.2f}{RESET}")
            print(f"IoC: {YELLOW}{best_result['ioc']:.4f}{RESET}")
            print(f"Decrypted: {highlighted_decrypted}")

def generate_neighbor(key: str) -> str:
    """Generates a neighbor key by swapping two characters."""
    key_list = list(key)
    i, j = random.sample(range(len(key_list)), 2)
    key_list[i], key_list[j] = key_list[j], key_list[i]
    return "".join(key_list)

def simulated_annealing_attack_single():
    """
    Attempts to break a single columnar transposition cipher using simulated annealing.
    """
    print(f"\n{BLUE}--- Simulated Annealing Attack (Single Key) ---{RESET}")
    ciphertext = input("Enter ciphertext: ").upper().replace(" ", "")
    required_words_input = input("Enter known plaintext words to highlight (comma-separated, optional): ")
    required_words = [word.strip() for word in required_words_input.split(",")] if required_words_input else []
    
    try:
        key_len = int(input(f"Enter exact key length to test (e.g., 10, recommended for keys > 8): "))
        if key_len <= 1:
            print(f"{RED}Key length must be greater than 1.{RESET}")
            return
        
        default_iters = 500_000 if key_len > 12 else 200_000
        iterations = int(input(f"Enter number of iterations (default: {YELLOW}{default_iters:,}{RESET}): ") or str(default_iters))

    except ValueError:
        print(f"{RED}Invalid number.{RESET}")
        return

    initial_temp = 1000.0 
    print(f"Running {YELLOW}{iterations:,}{RESET} iterations... (Updates will print only when a better score is found)")
    
    expected_freqs = load_bigram_frequencies(ngram_path)
    if not expected_freqs:
        print(f"{RED}Bigram frequency file not found. Cannot score candidates.{RESET}")
        return

    # Initial State
    cols = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:key_len]
    current_key = "".join(random.sample(cols, len(cols)))
    current_plaintext = decrypt_columnar_transposition(ciphertext, current_key)
    current_score = calculate_bigram_score(current_plaintext, expected_freqs)

    best_state = {
        'key': current_key,
        'bigram_score': current_score
    }
    
    temp = initial_temp
    try:
        for i in range(iterations):
            new_key = generate_neighbor(current_key)
            new_plaintext = decrypt_columnar_transposition(ciphertext, new_key)
            new_score = calculate_bigram_score(new_plaintext, expected_freqs)
            
            delta = new_score - current_score
            if delta < 0 or random.random() < math.exp(-delta / temp):
                current_key = new_key
                current_score = new_score
                
                if current_score < best_state['bigram_score']:
                    # --- MODIFICATION: Only store the key and score ---
                    best_state['key'] = current_key
                    best_state['bigram_score'] = current_score
                    
                    # --- Re-decrypt for display to ensure consistency ---
                    best_plaintext_for_display = decrypt_columnar_transposition(ciphertext, best_state['key'])
                    display_text = best_plaintext_for_display.replace('\n', ' ').replace('\r', '')[:50]
                    print(f"Score: {best_state['bigram_score']:<10.2f} | Key: {YELLOW}{best_state['key']}{RESET} | Text: {display_text}...")

            temp = initial_temp * (1.0 - (i + 1) / iterations)

        print("\n" + "="*80)
        print(f"\n{YELLOW}--- FINAL BEST RESULT ---{RESET}")
        if best_state.get('key'):
            # --- MODIFICATION: Final decryption from the best key found ---
            final_plaintext = decrypt_columnar_transposition(ciphertext, best_state['key'])
            highlighted_decrypted = highlight_phrases(final_plaintext, required_words)
            print(f"Key: {YELLOW}{best_state['key']}{RESET}")
            print(f"N-gram Score: {YELLOW}{best_state['bigram_score']:.2f}{RESET} (Lower is better)")
            print(f"IoC: {YELLOW}{calculate_ioc(final_plaintext):.4f}{RESET}")
            print(f"Decrypted: {highlighted_decrypted}")
        else:
            print(f"{RED}No result found.{RESET}")

    except KeyboardInterrupt:
        print("\n\nProcess interrupted by user.")
        if best_state.get('key'):
             print(f"\n{YELLOW}--- BEST RESULT FOUND BEFORE STOPPING ---{RESET}")
             final_plaintext = decrypt_columnar_transposition(ciphertext, best_state['key'])
             highlighted_decrypted = highlight_phrases(final_plaintext, required_words)
             print(f"Key: {YELLOW}{best_state['key']}{RESET}")
             print(f"N-gram Score: {YELLOW}{best_state['bigram_score']:.2f}{RESET}")
             print(f"Decrypted: {highlighted_decrypted}")

def simulated_annealing_attack_double():
    """
    Attempts to break a double columnar transposition cipher using simulated annealing.
    """
    print(f"\n{BLUE}--- Simulated Annealing Attack (Double Key) ---{RESET}")
    ciphertext = input("Enter ciphertext: ").upper().replace(" ", "")
    required_words_input = input("Enter known plaintext words to highlight (comma-separated, optional): ")
    required_words = [word.strip() for word in required_words_input.split(",")] if required_words_input else []
    
    try:
        same_length_choice = input("Are both keys the same length? (Y/N, default: Y): ").upper() or "Y"
        if same_length_choice == 'Y':
            key_len = int(input(f"Enter the exact key length for both keys (e.g., 10): "))
            if key_len <= 1:
                print(f"{RED}Key length must be greater than 1.{RESET}")
                return
            key_len1, key_len2 = key_len, key_len
        else:
            key_len1 = int(input(f"Enter the length for the {YELLOW}first key{RESET} (e.g., 8): "))
            key_len2 = int(input(f"Enter the length for the {YELLOW}second key{RESET} (e.g., 10): "))
            if key_len1 <= 1 or key_len2 <= 1:
                print(f"{RED}Key lengths must be greater than 1.{RESET}")
                return
        
        default_iters = 500_000 if max(key_len1, key_len2) > 10 else 200_000
        iterations = int(input(f"Enter number of iterations (default: {YELLOW}{default_iters:,}{RESET}): ") or str(default_iters))

    except ValueError:
        print(f"{RED}Invalid number.{RESET}")
        return

    initial_temp = 1000.0 
    print(f"Running {YELLOW}{iterations:,}{RESET} iterations... (Updates will print only when a better score is found)")
    
    expected_freqs = load_bigram_frequencies(ngram_path)
    if not expected_freqs:
        print(f"{RED}Bigram frequency file not found. Cannot score candidates.{RESET}")
        return

    # Initial State
    cols1 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:key_len1]
    cols2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:key_len2]
    current_key1 = "".join(random.sample(cols1, len(cols1)))
    current_key2 = "".join(random.sample(cols2, len(cols2)))
    
    intermediate = decrypt_columnar_transposition(ciphertext, current_key2)
    current_plaintext = decrypt_columnar_transposition(intermediate, current_key1)
    current_score = calculate_bigram_score(current_plaintext, expected_freqs)

    best_state = {
        'key1': current_key1,
        'key2': current_key2,
        'bigram_score': current_score
    }
    
    temp = initial_temp
    try:
        for i in range(iterations):
            new_key1, new_key2 = current_key1, current_key2
            if random.random() < 0.5:
                new_key1 = generate_neighbor(current_key1)
            else:
                new_key2 = generate_neighbor(current_key2)

            intermediate = decrypt_columnar_transposition(ciphertext, new_key2)
            new_plaintext = decrypt_columnar_transposition(intermediate, new_key1)
            new_score = calculate_bigram_score(new_plaintext, expected_freqs)
            
            delta = new_score - current_score
            if delta < 0 or random.random() < math.exp(-delta / temp):
                current_key1, current_key2 = new_key1, new_key2
                current_score = new_score
                
                if current_score < best_state['bigram_score']:
                    # --- MODIFICATION: Only store the keys and score ---
                    best_state['key1'] = current_key1
                    best_state['key2'] = current_key2
                    best_state['bigram_score'] = current_score

                    # --- Re-decrypt for display to ensure consistency ---
                    intermediate_display = decrypt_columnar_transposition(ciphertext, best_state['key2'])
                    best_plaintext_for_display = decrypt_columnar_transposition(intermediate_display, best_state['key1'])
                    display_text = best_plaintext_for_display.replace('\n', ' ').replace('\r', '')[:40]
                    print(f"Score: {best_state['bigram_score']:<10.2f} | Keys: ({YELLOW}{best_state['key1']}{RESET}, {YELLOW}{best_state['key2']}{RESET}) | Text: {display_text}...")

            temp = initial_temp * (1.0 - (i + 1) / iterations)

        print("\n" + "="*80)
        print(f"\n{YELLOW}--- FINAL BEST RESULT ---{RESET}")
        if best_state.get('key1'):
            # --- MODIFICATION: Final decryption from the best keys found ---
            intermediate = decrypt_columnar_transposition(ciphertext, best_state['key2'])
            final_plaintext = decrypt_columnar_transposition(intermediate, best_state['key1'])
            highlighted_decrypted = highlight_phrases(final_plaintext, required_words)
            print(f"Keys: {YELLOW}({best_state['key1']}, {best_state['key2']}){RESET}")
            print(f"N-gram Score: {YELLOW}{best_state['bigram_score']:.2f}{RESET} (Lower is better)")
            print(f"IoC: {YELLOW}{calculate_ioc(final_plaintext):.4f}{RESET}")
            print(f"Decrypted: {highlighted_decrypted}")
        else:
            print(f"{RED}No result found.{RESET}")

    except KeyboardInterrupt:
        print("\n\nProcess interrupted by user.")
        if best_state.get('key1'):
             print(f"\n{YELLOW}--- BEST RESULT FOUND BEFORE STOPPING ---{RESET}")
             intermediate = decrypt_columnar_transposition(ciphertext, best_state['key2'])
             final_plaintext = decrypt_columnar_transposition(intermediate, best_state['key1'])
             highlighted_decrypted = highlight_phrases(final_plaintext, required_words)
             print(f"Keys: {YELLOW}({best_state['key1']}, {best_state['key2']}){RESET}")
             print(f"N-gram Score: {YELLOW}{best_state['bigram_score']:.2f}{RESET}")
             print(f"Decrypted: {highlighted_decrypted}")

def run():
    while True:
        print(f"\n{BLUE}Columnar Transposition Cipher Tool{RESET}")
        print(f"{GREY}" + "="*50 + RESET)
        print(f"1. {YELLOW}Dictionary Attack{RESET} (Single Transposition)")
        print(f"2. {YELLOW}Exhaustive Attack{RESET} (Single Transposition, Key Length <= 12)")
        print(f"3. {YELLOW}Direct Decrypt{RESET} (Single Transposition)")
        print(f"4. {YELLOW}Double Exhaustive Attack{RESET} (Double Transposition, Key Length <= 8)")
        print(f"5. {GREEN}Simulated Annealing ({RESET}{YELLOW}Single Key{RESET}{GREEN}, Key Length > 8){RESET}") # New option
        print(f"6. {GREEN}Simulated Annealing ({RESET}{YELLOW}Double Key{RESET}{GREEN}, Any Key Length){RESET}") # Renamed
        print(f"7. {RED}Exit{RESET}")
        
        choice = input("\nSelect an option: ")
        
        if choice == '1': dictionary_attack()
        elif choice == '2': exhaustive_attack()
        elif choice == '3': direct_decrypt()
        elif choice == '4': double_exhaustive_attack()
        elif choice == '5': simulated_annealing_attack_single() # Call new function
        elif choice == '6': simulated_annealing_attack_double() # Call renamed function
        elif choice == '7':
            print(f"{BLUE}Goodbye!{RESET}")
            break
        else:
            print(f"{RED}Invalid choice, please try again.{RESET}")
        
        input(f"\n{GREY}Press Enter to return to the main menu...{RESET}")
        os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == "__main__":
    if not os.path.exists(data_dir): os.makedirs(data_dir)
    if not os.path.exists(dictionary_path):
        print(f"{GREY}Creating dummy dictionary file at '{dictionary_path}'...{RESET}")
        with open(dictionary_path, 'w') as f: f.write("SECRET\nCRYPTO\nCOLUMN\nKEY\nCIPHER\nATTACK\n")
    
    run()