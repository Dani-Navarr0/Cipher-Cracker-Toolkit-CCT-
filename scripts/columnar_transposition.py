import os
import math
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Dict
from functools import lru_cache
from itertools import permutations
import random
from collections import Counter
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores, score_text
from transposition_core import make_decryptor
from annealing import Fitness, Schedule
from layered import LayeredSolver, TranspositionLayer
from ngram_scoring import codes_to_text, text_to_codes

# Below this many keys one process beats spawning a pool (see process_key_batch).
PARALLEL_THRESHOLD = 50_000

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
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner, option

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
    freqs = Counter(text)
    numerator = sum(count * (count - 1) for count in freqs.values())
    denominator = n * (n - 1)
    return numerator / denominator if denominator > 0 else 0.0

@lru_cache(maxsize=None)
def load_bigram_frequencies(file_path: str) -> Dict[str, float]:
    return load_ngram_scores(file_path)

def calculate_bigram_score(text: str, expected_freqs: Dict[str, float]) -> float:
    return score_text(text, expected_freqs)

# --- CORE DECRYPTION AND PROCESSING ---
def key_order(key: str) -> tuple:
    """Column read order for a key: columns sorted by (letter, position)."""
    return tuple(original_index for _, original_index in sorted((char, i) for i, char in enumerate(key)))


def decrypt_columnar_transposition(ciphertext: str, key: str) -> str:
    if len(key) == 0: return ""
    try:
        decrypt = make_decryptor(ciphertext, len(key), "write_rows_read_cols")
    except UnicodeEncodeError:
        return _decrypt_columnar_grid(ciphertext, key)
    return decrypt(key_order(key)).decode("latin-1")


def _decrypt_columnar_grid(ciphertext: str, key: str) -> str:
    """Reference grid implementation (used for non-Latin-1 text)."""
    key_map = sorted([(char, i) for i, char in enumerate(key)])
    key_len = len(key)
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
    evaluated = {}
    decryptors = {}
    for key in keys:
        order = key_order(key)
        cached = evaluated.get(order)
        if cached is None:
            decrypt = decryptors.get(len(key))
            if decrypt is None:
                try:
                    decrypt = decryptors[len(key)] = make_decryptor(ciphertext, len(key), "write_rows_read_cols")
                except UnicodeEncodeError:
                    decrypt = None
            decrypted = decrypt(order).decode("latin-1") if decrypt else _decrypt_columnar_grid(ciphertext, key)
            cached = evaluated[order] = (decrypted, calculate_ioc(decrypted), calculate_bigram_score(decrypted, expected_freqs))
        decrypted, ioc, bigram_score = cached
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
    if len(keys) < PARALLEL_THRESHOLD or num_processes == 1:
        print(f"Processing {YELLOW}{len(keys):,}{RESET} keys in a single process.")
        return process_key_batch((keys, ciphertext, expected_freqs))
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
    phrases = sorted((phrase for phrase in phrases if phrase), key=len, reverse=True)
    if not phrases:
        return text
    pattern = "|".join(re.escape(phrase) for phrase in phrases)
    return re.sub(f'({pattern})', f'{RED}\\1{RESET}', text, flags=re.IGNORECASE)

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
        best_position = None
        for j, key2 in enumerate(keys2):
            intermediate_text = decrypt_columnar_transposition(ciphertext, key2)
            for i, key1 in enumerate(keys1):
                final_plaintext = decrypt_columnar_transposition(intermediate_text, key1)

                current_score = calculate_bigram_score(final_plaintext, expected_freqs)

                # Ties go to the earliest combination in key1-major order, as before the loop swap.
                if best_position is None or current_score < best_score or (current_score == best_score and (i, j) < best_position):
                    best_position = (i, j)
                    best_score = current_score
                    best_result = {
                        'key1': key1, 'key2': key2, 'plaintext': final_plaintext,
                        'bigram_score': current_score, 'ioc': calculate_ioc(final_plaintext)
                    }
                    progress = ((j * len(keys1) + i + 1) / total_combinations) * 100
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


KEY_LABELS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def order_to_key(order) -> str:
    """Column read order -> key string usable with decrypt_columnar_transposition."""
    key = [""] * len(order)
    for rank, column in enumerate(order):
        key[column] = KEY_LABELS[rank] if len(order) <= len(KEY_LABELS) else chr(0x100 + rank)
    return "".join(key)


def anneal_columnar(ciphertext: str, widths, iterations: int, restarts: int = 3):
    """Shared-engine annealing for single or double columnar transposition.

    ``widths`` are in encryption order ([w] or [w1, w2], key 1 applied first).
    Uses the geometric 20 -> 0.1 schedule plus a final hill climb; the previous
    loop started at 1000 with linear cooling (a random walk for ~98% of it).
    Returns (keys in encryption order, plaintext, n-gram cost).
    """
    letters = "".join(char for char in ciphertext if "A" <= char <= "Z")
    codes = text_to_codes(letters)
    model = load_bigram_frequencies(ngram_path)
    best = None
    for attempt in range(1, restarts + 1):
        layers = [TranspositionLayer(len(codes), width, "write_rows_read_cols") for width in reversed(widths)]
        solver = LayeredSolver(codes, layers, Fitness(model, 0.5, fixed_letters=codes))
        solver.anneal(Schedule(iterations))
        score = solver.polish()
        plaintext = codes_to_text(solver.plaintext())
        keys = [order_to_key(layer.key) for layer in reversed(layers)]
        print(f"Run {attempt}/{restarts}: keys {keys} | {plaintext[:50]}...")
        if best is None or score > best[0]:
            best = (score, keys, plaintext)
    _, keys, plaintext = best
    return keys, plaintext, calculate_bigram_score(plaintext, model)


def ask_restarts(default: int = 3) -> int:
    text = input(f"Independent runs (default: {YELLOW}{default}{RESET}): ").strip()
    return max(1, int(text)) if text.isdigit() else default


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
        default_iters = 1_000_000 if key_len > 12 else 300_000
        iterations = int(input(f"Enter number of iterations per run (default: {YELLOW}{default_iters:,}{RESET}): ").replace(",", "") or str(default_iters))
        restarts = ask_restarts()
    except ValueError:
        print(f"{RED}Invalid number.{RESET}")
        return

    print(f"Running {YELLOW}{restarts}{RESET} x {YELLOW}{iterations:,}{RESET} iterations (Ctrl+C ends a run early)...")
    keys, plaintext, cost = anneal_columnar(ciphertext, [key_len], iterations, restarts)
    print("\n" + "="*80)
    print(f"\n{YELLOW}--- FINAL BEST RESULT ---{RESET}")
    print(f"Key: {YELLOW}{keys[0]}{RESET}")
    print(f"N-gram Score: {YELLOW}{cost:.2f}{RESET} (Lower is better)")
    print(f"IoC: {YELLOW}{calculate_ioc(plaintext):.4f}{RESET}")
    print(f"Decrypted: {highlight_phrases(plaintext, required_words)}")


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
        default_iters = 1_500_000 if max(key_len1, key_len2) > 10 else 800_000
        iterations = int(input(f"Enter number of iterations per run (default: {YELLOW}{default_iters:,}{RESET}): ").replace(",", "") or str(default_iters))
        restarts = ask_restarts(4)
    except ValueError:
        print(f"{RED}Invalid number.{RESET}")
        return

    print(f"Running {YELLOW}{restarts}{RESET} x {YELLOW}{iterations:,}{RESET} iterations (Ctrl+C ends a run early)...")
    print(f"{GREY}Tip: the Two-Layer Solver in the main menu runs these searches in parallel across CPU cores.{RESET}")
    keys, plaintext, cost = anneal_columnar(ciphertext, [key_len1, key_len2], iterations, restarts)
    print("\n" + "="*80)
    print(f"\n{YELLOW}--- FINAL BEST RESULT ---{RESET}")
    print(f"Keys: {YELLOW}({keys[0]}, {keys[1]}){RESET}")
    print(f"N-gram Score: {YELLOW}{cost:.2f}{RESET} (Lower is better)")
    print(f"IoC: {YELLOW}{calculate_ioc(plaintext):.4f}{RESET}")
    print(f"Decrypted: {highlight_phrases(plaintext, required_words)}")

def run():
    while True:
        banner("Columnar Transposition", "Dictionary, exhaustive and annealing attacks")
        option(1, "Dictionary attack", "(single transposition)")
        option(2, "Exhaustive attack", "(single transposition, key length <= 12)")
        option(3, "Direct decrypt", "(single transposition)")
        option(4, "Double exhaustive attack", "(double transposition, key lengths <= 8)")
        option(5, "Simulated annealing: single key", "(key length > 8)")
        option(6, "Simulated annealing: double key", "(any key length)")
        option(7, "Back to main menu")
        
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