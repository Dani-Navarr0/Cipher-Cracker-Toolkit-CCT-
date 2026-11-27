"""Tool 45: columnar transposition. Every search runs in C: the exhaustive,
dictionary and double-exhaustive searches (native/layered_columnar.c) and the
single/double annealing (the layered engine, native/layered_engine.c).
Python keeps the menus, the key <-> column-order conversions, the one-shot
decryptions of the results and the output."""
import os
import math
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from typing import List, Dict
from functools import lru_cache
from collections import Counter
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores, score_text
from transposition_core import make_decryptor
from annealing import Fitness, Schedule
from layered import LayeredSolver, TranspositionLayer
from ngram_scoring import codes_to_text, text_to_codes

STANDARD = "write_rows_read_cols"     # the layout of every search in this tool

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

KEEP_PER_BATCH = 200


def _workers(tasks: int) -> int:
    import compute
    return compute.workers(tasks)


def _cost(total: int, length: int, ngram_size: int) -> float:
    """score_text's cost (255 - mean n-gram score; lower is better) from an n-gram total."""
    count = length - ngram_size + 1
    return 255 - total / count if count > 0 else float("inf")


def _result(codes, width, order, total, model, ioc, key=None) -> Dict:
    plaintext = codes_to_text(make_decryptor(codes, width, STANDARD)(order))
    return {'key': key if key is not None else order_to_key(order), 'plaintext': plaintext, 'ioc': ioc,
            'bigram_score': _cost(total, len(codes), model.size)}


def process_key_batch(args):
    """Score every key of ``keys`` (keywords or digit strings) as a columnar key
    (write rows, read columns), in C. ``args`` = (keys, ciphertext, n-gram model
    [, required words]); the ciphertext's letters A-Z are used. Returns the
    KEEP_PER_BATCH best results by n-gram cost (ties: earlier key) plus every
    result whose plaintext contains all the required words. Keys of length < 2
    or longer than the text (or 64) are skipped."""
    from native.layered_engine import MAXW, score_orders
    keys, ciphertext, expected_freqs = args[:3]
    required_words = [word for word in (args[3] if len(args) > 3 else []) if word]
    codes = text_to_codes(ciphertext)
    required = [text_to_codes(word) for word in required_words]
    ioc = calculate_ioc(codes_to_text(codes))
    by_width = {}
    for key in keys:
        if 2 <= len(key) <= min(MAXW, len(codes)):
            by_width.setdefault(len(key), {}).setdefault(key_order(key), []).append(key)
    entries = []                         # (total, matched, order, key), in key order per width
    for width, groups in by_width.items():
        orders = list(groups)
        totals, matched = score_orders(codes, width, STANDARD, expected_freqs, orders, required)
        for total, match, order, group in zip(totals, matched, orders, groups.values()):
            entries += [(total, match, order, key) for key in group]
    ranked = sorted(range(len(entries)), key=lambda index: -entries[index][0])
    keep = set(ranked[:KEEP_PER_BATCH])
    if required:
        keep |= {index for index, entry in enumerate(entries) if entry[1]}
    return [_result(codes, len(entries[index][2]), entries[index][2], entries[index][0], expected_freqs, ioc,
                    entries[index][3]) for index in sorted(keep, key=lambda index: -entries[index][0])]


def _run_threads(searches, total_work, label):
    """Step every resumable C search (TopK / DoubleColumnar) to the end on a
    thread pool (ctypes releases the GIL), printing progress; Ctrl+C stops all
    of them after their current call and keeps what they found."""
    stop = threading.Event()

    def work(search):
        while not stop.is_set() and search.step():
            pass

    started = time.time()
    with ThreadPoolExecutor(max_workers=_workers(len(searches))) as pool:
        futures = [pool.submit(work, search) for search in searches]
        try:
            pending = futures
            while pending:
                _, pending = wait(pending, timeout=0.5)
                done = sum(search.processed for search in searches)
                print(f"{label}: {done:,}/{total_work:,} ({done / max(1, total_work):.0%}) "
                      f"| {time.time() - started:.1f}s", end='\r')
        except KeyboardInterrupt:
            stop.set()
            print(f"\n{YELLOW}Interrupted: showing the best found so far.{RESET}")
        for future in futures:
            future.result()
    print()
    return not stop.is_set()


# --- UI AND ATTACK MODE FUNCTIONS ---
def highlight_phrases(text: str, phrases: List[str]) -> str:
    phrases = sorted((phrase for phrase in phrases if phrase), key=len, reverse=True)
    if not phrases:
        return text
    pattern = "|".join(re.escape(phrase) for phrase in phrases)
    return re.sub(f'({pattern})', f'{RED}\\1{RESET}', text, flags=re.IGNORECASE)

def exhaustive_results(ciphertext: str, width: int, required_words: List[str]) -> List[Dict]:
    """Every column order of ``width`` (write rows, read columns) in C, split by
    first column across threads. Returns the KEEP_PER_BATCH best by n-gram cost
    plus every order whose plaintext contains all the required words, best
    first (ties: the lexicographically earlier order)."""
    from native.layered_engine import TopK
    model = load_bigram_frequencies(ngram_path)
    codes = text_to_codes(ciphertext)
    required = [text_to_codes(word) for word in required_words if word]
    prefixes = [(column,) for column in range(width)] if width >= 8 else [()]
    searches = [TopK(codes, width, STANDARD, model, KEEP_PER_BATCH, prefix, required) for prefix in prefixes]
    _run_threads(searches, math.factorial(width), "Column orders tested")
    best = sorted((item for search in searches for item in search.best()), key=lambda item: (-item[0], item[1]))
    chosen = {tuple(order): total for total, order in best[:KEEP_PER_BATCH]}
    lost = 0
    for search in searches:
        for total, order in search.matches():
            chosen[tuple(order)] = total
        lost += max(0, search.nmatch.value - search.max_matches)
    if lost:
        print(f"{YELLOW}{lost:,} more orders contain the required words; only the first ones are listed.{RESET}")
    ioc = calculate_ioc(codes_to_text(codes))
    ordered = sorted(chosen.items(), key=lambda item: (-item[1], item[0]))
    return [_result(codes, width, list(order), total, model, ioc) for order, total in ordered]


def run_bruteforce(keys_to_test: List[str], ciphertext: str, required_words: List[str], precomputed=None):
    if not keys_to_test and precomputed is None:
        print(f"{RED}No keys to test based on the criteria.{RESET}")
        return

    expected_freqs = load_bigram_frequencies(ngram_path)
    if precomputed is None:
        print(f"Scoring {YELLOW}{len(keys_to_test):,}{RESET} keys in C...")
    all_results = precomputed if precomputed is not None else process_key_batch(
        (keys_to_test, ciphertext, expected_freqs, required_words))

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

def _ask_letters():
    return "".join(ch for ch in input("Enter ciphertext: ").upper() if "A" <= ch <= "Z")


def dictionary_attack():
    print(f"\n{BLUE}--- Dictionary Attack ---{RESET}")
    ciphertext = _ask_letters()
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
    ciphertext = _ask_letters()
    required_words_input = input("Enter known plaintext words to prioritize (comma-separated, optional): ")
    required_words = [word.strip() for word in required_words_input.split(",")] if required_words_input else []

    try:
        key_len = int(input("Enter exact key length to test (e.g., 8): "))
    except ValueError:
        print(f"{RED}Invalid number.{RESET}")
        return
    if not 2 <= key_len <= min(12, len(ciphertext)):
        print(f"{RED}Key length must be between 2 and 12 (and at most the text length).{RESET}")
        return
    num_perms = math.factorial(key_len)
    print(f"Testing {YELLOW}{num_perms:,}{RESET} column orders for key length {key_len} in C "
          f"on {_workers(key_len if key_len >= 8 else 1)} thread(s)...")
    if key_len > 11:
        if input(f"{YELLOW}Warning: {num_perms:,} orders take several minutes. Continue? (Y/N): {RESET}").upper() != 'Y':
            return
    run_bruteforce([], ciphertext, required_words,
                   precomputed=exhaustive_results(ciphertext, key_len, required_words))

def direct_decrypt():
    print(f"\n{BLUE}--- Direct Decrypt ---{RESET}")
    from transposition_core import order_to_keyword, parse_column_key
    from layered import TRANSPOSITION_MODES
    ciphertext = "".join(ch for ch in input("Enter ciphertext: ").upper() if "A" <= ch <= "Z")
    print(f"{GREY}Key: a keyword ('ZEBRAS'), a digit key ('521304'), or a read order as other tools print it "
          f"('[4, 2, 1, 3, 5, 0]' or '4 2 1 3 5 0').{RESET}")
    key_text = input("Enter key: ")
    order = parse_column_key(key_text)
    if not order or len(order) >= len(ciphertext):
        print(f"{RED}Could not read a column key from '{key_text}'.{RESET}")
        return
    modes = list(TRANSPOSITION_MODES)
    for index, mode in enumerate(modes, start=1):
        print(f"  [{index}] {TRANSPOSITION_MODES[mode]}{' (default)' if index == 1 else ''}")
    choice = input("Layout (Enter = 1): ").strip()
    mode = modes[int(choice) - 1] if choice.isdigit() and 1 <= int(choice) <= 4 else modes[0]
    required_words_input = input("Enter plaintext words to highlight (comma-separated, optional): ")
    required_words = [word.strip() for word in required_words_input.split(",")] if required_words_input else []

    plaintext = make_decryptor(ciphertext, len(order), mode)(order).decode("latin-1")
    highlighted_plaintext = highlight_phrases(plaintext, required_words)

    print(f"\n{GREY}---------------------------------{RESET}")
    print(f"Read order: {YELLOW}{order}{RESET} | as a key: {YELLOW}{order_to_keyword(order)}{RESET} | {TRANSPOSITION_MODES[mode]}")
    print(f"Plaintext: {GREEN}{highlighted_plaintext}{RESET}")
    print(f"{GREY}---------------------------------{RESET}")

def double_exhaustive_results(ciphertext: str, key_len1: int, key_len2: int):
    """Double columnar (key 1 applied first, both write rows / read columns):
    every key2 x every key1 in C, key2 ranges split across threads. Keys are
    digit strings ('0'..'7'), each tried in itertools.permutations order; ties
    go to the earliest (key1 index, key2 index). Returns a result dict or None."""
    from native.layered_engine import DoubleColumnar
    model = load_bigram_frequencies(ngram_path)
    codes = text_to_codes(ciphertext)
    outer = math.factorial(key_len2)
    parts = min(outer, 4 * _workers(outer))
    bounds = [outer * part // parts for part in range(parts + 1)]
    searches = [DoubleColumnar(codes, key_len1, key_len2, model, bounds[part], bounds[part + 1])
                for part in range(parts) if bounds[part] < bounds[part + 1]]
    _run_threads(searches, outer, f"Key-2 orders done (x {math.factorial(key_len1):,} key-1 orders each)")
    found = [search.best() for search in searches if search.best() is not None]
    if not found:
        return None
    total, i, j, key1, key2 = min(found, key=lambda item: (-item[0], item[1], item[2]))
    key1, key2 = "".join(map(str, key1)), "".join(map(str, key2))
    plaintext = decrypt_columnar_transposition(decrypt_columnar_transposition(codes_to_text(codes), key2), key1)
    return {'key1': key1, 'key2': key2, 'plaintext': plaintext, 'bigram_score': _cost(total, len(codes), model.size),
            'ioc': calculate_ioc(plaintext)}


def double_exhaustive_attack():
    """
    Performs an exhaustive search for a double columnar transposition cipher,
    allowing for two different key lengths (in C).
    """
    print(f"\n{BLUE}--- Double Exhaustive Attack (Variable Length) ---{RESET}")
    ciphertext = _ask_letters()
    required_words_input = input("Enter known plaintext words to highlight (comma-separated, optional): ")
    required_words = [word.strip() for word in required_words_input.split(",")] if required_words_input else []

    try:
        key_len1 = int(input(f"Enter length for the {YELLOW}first key{RESET} (e.g., 3): "))
        key_len2 = int(input(f"Enter length for the {YELLOW}second key{RESET} (e.g., 4): "))
    except ValueError:
        print(f"{RED}Invalid number.{RESET}")
        return
    if not (2 <= key_len1 <= 8 and 2 <= key_len2 <= 8) or max(key_len1, key_len2) > len(ciphertext):
        print(f"{RED}Error: Key lengths must be between 2 and 8 (and at most the text length).{RESET}")
        return
    total_combinations = math.factorial(key_len1) * math.factorial(key_len2)
    if total_combinations > 100_000_000:
        if input(f"{YELLOW}Warning: Testing {total_combinations:,} combinations may take minutes. "
                 f"Continue? (Y/N): {RESET}").upper() != 'Y':
            return

    print(f"Testing {YELLOW}{total_combinations:,}{RESET} key combinations "
          f"({math.factorial(key_len1):,} for key1 x {math.factorial(key_len2):,} for key2) in C...")
    best_result = double_exhaustive_results(ciphertext, key_len1, key_len2)
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
    letters = sum(1 for char in ciphertext if "A" <= char <= "Z")
    if max([key_len]) > min(64, letters):
        print(f"{RED}Key length must be at most 64 (the C engine's limit) and the text length.{RESET}")
        return
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
    print(f"{GREY}Tip: the Two-Layer Solver (61) runs these searches as parallel independent runs.{RESET}")
    letters = sum(1 for char in ciphertext if "A" <= char <= "Z")
    if max([key_len1, key_len2]) > min(64, letters):
        print(f"{RED}Key length must be at most 64 (the C engine's limit) and the text length.{RESET}")
        return
    keys, plaintext, cost = anneal_columnar(ciphertext, [key_len1, key_len2], iterations, restarts)
    print("\n" + "="*80)
    print(f"\n{YELLOW}--- FINAL BEST RESULT ---{RESET}")
    print(f"Keys: {YELLOW}({keys[0]}, {keys[1]}){RESET}")
    print(f"N-gram Score: {YELLOW}{cost:.2f}{RESET} (Lower is better)")
    print(f"IoC: {YELLOW}{calculate_ioc(plaintext):.4f}{RESET}")
    print(f"Decrypted: {highlight_phrases(plaintext, required_words)}")

def run():
    import native
    native.require()            # every search runs in C
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