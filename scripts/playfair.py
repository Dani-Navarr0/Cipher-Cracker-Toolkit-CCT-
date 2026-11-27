"""Playfair cipher: keyless square annealing (mode A, playfair_anneal), a
keyword dictionary attack and direct decryption.

The dictionary attack builds the square of every word of the word list (the
keyword's distinct letters, then the rest of the alphabet), decrypts and
scores it in C (native/digraphic.c: cct_playfair_keywords), and ranks the
words by the toolkit's fitness; optional known plaintext words (cribs) flag
the squares whose plaintext contains all of them.
"""
import heapq
import math
import os
import time
from functools import lru_cache
from typing import Dict, List, Tuple

from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores
from theme import RED, GREEN, YELLOW, GREY, RESET, banner

# Default Playfair alphabet
DEFAULT_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
dictionary_path = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")
ngram_path = DEFAULT_NGRAM_PATH
CHUNK_WORDS = 10_000


# --- CORE PLAYFAIR FUNCTIONS (one-shot) ---

@lru_cache(maxsize=4096)
def create_playfair_matrix(key: str, alphabet: str) -> List[List[str]]:
    matrix_chars = []
    key_upper = key.upper()
    # Merge J into I *before* filtering, otherwise J is dropped as "not in alphabet".
    if len(alphabet) == 25 and 'J' not in alphabet:
        key_upper = key_upper.replace('J', 'I')
    normalized_key = "".join(char for char in key_upper if char in alphabet)

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


@lru_cache(maxsize=4096)
def get_char_map(matrix: Tuple[Tuple[str, ...], ...]) -> Dict[str, Tuple[int, int]]:
    return {char: (r, c) for r, row in enumerate(matrix) for c, char in enumerate(row)}


def normalize_text(text: str, alphabet: str) -> str:
    """Upper case, J -> I for a 25-symbol alphabet without J, only alphabet symbols."""
    text = text.upper()
    if len(alphabet) == 25 and 'J' not in alphabet:
        text = text.replace('J', 'I')
    return "".join(char for char in text if char in alphabet)


def decrypt_playfair(ciphertext: str, key: str, alphabet: str) -> str:
    matrix = create_playfair_matrix(key, alphabet)
    matrix_tuple = tuple(tuple(row) for row in matrix)
    char_map = get_char_map(matrix_tuple)

    plaintext = []
    normalized_text = normalize_text(ciphertext, alphabet)
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
    if not phrases: return False  # No crib given: nothing can "match".
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


def deduplicate_results(results: List[Dict]) -> List[Dict]:
    """Filters out duplicate plaintexts (caused by keys that reduce to the same Playfair matrix)."""
    unique_results = []
    seen_plaintexts = set()
    for res in results:
        if res['plaintext'] not in seen_plaintexts:
            seen_plaintexts.add(res['plaintext'])
            unique_results.append(res)
    return unique_results


def save_results_to_file(results: List[Dict], filename: str):
    with open(filename, 'w', encoding='utf-8') as f:
        for result in results:
            f.write(f"Key: {result['key']}\n")
            f.write(f"Fitness: {result['fitness']:.2f}\n")
            f.write(f"IoC: {result['ioc']:.6f}\n")
            if result.get('crib'):
                f.write("Contains every crib: yes\n")
            f.write(f"Plaintext: {result['plaintext']}\n")
            f.write("-" * 20 + "\n")
    print(f"Results saved to {filename}")


# --- KEYWORD (DICTIONARY) ATTACK, C ---

def symbol_encoder(alphabet: str):
    """encode(text) -> bytes of alphabet indices (upper case, J -> I for a
    25-symbol alphabet without J, other characters dropped), using C-level
    string operations only (it runs on every word of the word list)."""
    count = len(alphabet)
    table = {code: None for code in range(128, 128 + count)}        # input symbols that would clash
    for i, char in enumerate(alphabet):
        table[ord(char)] = chr(128 + i)
    if count == 25 and 'J' not in alphabet and 'I' in alphabet:
        table[ord('J')] = table[ord('I')]
    table = str.maketrans(table)
    shift = bytes((b - 128) % 256 for b in range(256))
    drop = bytes(range(128)) + bytes(range(128 + count, 256))

    def encode(text: str) -> bytes:
        return text.upper().translate(table).encode("latin-1", "ignore").translate(shift, drop)
    return encode


def keyword_attack(ciphertext: str, words: List[str], alphabet: str = DEFAULT_ALPHABET, cribs: List[str] = (),
                   top: int = 100, ngram_model=None, progress=None):
    """Score the keyword square of every word in C. ``cribs``: known plaintext
    words; a square is flagged when its plaintext contains all of them.
    ``progress(words done, total)`` is called after every chunk; Ctrl+C stops
    early and keeps the words scored so far.
    Returns (best ``top`` results by fitness, every crib-matching result), each
    a list of dicts {'key', 'plaintext', 'fitness', 'ioc', 'crib'}, best first,
    one per distinct plaintext."""
    from native import digraphic
    model = ngram_model or load_ngram_scores(DEFAULT_NGRAM_PATH)
    dim = math.isqrt(len(alphabet))
    if dim * dim != len(alphabet) or dim not in (5, 6) or len(set(alphabet)) != len(alphabet):
        raise ValueError("the alphabet must have 25 or 36 distinct symbols")
    encode = symbol_encoder(alphabet)
    text = normalize_text(ciphertext, alphabet)
    cipher = encode(text[:len(text) // 2 * 2])
    to_az = bytes(ord(char) - 65 if "A" <= char <= "Z" else 255 for char in alphabet)
    index = {char: i for i, char in enumerate(alphabet)}
    crib_codes = []
    for crib in cribs:
        if any(ch.isalnum() for ch in crib):
            crib = crib.upper().replace(" ", "")
            if len(alphabet) == 25 and 'J' not in alphabet:
                crib = crib.replace('J', 'I')
            crib_codes.append(bytes(index.get(char, 255) for char in crib))   # 255: cannot occur
    keys = [encode(word) for word in words]
    m = len(keys)
    fitness, ioc, hits = [float("-inf")] * m, [0.0] * m, [0] * m

    def score_chunk(start):
        f, i, h = digraphic.playfair_keywords(cipher, dim, to_az, keys[start:start + CHUNK_WORDS], model, crib_codes)
        end = start + len(f)
        fitness[start:end], ioc[start:end], hits[start:end] = f, i, h
        return len(f)
    # ctypes releases the GIL during the C call, so the threads run in parallel
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import compute
    workers = compute.workers(-(-m // CHUNK_WORDS))
    done = 0
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [pool.submit(score_chunk, start) for start in range(0, m, CHUNK_WORDS)]
        for future in as_completed(futures):
            done += future.result()
            if progress:
                progress(done, m)
        pool.shutdown()
    except KeyboardInterrupt:
        pool.shutdown(wait=True, cancel_futures=True)
        print(f"\n{YELLOW}Interrupted; ranking the words scored so far.{RESET}")

    def result(i):
        return {'key': words[i], 'plaintext': decrypt_playfair(text, words[i], alphabet), 'fitness': fitness[i],
                'ioc': ioc[i], 'crib': bool(hits[i])}
    order = [i for i in heapq.nlargest(top * 4, range(m), key=fitness.__getitem__) if fitness[i] > float("-inf")]
    best = deduplicate_results([result(i) for i in order])[:top]
    crib_rows = [i for i in range(len(hits)) if hits[i]]
    crib_rows.sort(key=lambda i: -fitness[i])
    return best, deduplicate_results([result(i) for i in crib_rows])


def run_dictionary_attack(ciphertext: str, alphabet: str):
    import cipher_profile as cp
    print(f"\n{YELLOW}--- Dictionary Attack (every word as the keyword, scored in C) ---{RESET}")
    crib_input = input("Known plaintext words, all must occur (comma-separated, optional): ").upper()
    cribs = [p.strip() for p in crib_input.split(",") if p.strip()]
    extra_input = input("Extra keys to try besides the word list (comma-separated, optional): ").upper()
    extra = [k.strip() for k in extra_input.split(",") if k.strip()]
    print(f"{YELLOW}Loading dictionary...{RESET}")
    words = extra + load_dictionary(dictionary_path, alphabet)
    if not words:
        return
    started = time.time()

    def progress(done, total):
        print(f"Progress: {done:,}/{total:,} keywords ({100 * done / total:.1f}%)", end='\r')
    best, crib_results = keyword_attack(ciphertext, words, alphabet, cribs, progress=progress)
    print(f"\n{YELLOW}Scored {len(words):,} keywords in {time.time() - started:.2f} seconds{RESET}")
    if not best:
        return
    letters = sum(1 for ch in best[0]['plaintext'] if "A" <= ch <= "Z")
    refs = cp.references(letters) if letters >= cp.MIN_LETTERS else None

    def show(rank, row):
        verdict = f" [{cp.judge(row['fitness'], refs)}]" if refs else ""
        marker = f" {YELLOW}(contains every crib){RESET}" if row['crib'] else ""
        print(f"{rank:>2}. key {YELLOW}{row['key']}{RESET} | fitness {row['fitness']:.1f}{verdict} | "
              f"IoC {row['ioc']:.4f}{marker}")
        print(f"    {highlight_match(row['plaintext'], cribs) if row['crib'] else row['plaintext']}")
    if cribs:
        print(f"\nFound {RED}{len(crib_results)}{RESET} UNIQUE plaintext(s) containing every crib")
        for rank, row in enumerate(crib_results[:10], start=1):
            show(rank, row)
    print(f"\n{YELLOW}BEST BY FITNESS{RESET} {GREY}(higher = more English){RESET}")
    for rank, row in enumerate(best[:10], start=1):
        show(rank, row)
    rows = deduplicate_results(crib_results + best)
    if input(f"\nSave {len(rows)} UNIQUE results to file? ({YELLOW}Y/N{RESET}): ").upper() == 'Y':
        filename = input("Enter filename for results: ") or "playfair_dictionary_results"
        save_results_to_file(rows, f"{filename}.txt")


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
    banner("Playfair Cipher", "Digraph cipher: square annealing (no key needed), dictionary attack, decrypt")

    # 1. Ask for Alphabet
    use_custom = input(f"Use custom alphabet? ({YELLOW}Y/N{RESET}): ").upper() == 'Y'
    current_alphabet = DEFAULT_ALPHABET
    if use_custom:
        custom_input = input(f"{GREY}Enter custom alphabet (25 or 36 distinct symbols, a 5x5 or 6x6 grid): {RESET}").upper()
        if len(custom_input) in [25, 36] and len(set(custom_input)) == len(custom_input):
            current_alphabet = custom_input
        else:
            print(f"{RED}Invalid alphabet ({len(custom_input)} symbols, or repeats). Using the default 25-letter "
                  f"alphabet.{RESET}")

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
        mode = input(f"Choose a mode:\n({YELLOW}A{RESET}) Annealing: no key or word list needed {GREY}(recommended; 5x5, J=I){RESET}\n"
                     f"({YELLOW}1{RESET}) Dictionary Attack {GREY}(every word as the keyword; optional crib words){RESET}\n"
                     f"({YELLOW}2{RESET}) Direct Decrypt\n({YELLOW}N{RESET}) Enter New Ciphertext\n"
                     f"({YELLOW}Q{RESET}) Quit to Main Menu\n{GREY}Selection: {RESET}").upper()

        if mode == 'A':
            if current_alphabet != DEFAULT_ALPHABET:
                print(f"{YELLOW}Annealing uses the standard 5x5 square (J = I), not the custom alphabet.{RESET}")
            import playfair_anneal
            playfair_anneal.attack_interactive(ciphertext)
        elif mode == 'Q':
            print(f"{YELLOW}Returning to main menu...{RESET}")
            break
        elif mode == 'N':
            new_ct = input(f"{GREY}Enter new ciphertext: {RESET}").upper()
            if new_ct:
                ciphertext = new_ct
        elif mode == '1':
            run_dictionary_attack(ciphertext, current_alphabet)
        elif mode == '2':
            run_direct_decrypt(ciphertext, current_alphabet)
        else:
            print(f"{RED}Invalid selection. Please enter a valid menu option.{RESET}")


if __name__ == "__main__":
    run()
