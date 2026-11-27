import random
import math
import time
import os
from collections import Counter
from utils.utils import get_input_ciphertexts
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores, score_text

from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner
ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ" # J is typically omitted
ngram_path = DEFAULT_NGRAM_PATH

def calculate_ioc(text: str) -> float:
    text = ''.join(filter(str.isalpha, text.upper()))
    n = len(text)
    if n < 2: return 0.0
    freqs = Counter(text)
    numerator = sum(count * (count - 1) for count in freqs.values())
    denominator = n * (n - 1)
    return numerator / denominator if denominator > 0 else 0.0

def load_bigram_frequencies(file_path):
    return load_ngram_scores(file_path)

def calculate_fitness(text, expected_freqs):
    return score_text(text, expected_freqs)

def generate_square(key):
    sq = []
    for char in key.upper() + ALPHABET:
        char = 'I' if char == 'J' else char
        if char in ALPHABET and char not in sq:
            sq.append(char)
    return "".join(sq)

def decrypt_foursquare(ciphertext, tr_matrix, bl_matrix):
    # The squares merge J into I; dropping J would shift every digraph after it.
    text = "".join(c for c in ciphertext.upper().replace("J", "I") if c in ALPHABET)
    if len(text) % 2 != 0: text += "X"
    
    plaintext = []
    for i in range(0, len(text), 2):
        c1, c2 = text[i], text[i+1]
        if c1 not in tr_matrix or c2 not in bl_matrix:
            plaintext.extend([c1, c2])
            continue
            
        r1, col1 = divmod(tr_matrix.index(c1), 5)
        r2, col2 = divmod(bl_matrix.index(c2), 5)
        
        plaintext.append(ALPHABET[r1 * 5 + col2]) # TL
        plaintext.append(ALPHABET[r2 * 5 + col1]) # BR
    return "".join(plaintext)

def mutate(tr, bl):
    if random.random() < 0.5:
        idx1, idx2 = random.sample(range(25), 2)
        l = list(tr)
        l[idx1], l[idx2] = l[idx2], l[idx1]
        return "".join(l), bl
    else:
        idx1, idx2 = random.sample(range(25), 2)
        l = list(bl)
        l[idx1], l[idx2] = l[idx2], l[idx1]
        return tr, "".join(l)

def run_sa(ciphertext, expected_freqs, config):
    temp = config.get('initial_temp', 20.0)
    cooling_rate = config.get('cooling_rate', 0.995)
    steps_per_temp = config.get('steps_per_temp', 1000)

    tr, bl = "".join(random.sample(ALPHABET, 25)), "".join(random.sample(ALPHABET, 25))
    best_tr, best_bl = tr, bl
    best_score = current_score = calculate_fitness(decrypt_foursquare(ciphertext, tr, bl), expected_freqs)
    
    print(f"\n{YELLOW}Starting Simulated Annealing...{RESET}")
    start_time = time.time()
    
    try:
        while temp > 0.1:
            for _ in range(steps_per_temp):
                new_tr, new_bl = mutate(tr, bl)
                new_score = calculate_fitness(decrypt_foursquare(ciphertext, new_tr, new_bl), expected_freqs)
                
                delta = current_score - new_score
                if delta > 0 or random.random() < math.exp(delta / temp):
                    tr, bl, current_score = new_tr, new_bl, new_score
                    if new_score < best_score:
                        best_tr, best_bl, best_score = new_tr, new_bl, new_score
            temp *= cooling_rate
            print(f"Temp: {temp:>5.2f} | Score: {GREEN}{best_score:>8.2f}{RESET} | Text: {decrypt_foursquare(ciphertext, best_tr, best_bl)[:40]}...", end='\r')
    except KeyboardInterrupt:
        pass
        
    best_plaintext = decrypt_foursquare(ciphertext, best_tr, best_bl)
    final_ioc = calculate_ioc(best_plaintext)

    print(f"\n{GREEN}Annealing Complete in {time.time() - start_time:.2f}s!{RESET}")
    print(f"Key 1 (Top-Right): {best_tr}\nKey 2 (Bottom-Left): {best_bl}")
    print(f"N-gram Score: {YELLOW}{best_score:.2f}{RESET}")
    print(f"IoC: {YELLOW}{final_ioc:.4f}{RESET}")
    print(f"Plaintext:\n{best_plaintext}\n")

# ---------------------------------------------------------------- fast annealing

def _pairs(ciphertext):
    text = "".join(c for c in ciphertext.upper().replace("J", "I") if c in ALPHABET)
    if len(text) % 2:
        text = text[:-1]
    codes = bytes(ALPHABET.index(c) for c in text)
    return codes[0::2], codes[1::2]


def make_decryptor(ciphertext):
    """decrypt(tr_pos, bl_pos) -> plaintext as 0-24 indices; C when available."""
    first, second = _pairs(ciphertext)
    try:
        import ctypes
        import native
        p = ctypes.c_char_p
        function = native.function("cct_foursquare_decrypt", None, [p, p, ctypes.c_int32, p, p, p])
    except Exception:
        function = None
    if function is not None:
        out = ctypes.create_string_buffer(2 * len(first))

        def decrypt(tr_pos, bl_pos):
            function(first, second, len(first), bytes(tr_pos), bytes(bl_pos), out)
            return out.raw
        return decrypt

    def decrypt(tr_pos, bl_pos):
        out = bytearray(2 * len(first))
        for i, (a, b) in enumerate(zip(first, second)):
            a, b = tr_pos[a], bl_pos[b]
            out[2 * i] = (a // 5) * 5 + b % 5
            out[2 * i + 1] = (b // 5) * 5 + a % 5
        return bytes(out)
    return decrypt


TO_AZ = bytes(ord(ch) - 65 for ch in ALPHABET) + bytes(231)


def solve(ciphertext, iterations=1_000_000, seed=None):
    """One annealing run on the shared engine. Returns (fitness, TR key, BL key, plaintext)."""
    from annealing import Schedule, anneal, hill_climb
    import cipher_profile as cp
    if seed is not None:
        random.seed(seed)
    decrypt = make_decryptor(ciphertext)
    fitness = cp.fitness_function()
    squares = [random.sample(range(25), 25), random.sample(range(25), 25)]      # cell -> letter
    positions = [[0] * 25, [0] * 25]                                            # letter -> cell
    for k in (0, 1):
        for cell, letter in enumerate(squares[k]):
            positions[k][letter] = cell
    last = []

    def score():
        return fitness(decrypt(positions[0], positions[1]).translate(TO_AZ))

    def swap(k, i, j):
        square, position = squares[k], positions[k]
        square[i], square[j] = square[j], square[i]
        position[square[i]], position[square[j]] = i, j

    def propose():
        k = random.randrange(2)
        i, j = random.sample(range(25), 2)
        swap(k, i, j)
        last[:] = [k, i, j]
        return score()

    def undo():
        swap(*last)

    best, _ = anneal(score(), propose, undo, lambda: (squares[0][:], squares[1][:]), Schedule(iterations))
    for k in (0, 1):
        squares[k][:] = best[k]
        for cell, letter in enumerate(squares[k]):
            positions[k][letter] = cell

    def apply_move(move):
        swap(*move)
        last[:] = list(move)
        return score()
    moves = [(k, i, j) for k in (0, 1) for i in range(25) for j in range(i + 1, 25)]
    final = hill_climb(score(), moves, apply_move, undo, 10)
    keys = ["".join(ALPHABET[x] for x in squares[k]) for k in (0, 1)]
    plain = "".join(ALPHABET[x] for x in decrypt(positions[0], positions[1]))
    return final, keys[0], keys[1], plain


def solve_job(job):
    return solve(job['ciphertext'], job['iterations'], job['seed'])


def run_parallel(ciphertext, iterations=1_000_000, runs=8):
    from concurrent.futures import ProcessPoolExecutor, as_completed
    import cipher_profile as cp
    jobs = [{'ciphertext': ciphertext, 'iterations': iterations, 'seed': random.randrange(2 ** 32)} for _ in range(runs)]
    workers = max(1, min(runs, (os.cpu_count() or 2) - 1))
    started, results = time.time(), []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for done, future in enumerate(as_completed([pool.submit(solve_job, job) for job in jobs]), start=1):
            results.append(future.result())
            print(f"  run {done}/{runs} | best fitness {max(r[0] for r in results):.1f}", end="\r")
    results.sort(key=lambda r: -r[0])
    best = results[0]
    agreeing = sum(1 for r in results if r[3] == best[3])
    letters = len(_pairs(ciphertext)[0]) * 2
    verdict = cp.judge(best[0], cp.references(letters)) if letters >= cp.MIN_LETTERS else ""
    print(f"\n{GREEN}Done in {time.time() - started:.0f} s.{RESET} Best fitness {best[0]:.1f} [{verdict}], "
          f"{agreeing}/{len(results)} runs agree")
    print(f"Key 1 (Top-Right): {best[1]}\nKey 2 (Bottom-Left): {best[2]}\nPlaintext:\n{best[3]}\n")
    return results


def run():
    banner("Four-Square Cipher", "Direct decryption or simulated annealing (parallel runs)")
    ciphers = get_input_ciphertexts()
    if not ciphers: return

    print(f"\n  ({YELLOW}1{RESET}) Direct Decryption\n  ({YELLOW}2{RESET}) Simulated Annealing {GREY}(no key needed){RESET}")
    mode = input(">> ").strip()

    for cipher in ciphers:
        if mode == '1':
            k1 = input("Enter Key 1 (Top-Right): ")
            k2 = input("Enter Key 2 (Bottom-Left): ")
            print(decrypt_foursquare(cipher, generate_square(k1), generate_square(k2)))
        elif mode == '2':
            s = input(f"Annealing steps per run (default {YELLOW}1,000,000{RESET}): ").strip().replace(",", "")
            r = input(f"Independent runs (default {YELLOW}8{RESET}): ").strip()
            run_parallel(cipher, int(s) if s.isdigit() else 1_000_000, int(r) if r.isdigit() and int(r) > 0 else 8)

if __name__ == "__main__":
    run()