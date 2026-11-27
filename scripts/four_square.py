"""Four-square cipher: direct decryption with two keywords, or a keyless
attack that anneals both key squares in C (native/digraphic.c), with several
independent runs in parallel processes."""
import os
import random
import time

from utils.utils import get_input_ciphertexts
from theme import GREEN, YELLOW, GREY, RESET, banner

ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J is merged into I


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

# ---------------------------------------------------------------- keyless attack (C)

def _pairs(ciphertext):
    text = "".join(c for c in ciphertext.upper().replace("J", "I") if c in ALPHABET)
    if len(text) % 2:
        text = text[:-1]
    codes = bytes(ALPHABET.index(c) for c in text)
    return codes[0::2], codes[1::2]


def make_decryptor(ciphertext):
    """decrypt(tr_pos, bl_pos) -> plaintext as 0-24 indices (C)."""
    first, second = _pairs(ciphertext)
    import ctypes
    import native
    p = ctypes.c_char_p
    function = native.function("cct_foursquare_decrypt", None, [p, p, ctypes.c_int32, p, p, p])
    out = ctypes.create_string_buffer(2 * len(first))

    def decrypt(tr_pos, bl_pos):
        function(first, second, len(first), bytes(tr_pos), bytes(bl_pos), out)
        return out.raw
    return decrypt


TO_AZ = bytes(ord(ch) - 65 for ch in ALPHABET)


def solve(ciphertext, iterations=1_000_000, seed=None):
    """One annealing run in C over the top-right and bottom-left squares (swap
    two cells of one square per move; cooling 20 -> 0.1; then a polish over all
    600 single swaps). Returns (fitness, TR key, BL key, plaintext)."""
    from native import digraphic
    from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores
    if seed is not None:
        random.seed(seed)
    first, second = _pairs(ciphertext)
    symbols = bytes(x for pair in zip(first, second) for x in pair)
    # the model and weight of cipher_profile.fitness_function()
    cipher = digraphic.make_cipher(digraphic.FOURSQUARE, symbols, 25, TO_AZ, load_ngram_scores(DEFAULT_NGRAM_PATH))
    start = [random.sample(range(25), 25), random.sample(range(25), 25)]
    final, squares = digraphic.anneal(cipher, start, iterations, 20.0, 0.1, random.getrandbits(64), polish_rounds=10)
    keys = ["".join(ALPHABET[x] for x in squares[k]) for k in (0, 1)]
    _, plain = digraphic.score(cipher, squares)
    return final, keys[0], keys[1], "".join(ALPHABET[x] for x in plain)


def solve_job(job):
    return solve(job['ciphertext'], job['iterations'], job['seed'])


def run_parallel(ciphertext, iterations=1_000_000, runs=8):
    from concurrent.futures import ProcessPoolExecutor, as_completed
    import cipher_profile as cp
    import native
    native.require()
    jobs = [{'ciphertext': ciphertext, 'iterations': iterations, 'seed': random.randrange(2 ** 32)} for _ in range(runs)]
    import compute
    workers = compute.workers(runs)
    started, results = time.time(), []
    try:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for done, future in enumerate(as_completed([pool.submit(solve_job, job) for job in jobs]), start=1):
                results.append(future.result())
                print(f"  run {done}/{runs} | best fitness {max(r[0] for r in results):.1f}", end="\r")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted; showing the finished runs.{RESET}")
    if not results:
        return results
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