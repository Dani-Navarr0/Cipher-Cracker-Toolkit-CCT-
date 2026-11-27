"""Hill cipher: decryption, encryption, a ciphertext-only attack (row by row,
in C: native/digraphic_hill.c) and a known-plaintext attack."""
import itertools
import math
import time
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores

from theme import RED, GREEN, YELLOW, BLUE, GREY, RESET, banner


def calculate_ioc(text: str) -> float:
    text = "".join(filter(str.isalpha, text.upper()))
    n = len(text)
    if n < 2:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return sum(count * (count - 1) for count in counts.values()) / (n * (n - 1))


# --- HILL CIPHER CORE FUNCTIONS ---
def matrix_to_key(matrix, alphabet):
    key_str = ""
    for row in matrix:
        for element in row:
            key_str += alphabet[int(element) % len(alphabet)]
    return key_str

def key_to_matrix(key, matrix_size, alphabet):
    required_length = matrix_size * matrix_size
    key_indices = [alphabet.index(c) for c in key[:required_length] if c in alphabet]
    return [key_indices[row * matrix_size:(row + 1) * matrix_size] for row in range(matrix_size)]

# Matrices are plain lists/tuples of integer rows. Exact integer arithmetic
# (no floating-point determinant rounding) and no numpy dependency.

def determinant(matrix) -> int:
    size = len(matrix)
    if size == 1:
        return matrix[0][0]
    if size == 2:
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
    return sum(
        (-1) ** column * matrix[0][column] * determinant([row[:column] + row[column + 1:] for row in matrix[1:]])
        for column in range(size)
    )

def modular_inverse(matrix, modulus):
    """Modular inverse via the adjugate: inv = det^-1 * adj(M) (mod m)."""
    matrix = [list(row) for row in matrix]
    size = len(matrix)
    try:
        det_inv = pow(determinant(matrix) % modulus, -1, modulus)
    except ValueError:
        return None  # Determinant not invertible mod m: no inverse exists.
    if size == 1:
        return [[det_inv]]
    # adj[c][r] = cofactor(r, c)
    return [
        [
            det_inv * (-1) ** (r + c) * determinant(
                [row[:c] + row[c + 1:] for i, row in enumerate(matrix) if i != r]
            ) % modulus
            for r in range(size)
        ]
        for c in range(size)
    ]

def multiply_mod(left, right, modulus):
    return [
        [sum(left[r][k] * right[k][c] for k in range(len(right))) % modulus for c in range(len(right[0]))]
        for r in range(len(left))
    ]

def decrypt_with_inverse(cipher_indices, inverse_matrix, alphabet):
    """Decrypt pre-filtered, padded ciphertext indices with an inverse key."""
    size = len(inverse_matrix)
    modulus = len(alphabet)
    rows = [tuple(row) for row in inverse_matrix]
    out = []
    append = out.append
    for i in range(0, len(cipher_indices), size):
        chunk = cipher_indices[i:i + size]
        for row in rows:
            append(alphabet[sum(a * b for a, b in zip(row, chunk)) % modulus])
    return "".join(out)

def prepare_ciphertext(ciphertext, alphabet, matrix_size):
    indices = [alphabet.index(c) for c in ciphertext if c in alphabet]
    while len(indices) % matrix_size != 0:
        indices.append(0)  # pad with alphabet[0], as before
    return indices

def decrypt_hill(ciphertext, key_matrix, alphabet):
    """Decrypts Hill cipher using the column vector method."""
    inverse_matrix = modular_inverse(key_matrix, len(alphabet))
    if inverse_matrix is None: return None
    return decrypt_with_inverse(prepare_ciphertext(ciphertext, alphabet, len(key_matrix)), inverse_matrix, alphabet)

def is_valid_key_matrix(matrix, modulus):
    det = determinant(matrix) % modulus
    return det != 0 and math.gcd(det, modulus) == 1

# --- CIPHERTEXT-ONLY ROW ATTACK -------------------------------------------
# Decryption is p_block = D * c_block. Row i of D alone produces plaintext
# letters i, i+n, i+2n, ...: every n-th letter of the plaintext, which have
# English letter frequencies. So each possible row (26^n of them) is scored on
# its own, the best rows are kept, and only combinations of those rows are
# scored as full decryptions with n-grams. 3x3 needs 17,576 row scores instead
# of 26^9 matrices.

ENGLISH_PERCENT = [8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61,
                   6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07]


def row_attack(ciphertext, matrix_size=2, keep_rows=40, top=20, report=None):
    """Ciphertext-only attack on a Hill cipher over A-Z (C engine; matrix_size
    1-4). Stage 1 scores every row by chi-squared and keeps ``keep_rows``;
    stage 2 ranks every invertible ordered choice of kept rows by fitness.
    ``report(rows scored)`` is called after stage 1. Returns up to ``top``
    results, best first: dicts with key matrix, inverse, plaintext, fitness."""
    from native import digraphic
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if not 1 <= matrix_size <= 4:
        raise ValueError("row_attack handles 1x1 to 4x4 keys")
    if not matrix_size <= keep_rows <= 256:
        raise ValueError("keep_rows must be between the matrix size and 256")
    cipher = bytes(prepare_ciphertext(normalize_input(ciphertext, alphabet), alphabet, matrix_size))
    scored, best_rows = digraphic.hill_best_rows(cipher, matrix_size, ENGLISH_PERCENT, keep_rows)
    if report:
        report(scored)
    rows = [row for _, row in best_rows]
    out = []
    for score, combo in digraphic.hill_combine(cipher, matrix_size, rows, load_ngram_scores(DEFAULT_NGRAM_PATH), top):
        inverse = [list(rows[i]) for i in combo]
        key = modular_inverse(inverse, 26)
        out.append({'fitness': score, 'key_matrix': key, 'inverse': inverse,
                    'key_rep': matrix_to_key(key, alphabet),
                    'plaintext': decrypt_with_inverse(cipher, inverse, alphabet)})
    return out


def encrypt_hill(plaintext, key_matrix, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    """c_block = K * p_block (column vectors); pads with alphabet[0]."""
    indices = prepare_ciphertext(normalize_input(plaintext, alphabet), alphabet, len(key_matrix))
    return decrypt_with_inverse(indices, key_matrix, alphabet)


# --- KNOWN-PLAINTEXT ATTACK ------------------------------------------------

def known_plaintext_candidates(ciphertext, crib, matrix_size, position=None, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    """Keys consistent with ``crib`` at ``position`` (0-indexed; None = try
    every position). A crib covering k whole blocks gives k equations; the key
    is solved from ``matrix_size`` blocks whose plaintext matrix is invertible
    and must reproduce every other crib block too. Returns dicts sorted by
    (blocks confirmed, fitness), best first."""
    from annealing import Fitness
    modulus = len(alphabet)
    cipher_text = normalize_input(ciphertext, alphabet)
    crib = normalize_input(crib, alphabet)
    n = matrix_size
    fitness = Fitness(load_ngram_scores(DEFAULT_NGRAM_PATH), 0.5)
    positions = [position] if position is not None else range(0, len(cipher_text) - len(crib) + 1)
    found = {}
    for start in positions:
        first = -(-start // n) * n                       # first block boundary inside the crib
        blocks = []
        for block_start in range(first, start + len(crib) - n + 1, n):
            p = [alphabet.index(ch) for ch in crib[block_start - start:block_start - start + n]]
            c = [alphabet.index(ch) for ch in cipher_text[block_start:block_start + n]]
            if len(c) == n:
                blocks.append((p, c))
        if len(blocks) < n:
            continue
        for chosen in itertools.combinations(range(len(blocks)), n):
            p_matrix = [[blocks[j][0][row] for j in chosen] for row in range(n)]
            p_inverse = modular_inverse(p_matrix, modulus)
            if p_inverse is None:
                continue
            c_matrix = [[blocks[j][1][row] for j in chosen] for row in range(n)]
            key = multiply_mod(c_matrix, p_inverse, modulus)
            if not is_valid_key_matrix(key, modulus):
                continue
            confirmed = sum(1 for p, c in blocks
                            if [sum(key[r][k] * p[k] for k in range(n)) % modulus for r in range(n)] == c)
            if confirmed < len(blocks):
                continue                                 # contradicts another crib block
            rep = matrix_to_key(key, alphabet)
            if rep not in found:
                plaintext = decrypt_hill(cipher_text, key, alphabet)
                found[rep] = {'key_matrix': key, 'key_rep': rep, 'position': start, 'blocks': len(blocks),
                              'plaintext': plaintext, 'fitness': fitness(bytes(alphabet.index(ch) for ch in plaintext))}
            break
    return sorted(found.values(), key=lambda r: (-r['blocks'], -r['fitness']))


def crib_is_usable(crib, n, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    """True if, in some alignment, n of the crib's whole blocks form an invertible matrix."""
    crib = normalize_input(crib, alphabet)
    for offset in range(n):
        blocks = [[alphabet.index(ch) for ch in crib[i:i + n]] for i in range(offset, len(crib) - n + 1, n)]
        for chosen in itertools.combinations(blocks, n):
            if modular_inverse([[block[row] for block in chosen] for row in range(n)], len(alphabet)) is not None:
                return True
    return False


def known_plaintext_attack_hill(full_ciphertext, alphabet):
    """Interactive known-plaintext attack (2x2 or 3x3, crib position known or not)."""
    print(f"\n{BLUE}--- Hill Cipher Known-Plaintext Attack ---{RESET}")
    size_input = input(f"Matrix size (2 or 3, Enter = 2): ").strip()
    n = 3 if size_input == "3" else 2
    crib = normalize_input(input(f"{GREY}Known plaintext (a crib of at least {n * n + n} letters is safest): {RESET}").upper(),
                           alphabet)
    if len(crib) < n * n:
        print(f"{RED}Need at least {n * n} letters of known plaintext for a {n}x{n} key.{RESET}")
        return
    where = input("Its position in the plaintext, 1-indexed (Enter = unknown: try every position): ").strip()
    position = int(where) - 1 if where.isdigit() and int(where) >= 1 else None
    results = known_plaintext_candidates(full_ciphertext, crib, n, position, alphabet)
    if not results:
        print(f"{RED}No key is consistent with that crib"
              f"{' at that position' if position is not None else ' at any position'}.{RESET}")
        if not crib_is_usable(crib, n, alphabet):
            print(f"{YELLOW}The crib's own {n}-letter blocks never form an invertible matrix mod {len(alphabet)} "
                  f"(in any of the {n} alignments), so it cannot determine a key: give a longer crib.{RESET}")
        return
    import cipher_profile as cp
    refs = cp.references(len(normalize_input(full_ciphertext, alphabet))) if len(full_ciphertext) >= cp.MIN_LETTERS else None
    print(f"\n{GREEN}{len(results)} consistent key(s){RESET} {GREY}(more confirmed crib blocks and a higher "
          f"fitness are better; a key from exactly {n} blocks is not cross-checked){RESET}")
    for rank, result in enumerate(results[:8], start=1):
        verdict = f" [{cp.judge(result['fitness'], refs)}]" if refs else ""
        print(f"\n{rank}. key {YELLOW}{result['key_rep']}{RESET} matrix {result['key_matrix']}  crib at "
              f"{result['position'] + 1}, {result['blocks']} blocks  fitness {result['fitness']:.1f}{verdict}")
        print(f"   {result['plaintext']}")


def normalize_input(text, alphabet):
    return "".join([c.upper() for c in text if c.upper() in alphabet])

def decrypt_with_specific_key():
    print(f"\n{YELLOW}== Hill Cipher Direct Decryption =={RESET}")
    
    default_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    alphabet_input = input(f"\nEnter custom alphabet (default: A-Z): {RESET}").upper()
    alphabet = ''.join(dict.fromkeys(alphabet_input)) if alphabet_input else default_alphabet
    
    try:
        size_input = input(f"\nEnter matrix size (2 or 3, default is 2): {RESET}")
        matrix_size = int(size_input) if size_input in ['2', '3'] else 2
    except ValueError:
        matrix_size = 2
    
    key_input_method = input(f"\nInput key as (1) matrix elements or (2) text key? (1/2): {RESET}")
    
    matrix = None
    if key_input_method == '1':
        matrix = [[0] * matrix_size for _ in range(matrix_size)]
        for i in range(matrix_size):
            row_input = input(f"Row {i+1} (space-separated): ")
            values = row_input.split()
            if len(values) != matrix_size:
                print(f"{RED}Error: Expected {matrix_size} values.{RESET}")
                return
            matrix[i] = [int(v) for v in values]
    elif key_input_method == '2':
        key_text = input(f"Enter the key text: {RESET}").upper()
        key_text = normalize_input(key_text, alphabet)
        
        required_length = matrix_size * matrix_size
        if len(key_text) < required_length:
            padding_needed = required_length - len(key_text)
            padding = alphabet[:padding_needed]
            key_text += padding
            print(f"{YELLOW}Key was short. Padded with '{padding}' to create full key: {key_text}{RESET}")
            
        matrix = key_to_matrix(key_text, matrix_size, alphabet)
    else:
        print(f"{RED}Invalid option.{RESET}")
        return

    print(f"\n{GREEN}Using key matrix:\n{matrix}{RESET}")
    
    if not is_valid_key_matrix(matrix, len(alphabet)):
        print(f"{RED}Error: This matrix is not invertible in modulo {len(alphabet)}.{RESET}")
        return
    
    ciphertext = input(f"\nEnter the ciphertext to decrypt: {RESET}")
    ciphertext = normalize_input(ciphertext, alphabet)
    
    plaintext = decrypt_hill(ciphertext, matrix, alphabet)
    
    if plaintext:
        print(f"\n{GREEN}Decryption successful:{RESET}")
        print(f"\n{YELLOW}Plaintext:{RESET}\n{plaintext.lower()}")
        ioc = calculate_ioc(plaintext)
        print(f"\n{GREY}Index of Coincidence: {ioc:.6f}{RESET}")
    else:
        print(f"{RED}Decryption failed.{RESET}")

def run():
    banner("Hill Cipher", "Matrix cipher: decrypt, ciphertext-only attack (2x2 and 3x3), known plaintext, encrypt")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    print()
    print(f"  {YELLOW}[1]{RESET} Ciphertext-only attack, 2x2 or 3x3 {GREY}(row by row, in C){RESET}")
    print(f"  {YELLOW}[2]{RESET} Known-plaintext attack {GREY}(a crib, position known or not){RESET}")
    print(f"  {YELLOW}[3]{RESET} Decrypt with a known key")
    print(f"  {YELLOW}[4]{RESET} Encrypt {GREY}(make a test ciphertext){RESET}")
    mode = input(f"Select (Enter = 1): ").strip() or "1"

    if mode == '3':
        decrypt_with_specific_key()
        return
    if mode == '4':
        plaintext = input(f"{GREY}Plaintext: {RESET}")
        key_text = normalize_input(input("Key as letters (4 for 2x2, 9 for 3x3, row by row): ").upper(), alphabet)
        if len(key_text) not in (4, 9):
            print(f"{RED}The key needs 4 or 9 letters.{RESET}")
            return
        size = 2 if len(key_text) == 4 else 3
        key = key_to_matrix(key_text, size, alphabet)
        if not is_valid_key_matrix(key, 26):
            print(f"{RED}That matrix is not invertible mod 26, so the text could not be decrypted.{RESET}")
            return
        print(f"\n{GREEN}{encrypt_hill(plaintext, key)}{RESET}")
        return

    full_ciphertext = input(f"Enter the ciphertext to crack: {RESET}")
    ciphertext = normalize_input(full_ciphertext.upper(), alphabet)
    if len(ciphertext) < 8:
        print(f"{RED}Need more letters.{RESET}")
        return
    if mode == '2':
        known_plaintext_attack_hill(ciphertext, alphabet)
        return
    if mode != '1':
        print(f"{RED}Invalid selection.{RESET}")
        return

    import cipher_profile as cp
    refs = cp.references(len(ciphertext)) if len(ciphertext) >= cp.MIN_LETTERS else None
    size_input = input("Matrix size (2 or 3, Enter = try both): ").strip()
    sizes = [int(size_input)] if size_input in ('2', '3') else [2, 3]
    results = []
    for size in sizes:
        print(f"{GREY}Scoring every {size}x{size} key row ({26 ** size:,}) by letter frequencies, then combining the best...{RESET}")
        started = time.time()
        found = row_attack(ciphertext, size)
        for result in found:
            result['size'] = size
        results += found
        print(f"{GREY}  {size}x{size} done in {time.time() - started:.1f} s{RESET}")
    results.sort(key=lambda r: -r['fitness'])
    print(f"\n{GREEN}--- Best keys ---{RESET} {GREY}(fitness: higher = more English){RESET}")
    for i, result in enumerate(results[:8]):
        verdict = f" [{cp.judge(result['fitness'], refs)}]" if refs else ""
        print(f"{i + 1}. {result['size']}x{result['size']} key {YELLOW}{result['key_rep']}{RESET} "
              f"{result['key_matrix']}  fitness {result['fitness']:.1f}{verdict}")
        print(f"   {result['plaintext']}")
    if results and refs and cp.judge(results[0]['fitness'], refs) != "reads as English":
        print(f"{YELLOW}Not solved. Short texts give each key row few letters to judge; with known plaintext use "
              f"option 2.{RESET}")


def main():
    run()

if __name__ == "__main__":
    main()