import os
import numpy as np
import itertools
import time
import sys
from functools import lru_cache
from typing import List, Dict
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores, score_text

# --- DUMMY UTILS CLASS (to make script standalone) ---
class DummyUtils:
    def calculate_ioc(self, text: str) -> float:
        text = text.upper()
        text = ''.join(filter(str.isalpha, text))
        n = len(text)
        if n < 2: return 0.0
        freqs = {}
        for char in text:
            freqs[char] = freqs.get(char, 0) + 1
        numerator = sum(count * (count - 1) for count in freqs.values())
        denominator = n * (n - 1)
        return numerator / denominator if denominator > 0 else 0.0

    def save_to_file_hill(self, results: List[Dict], filename: str):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("Hill Cipher Brute-Force Results\n")
                f.write("=================================\n\n")
                for result in results:
                    f.write(f"Key Representation: {result['key_rep']}\n")
                    f.write("Key Matrix:\n")
                    for row in result['matrix']:
                        f.write(f"  {row}\n")
                    f.write(f"IoC Score: {result.get('ioc', 0):.4f}\n")
                    f.write(f"N-gram Score: {result.get('bigram_score', 0):.2f}\n")
                    f.write(f"Decrypted: {result['plaintext']}\n")
                    f.write("-" * 20 + "\n")
            print(f"{GREEN}Results successfully saved to {filename}{RESET}")
        except IOError as e:
            print(f"{RED}Error saving file: {e}{RESET}")

utils = DummyUtils()

# --- COLOR CODES AND PATHS ---
RED = '\033[38;5;88m'
YELLOW = '\033[38;5;3m'
GREY = '\033[38;5;238m'
RESET = '\033[0m'
GREEN = '\033[38;5;2m'
BLUE = '\033[38;5;4m'

data_dir = os.path.join(os.path.dirname(__file__), "data")
ngram_path = DEFAULT_NGRAM_PATH

# --- SCORING FUNCTIONS ---
@lru_cache(maxsize=None)
def load_bigram_frequencies(file_path: str) -> Dict[str, float]:
    return load_ngram_scores(file_path)

def calculate_bigram_score(text: str, expected_freqs: Dict[str, float]) -> float:
    return score_text(text, expected_freqs)

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
    return np.array(key_indices).reshape(matrix_size, matrix_size)

def modular_inverse(matrix, modulus):
    """
    Calculates the modular inverse of a matrix using the Adjugate Matrix method.
    This logic is based on the provided PDF for mathematical accuracy. 
    """
    det = int(round(np.linalg.det(matrix)))
    det = det % modulus
    
    try:
        det_inv = pow(det, -1, modulus)
    except ValueError:
        return None # Determinant is not invertible, no inverse exists. [cite: 358, 359, 360]

    n = matrix.shape[0]
    cofactors = np.zeros(matrix.shape)
    for r in range(n):
        for c in range(n):
            minor = np.delete(np.delete(matrix, r, axis=0), c, axis=1)
            cofactors[r, c] = ((-1)**(r + c)) * int(round(np.linalg.det(minor)))
    
    adjugate = cofactors.T
    inv_matrix = (det_inv * adjugate) % modulus
    return inv_matrix.astype(int)

def decrypt_hill(ciphertext, key_matrix, alphabet):
    """
    Decrypts Hill cipher using the correct column vector method. [cite: 332, 342]
    """
    matrix_size = key_matrix.shape[0]
    modulus = len(alphabet)
    inverse_matrix = modular_inverse(key_matrix, modulus)
    if inverse_matrix is None: return None
    
    plaintext = ""
    filtered_ciphertext = [c for c in ciphertext if c in alphabet]
    while len(filtered_ciphertext) % matrix_size != 0:
        filtered_ciphertext.append(alphabet[0])
        
    for i in range(0, len(filtered_ciphertext), matrix_size):
        chunk = filtered_ciphertext[i:i+matrix_size]
        chunk_vector = np.array([alphabet.index(c) for c in chunk])
        decrypted_vector = np.dot(inverse_matrix, chunk_vector) % modulus
        for idx in decrypted_vector:
            plaintext += alphabet[int(idx)]
    return plaintext

def highlight_phrases(text: str, phrases: list) -> str:
    highlighted_text = text.lower()
    if not phrases: return highlighted_text
    for phrase in phrases:
        phrase_lower = phrase.lower().replace(" ", "")
        highlighted_text = highlighted_text.replace(phrase_lower, f"{RED}{phrase_lower}{RESET}")
    return highlighted_text

def contains_fragment(plaintext, fragment):
    return fragment.lower().replace(" ", "") in plaintext.lower().replace(" ", "")

def is_valid_key_matrix(matrix, modulus):
    det = int(round(np.linalg.det(matrix))) % modulus
    return det != 0 and np.gcd(det, modulus) == 1

def generate_all_possible_matrices(matrix_size, alphabet_length):
    value_range = range(alphabet_length)
    for values in itertools.product(value_range, repeat=matrix_size*matrix_size):
        matrix = np.array(values).reshape(matrix_size, matrix_size)
        if is_valid_key_matrix(matrix, alphabet_length):
            yield matrix

def brute_force_hill_all_keys(ciphertext, alphabet, matrix_size, min_ioc, max_ioc,
                              known_fragments, max_results, expected_freqs):
    results = []
    
    print(f"\n{YELLOW}Starting brute force with all possible {matrix_size}x{matrix_size} matrices...{RESET}")
    print(f"{GREY}This may take a very long time. Filtering for valid (invertible) matrices...{RESET}")
    
    start_time = time.time()
    last_update_time = start_time
    matrices_checked = 0

    for matrix in generate_all_possible_matrices(matrix_size, len(alphabet)):
        matrices_checked += 1
        
        current_time = time.time()
        if current_time - last_update_time >= 2:
            elapsed_time = current_time - start_time
            print(f"{GREY}Matrices tested: {matrices_checked:,} | Time: {elapsed_time:.1f}s | Matches: {len(results)}{RESET}", end='\r')
            last_update_time = current_time

        plaintext = decrypt_hill(ciphertext, matrix, alphabet)
        if not plaintext: continue
        
        is_fragment_match = any(contains_fragment(plaintext, f) for f in known_fragments) if known_fragments else False
        ioc = utils.calculate_ioc(plaintext)
        is_ioc_match = min_ioc <= ioc <= max_ioc
        
        if is_fragment_match or is_ioc_match:
            bigram_score = calculate_bigram_score(plaintext, expected_freqs)
            results.append({
                'key_rep': matrix_to_key(matrix, alphabet), 'matrix': matrix, 'plaintext': plaintext,
                'ioc': ioc, 'bigram_score': bigram_score, 'is_fragment_match': is_fragment_match,
                'matched_fragments': [f for f in known_fragments if contains_fragment(plaintext, f)] if is_fragment_match else []
            })

        if len(results) >= max_results:
            print(f"\n{YELLOW}Maximum number of results ({max_results}) reached. Stopping search.{RESET}")
            break

    print(f"\n\n{GREY}Completed! {matrices_checked:,} valid matrices tested.{RESET}")
    
    results.sort(key=lambda x: (
        0 if x['is_fragment_match'] else 1, 0 if min_ioc <= x['ioc'] <= max_ioc else 1,
        x['bigram_score'], -x['ioc']
    ))
    return results

def known_plaintext_attack_hill(full_ciphertext, alphabet):
    print(f"\n{BLUE}--- Hill Cipher 3x3 Known-Plaintext Attack ---{RESET}")
    modulus = len(alphabet)

    try:
        plain_input = input(f"{GREY}Enter exactly 9 characters of known plaintext: {RESET}").upper()
        plain_input = normalize_input(plain_input, alphabet)
        if len(plain_input) != 9:
            print(f"{RED}Error: You must provide exactly 9 alphabet characters.{RESET}")
            return

        cipher_input = input(f"{GREY}Enter the corresponding 9 characters of ciphertext: {RESET}").upper()
        cipher_input = normalize_input(cipher_input, alphabet)
        if len(cipher_input) != 9:
            print(f"{RED}Error: You must provide exactly 9 alphabet characters.{RESET}")
            return
    except (KeyboardInterrupt, EOFError):
        print(f"\n{RED}Input cancelled.{RESET}")
        return

    p_indices = [alphabet.index(c) for c in plain_input]
    c_indices = [alphabet.index(c) for c in cipher_input]
    
    p_matrix = np.array(p_indices).reshape(3, 3, order='F')
    c_matrix = np.array(c_indices).reshape(3, 3, order='F')

    print(f"\n{GREY}Plaintext Matrix (P):\n{p_matrix}{RESET}")
    
    p_inverse = modular_inverse(p_matrix, modulus)
    
    if p_inverse is None:
        print(f"{RED}Error: The provided plaintext segment forms a non-invertible matrix.{RESET}")
        print(f"{YELLOW}Please try a different 9-character segment of known plaintext.{RESET}")
        return

    key_matrix = np.dot(c_matrix, p_inverse) % modulus
    
    print(f"\n{GREEN}Success! Key matrix found:{RESET}")
    for row in key_matrix:
        print(f"  {row}")

    key_rep = matrix_to_key(key_matrix, alphabet)
    print(f"\n{GREEN}Key Representation:{RESET} {YELLOW}{key_rep}{RESET}")

    if input(f"\n{GREY}Decrypt the full ciphertext with this key to verify? (y/n): {RESET}").lower() == 'y':
        plaintext = decrypt_hill(full_ciphertext, key_matrix, alphabet)
        print(f"\n{YELLOW}--- Full Decryption ---{RESET}")
        print(plaintext.lower())

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
        matrix = np.zeros((matrix_size, matrix_size), dtype=int)
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
        ioc = utils.calculate_ioc(plaintext)
        print(f"\n{GREY}Index of Coincidence: {ioc:.6f}{RESET}")
    else:
        print(f"{RED}Decryption failed.{RESET}")

def run():
    print(f"{GREEN}==============={RESET}")
    print(f"{GREEN}= Hill Cipher ={RESET}")
    print(f"{GREEN}==============={RESET}")
    
    print(f"\n{YELLOW}Select mode:{RESET}")
    print(f"1. Direct decryption with a known key")
    print(f"2. Brute force / Known-plaintext attack")
    mode = input(f"\n{GREY}Enter your choice (1-2): {RESET}")
    
    if mode == '1':
        decrypt_with_specific_key()
        return
    
    elif mode == '2':
        default_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        alphabet_input = input(f"\nEnter custom alphabet (default: A-Z): {RESET}").upper()
        alphabet = ''.join(dict.fromkeys(alphabet_input)) if alphabet_input else default_alphabet

        size_input = input(f"Enter matrix size (2 or 3, default is 2): {RESET}")
        matrix_size = int(size_input) if size_input in ['2', '3'] else 2

        full_ciphertext = input(f"Enter the full ciphertext to crack: {RESET}")
        ciphertext = normalize_input(full_ciphertext, alphabet)

        if matrix_size == 3:
            print(f"\n{YELLOW}Note: A 3x3 brute-force is computationally infeasible.{RESET}")
            if input(f"{GREY}Proceed with a known-plaintext attack instead? (y/n): {RESET}").lower() == 'y':
                known_plaintext_attack_hill(full_ciphertext, alphabet)
                return
            else:
                print(f"{RED}3x3 brute-force cancelled. Exiting.{RESET}")
                return

        fragments_input = input(f"Enter known plaintext fragments (comma-separated): {RESET}")
        known_fragments = [f.strip() for f in fragments_input.split(',')] if fragments_input else []
        
        if input(f"Use IoC filtering? (y/n, default y): {RESET}").lower() != 'n':
            min_ioc_str = input(f"Enter min IoC (default: 0.060): {RESET}") or "0.060"
            max_ioc_str = input(f"Enter max IoC (default: 0.075): {RESET}") or "0.075"
            min_ioc, max_ioc = float(min_ioc_str), float(max_ioc_str)
        else:
            print(f"{YELLOW}IoC filtering disabled.{RESET}")
            min_ioc, max_ioc = 0.0, 1.0
        
        max_results_input = input(f"Max results to find ('all' or number, default: 100): {RESET}") or "100"
        try:
            if max_results_input.lower() == 'all':
                max_results = sys.maxsize
                print(f"{YELLOW}Searching for all possible solutions.{RESET}")
            else:
                max_results = int(max_results_input)
        except ValueError:
            print(f"{RED}Invalid input. Defaulting to 100 results.{RESET}")
            max_results = 100

        expected_freqs = load_bigram_frequencies(ngram_path)
        if not expected_freqs:
            print(f"{RED}Warning: Bigram file not found. Scores will be less accurate.{RESET}")

        results = brute_force_hill_all_keys(
            ciphertext, alphabet, matrix_size, min_ioc, max_ioc, 
            known_fragments, max_results, expected_freqs
        )

        if results:
            print(f"\n{GREEN}--- TOP 10 RANKED SOLUTIONS ---{RESET}")
            print(f"{GREY}Ranked by: 1. Fragment Match, 2. IoC in Range, 3. N-gram Score, 4. IoC Score{RESET}")
            for i, result in enumerate(results[:10]):
                is_in_range = min_ioc <= result['ioc'] <= max_ioc
                range_marker = GREEN + " (In Range)" + RESET if is_in_range else ""
                fragment_marker = YELLOW + " (Fragment Match)" + RESET if result['is_fragment_match'] else ""
                highlighted = highlight_phrases(result['plaintext'], result.get('matched_fragments', []))
                
                print(f"{GREY}-{RESET}" * 50)
                print(f"Rank #{i+1}: Key: {YELLOW}{result['key_rep']}{RESET}{fragment_marker}")
                print(f"Matrix: {result['matrix'].flatten().tolist()}")
                print(f"Scores: IoC: {YELLOW}{result['ioc']:.4f}{RESET}{range_marker} | N-gram: {YELLOW}{result['bigram_score']:.2f}{RESET} (Lower is better)")
                print(f"Plaintext: {highlighted}")
            
            if input(f"\nSave all {len(results)} results to a file? (y/n): {RESET}").lower() == 'y':
                filename = input("Enter filename: ") or "hill_results.txt"
                utils.save_to_file_hill(results, filename)
        else:
            print(f"\n{RED}No matches found within the specified criteria.{RESET}")

def main():
    run()

if __name__ == "__main__":
    main()