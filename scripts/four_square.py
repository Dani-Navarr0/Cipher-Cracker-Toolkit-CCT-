import random
import math
import time
import os
from collections import Counter
from utils.utils import get_input_ciphertexts
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores, score_text

RESET, GREEN, YELLOW, RED, GREY = '\033[0m', '\033[32m', '\033[33m', '\033[31m', '\033[90m'
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
    text = "".join([c.upper() for c in ciphertext if c.upper() in ALPHABET])
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

def run():
    print(f"{GREY}================================{RESET}\n{RED}FOUR-SQUARE SOLVER{RESET}\n{GREY}================================{RESET}")
    ciphers = get_input_ciphertexts()
    if not ciphers: return
    
    print(f"\n  ({YELLOW}1{RESET}) Direct Decryption\n  ({YELLOW}2{RESET}) Simulated Annealing")
    mode = input(">> ").strip()
    
    for cipher in ciphers:
        if mode == '1':
            k1 = input("Enter Key 1 (Top-Right): ")
            k2 = input("Enter Key 2 (Bottom-Left): ")
            print(decrypt_foursquare(cipher, generate_square(k1), generate_square(k2)))
        elif mode == '2':
            config = {}
            t = input(f"Enter starting temperature (default {YELLOW}20.0{RESET}): ")
            config['initial_temp'] = float(t) if t else 20.0
            
            c = input(f"Enter cooling rate (default {YELLOW}0.995{RESET}): ")
            config['cooling_rate'] = float(c) if c else 0.995
            
            s = input(f"Enter steps per temperature (default {YELLOW}1000{RESET}): ")
            config['steps_per_temp'] = int(s) if s else 1000

            run_sa(cipher, load_bigram_frequencies(ngram_path), config)

if __name__ == "__main__":
    run()