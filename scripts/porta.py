from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Dict, Tuple
import time
from functools import lru_cache
import os
import random
import math
from utils.utils import get_input_ciphertexts
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores, score_text

try:
    from scripts.kasiski import analyze_kasiski
except ImportError:
    try:
        from kasiski import analyze_kasiski
    except ImportError:
        analyze_kasiski = None

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

    def save_results_to_file(self, results: List[Dict], filename: str, include_phrases: bool = True):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("Porta Cipher Brute-Force Results\n")
                f.write("=====================================\n\n")
                for result in results:
                    f.write(f"Key: {result['key']}\n")
                    if 'alphabet_used' in result:
                        f.write(f"Alphabet: {result['alphabet_used']}\n")
                    if 'ioc' in result:
                        f.write(f"IoC Score: {result.get('ioc', 0):.4f}\n")
                    if 'bigram_score' in result:
                        f.write(f"N-gram Score: {result.get('bigram_score', 0):.2f}\n")
                    if include_phrases and result.get('is_phrase_match'):
                        f.write(f"Matched Phrases: {', '.join(result.get('matched_phrases', []))}\n")
                    f.write(f"Plaintext: {result['plaintext']}\n")
                    f.write("-" * 20 + "\n")
            print(f"\033[32mResults successfully saved to {filename}\033[0m")
        except IOError as e:
            print(f"\033[31mError saving file: {e}\033[0m")

utils = DummyUtils()

RESET, GREEN, YELLOW, RED, BLUE, CYAN, GREY = '\033[0m', '\033[32m', '\033[33m', '\033[31m', '\033[34m', '\033[36m', '\033[90m'

data_dir = os.path.join(os.path.dirname(__file__), "data")
dictionary_path = os.path.join(data_dir, "words_alpha.txt")
ngram_path = DEFAULT_NGRAM_PATH

@lru_cache(maxsize=None)
def load_bigram_frequencies(file_path: str) -> Dict[str, float]:
    return load_ngram_scores(file_path)

def calculate_bigram_score(text: str, expected_freqs: Dict[str, float]) -> float:
    return score_text(text, expected_freqs)

@lru_cache(maxsize=None)
def get_alphabet(alphabet_str: str):
    alphabet = alphabet_str.upper()
    alphabet_dict = {char: i for i, char in enumerate(alphabet)}
    return alphabet, alphabet_dict

def decrypt_porta(ciphertext: str, key: str, alphabet_str: str) -> str:
    alphabet, alphabet_dict = get_alphabet(alphabet_str)
    alphabet_length = len(alphabet)
    half_len = alphabet_length // 2
    
    key_shifts = [alphabet_dict.get(k, 0) // 2 for k in key.upper() if k in alphabet_dict]
    if not key_shifts: return ciphertext
    
    plaintext = []
    key_index = 0
    for char in ciphertext:
        char_upper = char.upper()
        if char_upper in alphabet_dict:
            char_index = alphabet_dict[char_upper]
            shift = key_shifts[key_index % len(key_shifts)]
            
            if char_index < half_len:
                decrypted_char = alphabet[((char_index + shift) % half_len) + half_len]
            else:
                decrypted_char = alphabet[(char_index - half_len - shift) % half_len]
                
            plaintext.append(decrypted_char.lower())
            key_index += 1
        else:
            plaintext.append(char.lower())
    return ''.join(plaintext)

def load_dictionary(file_path: str, alphabet_str: str, min_length=3, max_length=15, allowed_lengths=None) -> List[str]:
    alphabet, _ = get_alphabet(alphabet_str)
    alphabet_set = set(alphabet)
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            if allowed_lengths:
                return [w.strip().upper() for w in file if set(w.strip().upper()).issubset(alphabet_set) and len(w.strip()) in allowed_lengths]
            return [w.strip().upper() for w in file if set(w.strip().upper()).issubset(alphabet_set) and min_length <= len(w.strip()) <= max_length]
    except FileNotFoundError:
        return []

def contains_all_phrases(text: str, phrases: List[str]) -> bool:
    if not phrases: return False
    return all(p.upper() in text.upper().replace(" ", "") for p in phrases)

def highlight_phrases(text: str, phrases: List[str]) -> str:
    highlighted = text.lower()
    for phrase in phrases:
        phrase_lower = phrase.lower().replace(" ", "")
        highlighted = highlighted.replace(phrase_lower, f"{RED}{phrase_lower}{RESET}")
    return highlighted

def process_batch(args: Tuple) -> List[Dict]:
    word_batch, ciphertext, target_phrases, alphabet_str, expected_freqs, min_ioc, max_ioc = args
    results = []
    for word in word_batch:
        plaintext = decrypt_porta(ciphertext, word, alphabet_str)
        is_phrase_match = contains_all_phrases(plaintext, target_phrases)
        ioc = utils.calculate_ioc(plaintext)
        if is_phrase_match or (min_ioc <= ioc <= max_ioc):
            results.append({
                'key': word, 'plaintext': plaintext, 'ioc': ioc, 
                'bigram_score': calculate_bigram_score(plaintext, expected_freqs),
                'is_phrase_match': is_phrase_match, 'matched_phrases': target_phrases if is_phrase_match else []
            })
    return results

def run_dictionary_attack(ciphertext: str, alphabet_str: str, expected_freqs: Dict, config: Dict):
    target_phrases = config.get('target_phrases', [])
    min_ioc, max_ioc = config.get('min_ioc', 0.065), config.get('max_ioc', 0.070)
    allowed_lengths = config.get('allowed_lengths', None)
    
    if config.get('use_kasiski') and analyze_kasiski:
        print(f"\n{CYAN}Running Kasiski Analysis...{RESET}")
        likely_lengths = analyze_kasiski(ciphertext)
        if likely_lengths:
            allowed_lengths = likely_lengths[:3]
            print(f"{GREEN}Filtering dictionary to words of length: {allowed_lengths}{RESET}")
            
    print(f"{YELLOW}Loading dictionary...{RESET}")
    dictionary = load_dictionary(dictionary_path, alphabet_str, allowed_lengths=allowed_lengths)
    all_results = []
    
    if dictionary:
        word_batches = [dictionary[i:i + 500] for i in range(0, len(dictionary), 500)]
        num_processes = max(1, os.cpu_count() - 1)
        print(f"Processing {YELLOW}{len(dictionary):,}{RESET} words with {YELLOW}{num_processes}{RESET} processes...")
        start_time = time.time()
        with ProcessPoolExecutor(max_workers=num_processes) as executor:
            futures = [executor.submit(process_batch, (b, ciphertext, target_phrases, alphabet_str, expected_freqs, min_ioc, max_ioc)) for b in word_batches]
            for i, future in enumerate(as_completed(futures)):
                all_results.extend(future.result())
                if len(word_batches) > 10: print(f"Progress: {(i + 1) / len(word_batches):.1%}", end='\r')
        print(f"\nSearch complete in {time.time() - start_time:.2f} seconds.{RESET}")
    
    all_results.sort(key=lambda x: (0 if x['is_phrase_match'] else 1, 0 if min_ioc <= x['ioc'] <= max_ioc else 1, x['bigram_score'], -x['ioc']))

    if all_results:
        print(f"\n{YELLOW}--- TOP 5 MATCHES ---{RESET}")
        for i, result in enumerate(all_results[:5]):
            print(f"Rank #{i+1}: Key: {YELLOW}{result['key']}{RESET} | Score: {YELLOW}{result['bigram_score']:.2f}{RESET} | IoC: {YELLOW}{result['ioc']:.4f}{RESET}")
            print(f"Text: {highlight_phrases(result['plaintext'], result['matched_phrases'])[:100]}...\n{GREY}{'-'*30}{RESET}")
    else:
        print(f"{RED}NO SOLUTIONS FOUND.{RESET}")
    return all_results

def run_simulated_annealing(ciphertext: str, alphabet_str: str, expected_freqs: Dict, config: Dict):
    key_length = config.get('key_length', 5)
    iterations = config.get('iterations', 200000)
    temp = config.get('initial_temp', 1000.0)
    cooling_rate = config.get('cooling_rate', 0.99995)
    
    alphabet, _ = get_alphabet(alphabet_str)
    best_key = current_key = "".join(random.choice(alphabet) for _ in range(key_length))
    best_score = current_score = calculate_bigram_score(decrypt_porta(ciphertext, current_key, alphabet_str), expected_freqs)
    
    try:
        for i in range(iterations):
            temp *= cooling_rate
            if temp <= 0.1: break
            
            k_list = list(current_key)
            k_list[random.randint(0, key_length - 1)] = random.choice(alphabet)
            neighbor_key = "".join(k_list)
            
            neighbor_score = calculate_bigram_score(decrypt_porta(ciphertext, neighbor_key, alphabet_str), expected_freqs)
            delta = neighbor_score - current_score
            
            if delta < 0 or random.random() < math.exp(-delta / temp):
                current_key, current_score = neighbor_key, neighbor_score
                if current_score < best_score:
                    best_key, best_score = current_key, current_score
                    print(f"Score: {best_score:8.2f} | Key: {best_key}", end='\r')
    except KeyboardInterrupt:
        pass
    
    best_plaintext = decrypt_porta(ciphertext, best_key, alphabet_str).upper()
    best_ioc = utils.calculate_ioc(best_plaintext)
    
    print(f"\nFinal Best Key: {YELLOW}{best_key}{RESET}")
    print(f"N-gram Score: {YELLOW}{best_score:.2f}{RESET}")
    print(f"IoC: {YELLOW}{best_ioc:.4f}{RESET}")
    print(f"Text: {best_plaintext}\n")
    
    return [{'key': best_key, 'plaintext': best_plaintext, 'bigram_score': best_score, 'ioc': best_ioc}]

def run():
    print(f"{GREY}================================{RESET}\n{RED}PORTA SOLVER{RESET}\n{GREY}================================{RESET}")
    ciphertexts = get_input_ciphertexts(prompt="Enter ciphertext")
    if not ciphertexts: return
    expected_freqs = load_bigram_frequencies(ngram_path)
    
    while True:
        print(f"\n{GREY}Select Action:{RESET}")
        print(f"  ({YELLOW}1{RESET}) Direct Decryption (Known Key)")
        print(f"  ({YELLOW}2{RESET}) Dictionary Attack")
        print(f"  ({YELLOW}3{RESET}) Simulated Annealing")
        print(f"  ({YELLOW}Q{RESET}) Quit")
        mode = input(">> ").strip().upper()
        if mode == 'Q': break
        
        config = {}
        if mode == '1': config['key'] = input("Enter key: ").upper().strip()
        elif mode == '2':
            config['use_kasiski'] = input(f"Auto-detect length with Kasiski? ({YELLOW}Y/N{RESET}): ").upper() == 'Y'
        elif mode == '3':
            config['key_length'] = int(input("Enter exact key length: "))
            iters = input(f"Enter iterations (default: {YELLOW}200000{RESET}): ")
            config['iterations'] = int(iters) if iters else 200000
            
            t = input(f"Enter initial temperature (default: {YELLOW}1000.0{RESET}): ")
            config['initial_temp'] = float(t) if t else 1000.0
            
            c = input(f"Enter cooling rate (default: {YELLOW}0.99995{RESET}): ")
            config['cooling_rate'] = float(c) if c else 0.99995
            
        for i, cipher in enumerate(ciphertexts):
            print(f"\n{CYAN}Processing Input #{i+1}{RESET}")
            if mode == '1':
                pt = decrypt_porta(cipher, config['key'], "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                print(f"Plaintext: {pt}")
            elif mode == '2':
                run_dictionary_attack(cipher, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", expected_freqs, config)
            elif mode == '3':
                run_simulated_annealing(cipher, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", expected_freqs, config)

if __name__ == "__main__":
    run()