from typing import List, Dict
from functools import lru_cache
import os
from utils.utils import get_input_ciphertexts
import attack_support
from annealing import Schedule
from periodic_solver import CANNOT_START, solve_periodic
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
            print(f"{GREEN}Results successfully saved to {filename}{RESET}")
        except IOError as e:
            print(f"{RED}Error saving file: {e}{RESET}")

utils = DummyUtils()

from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

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

load_dictionary = attack_support.load_dictionary
contains_all_phrases = attack_support.contains_all_phrases

def highlight_phrases(text: str, phrases: List[str]) -> str:
    highlighted = text.lower()
    for phrase in phrases:
        phrase_lower = phrase.lower().replace(" ", "")
        highlighted = highlighted.replace(phrase_lower, f"{RED}{phrase_lower}{RESET}")
    return highlighted

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
        all_results.extend(attack_support.run_batches(
            decrypt_porta, dictionary, ciphertext, alphabet_str, target_phrases, expected_freqs, min_ioc, max_ioc
        ))

    attack_support.sort_results(all_results)

    if all_results:
        print(f"\n{YELLOW}--- TOP 5 MATCHES ---{RESET}")
        for i, result in enumerate(all_results[:5]):
            print(f"Rank #{i+1}: Key: {YELLOW}{result['key']}{RESET} | Score: {YELLOW}{result['bigram_score']:.2f}{RESET} | IoC: {YELLOW}{result['ioc']:.4f}{RESET}")
            print(f"Text: {highlight_phrases(result['plaintext'], result['matched_phrases'])[:100]}...\n{GREY}{'-'*30}{RESET}")
    else:
        print(f"{RED}NO SOLUTIONS FOUND.{RESET}")
    return all_results

def porta_rule(c: int, k: int, m: int) -> int:
    """Porta decryption for alphabet indices (same maths as decrypt_porta)."""
    half, shift = m // 2, k // 2
    return ((c + shift) % half) + half if c < half else (c - half - shift) % half


# The dictionary attack runs decrypt_porta's rule in C (attack_support).
attack_support.register_kernel(decrypt_porta, porta_rule)


def run_simulated_annealing(ciphertext: str, alphabet_str: str, expected_freqs: Dict, config: Dict):
    """Anneal the key with the shared engine (geometric 20 -> 0.1 schedule)."""
    key_length = config.get('key_length', 5)
    iterations = config.get('iterations', 200000)
    restarts = config.get('restarts', 3)

    alphabet, _ = get_alphabet(alphabet_str)
    results = solve_periodic(ciphertext, alphabet, alphabet, key_length, porta_rule,
                             expected_freqs, Schedule(iterations), restarts=restarts)
    if results is None:
        print(f"{RED}{CANNOT_START}{RESET}")
        return []
    best_key = results[0][0]
    best_plaintext = decrypt_porta(ciphertext, best_key, alphabet_str).upper()
    best_score = calculate_bigram_score(best_plaintext, expected_freqs)
    best_ioc = utils.calculate_ioc(best_plaintext)

    print(f"\nFinal Best Key: {YELLOW}{best_key}{RESET} {GREY}(Porta key letters work in pairs: A=B, C=D, ...){RESET}")
    print(f"N-gram Score: {YELLOW}{best_score:.2f}{RESET} (lower is better)")
    print(f"IoC: {YELLOW}{best_ioc:.4f}{RESET}")
    print(f"Text: {best_plaintext}\n")

    return [{'key': best_key, 'plaintext': best_plaintext, 'bigram_score': best_score, 'ioc': best_ioc}]

def run():
    banner("Porta Cipher", "Reciprocal cipher with 13 alphabets")
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
            try:
                config['key_length'] = int(input("Enter exact key length: "))
                iters = input(f"Enter iterations (default: {YELLOW}200000{RESET}): ")
                config['iterations'] = int(iters) if iters else 200000
            except ValueError:
                print(f"{RED}Not a number.{RESET}")
                return
            # The shared engine cools from 20 to 0.1 (scripts/annealing.py); the old
            # temperature and cooling-rate prompts were never used, so they are gone.
            
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