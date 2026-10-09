from concurrent.futures import ProcessPoolExecutor, as_completed
import os
from typing import List, Tuple, Dict
import numpy as np
from functools import lru_cache
import itertools
import time
import random
from collections import Counter
from ngram_scoring import DEFAULT_NGRAM_PATH, DEFAULT_NGRAM_SIZE, load_ngram_scores, resolve_ngram_path, score_text

# --- DUMMY UTILS CLASS ---
class DummyUtils:
    def calculate_ioc(self, text: str) -> float:
        text = ''.join(filter(str.isalpha, text.upper()))
        n = len(text)
        if n < 2: return 0.0
        freqs = Counter(text)
        numerator = sum(count * (count - 1) for count in freqs.values())
        denominator = n * (n - 1)
        return numerator / denominator if denominator > 0 else 0.0

    def save_results_to_file(self, results: List[Dict], filename: str):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("Gromark Cipher Brute-Force Results\n")
                f.write("===================================\n\n")
                for result in results:
                    f.write(f"Keyword: {result['keyword']}\n")
                    f.write(f"Primer: {result['primer']}\n")
                    f.write(f"Alphabet: {result.get('alphabet', '')}\n")
                    f.write(f"IoC Score: {result.get('ioc', 0):.4f}\n")
                    if 'score' in result:
                        f.write(f"Fitness Score: {result.get('score', 0):.2f}\n")
                    elif 'bigram_score' in result:
                        f.write(f"N-gram Score: {result.get('bigram_score', 0):.2f}\n")
                    f.write(f"Decrypted: {result.get('decrypted', result.get('text', ''))}\n")
                    f.write("-" * 20 + "\n")
            print(f"{GREEN}Results successfully saved to {filename}{RESET}")
        except IOError as e:
            print(f"{RED}Error saving file: {e}{RESET}")

    def analyze_frequency_vg(self, text: str):
        print("\n--- Frequency Analysis ---")
        text = ''.join(filter(str.isalpha, text.upper()))
        total = len(text)
        if total == 0: return
        freqs = Counter(text)
        sorted_freqs = sorted(freqs.items(), key=lambda item: item[1], reverse=True)
        print("Character Frequencies:")
        for char, count in sorted_freqs:
            print(f"{char}: {count:<4} ({(count / total) * 100:.2f}%)")
        print("-" * 25)

utils = DummyUtils()

# --- COLOR CODES AND PATHS ---
RED, YELLOW, GREY, GREEN, BLUE, RESET = '\033[38;5;88m', '\033[38;5;3m', '\033[38;5;238m', '\033[38;5;2m', '\033[38;5;21m', '\033[0m'
try: data_dir = os.path.join(os.path.dirname(__file__), "data")
except NameError: data_dir = "data"

dictionary_path = os.path.join(data_dir, "words_alpha.txt")
ngram_path = DEFAULT_NGRAM_PATH

# --- SCORING FUNCTIONS ---
@lru_cache(maxsize=None)
def load_ngram_frequencies(file_path: str) -> Dict[str, float]:
    return load_ngram_scores(file_path)

def calculate_ngram_score(text: str, expected_freqs: Dict[str, float], n: int) -> float:
    return score_text(text, expected_freqs)

# --- DYNAMIC FITNESS ENGINE FACTORY ---
def get_fitness_evaluator(config: Dict, expected_freqs: Dict):
    scoring_mode = config.get('scoring_mode', '3')
    ngram_size = config.get('ngram_size', DEFAULT_NGRAM_SIZE)
    target_min_ioc = config.get('min_ioc', 0.060)
    target_max_ioc = config.get('max_ioc', 0.070)

    def get_ioc_penalty(text_ioc: float) -> float:
        if target_min_ioc <= text_ioc <= target_max_ioc: return 0.0
        elif text_ioc < target_min_ioc: return target_min_ioc - text_ioc
        else: return text_ioc - target_max_ioc

    def evaluate_fitness(text: str) -> float:
        if scoring_mode == '1': 
            return calculate_ngram_score(text, expected_freqs, ngram_size)
            
        text_ioc = utils.calculate_ioc(text)
        ioc_penalty = get_ioc_penalty(text_ioc)

        if scoring_mode == '2': 
            return ioc_penalty * 1000 
        else: 
            ngram_score = calculate_ngram_score(text, expected_freqs, ngram_size)
            return ngram_score * (1.0 + (ioc_penalty * 50))
            
    return evaluate_fitness

# --- GROMARK CORE FUNCTIONS ---
def create_keyed_alphabet(keyword: str, alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ") -> str:
    keyword = ''.join(dict.fromkeys(keyword.upper()))
    remaining = ''.join(c for c in alphabet if c not in keyword)
    base = keyword + remaining
    cols = len(keyword)
    if cols == 0: return alphabet
    rows = (len(base) + cols - 1) // cols
    block = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for i in range(rows):
        for j in range(cols):
            if idx < len(base):
                block[i][j] = base[idx]
                idx += 1
    sorted_keyword_with_indices = sorted([(char, i) for i, char in enumerate(keyword)])
    final_col_order = [i for char, i in sorted_keyword_with_indices]
    return ''.join(block[row][col] for col in final_col_order for row in range(rows) if row < len(block) and col < len(block[row]) and block[row][col])

def generate_running_key(primer: str, length: int) -> str:
    key = np.array([int(d) for d in primer if d.isdigit()], dtype=np.int8)
    if len(key) != 5: return "" 
    result = np.zeros(length, dtype=np.int8)
    result[:len(key)] = key
    for i in range(len(key), length): result[i] = (result[i-5] + result[i-4]) % 10
    return ''.join(map(str, result))

def decrypt_gromark(ciphertext: str, mixed_alphabet: str, running_key: str, alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ") -> str:
    result = []
    len_alpha = len(alphabet)
    for i, char in enumerate(ciphertext):
        if char in mixed_alphabet and i < len(running_key):
            mixed_pos = mixed_alphabet.find(char)
            if mixed_pos == -1:
                result.append(char.lower())
                continue
            straight_letter = alphabet[mixed_pos]
            shift = int(running_key[i])
            orig_pos = (alphabet.find(straight_letter) - shift) % len_alpha
            result.append(alphabet[orig_pos].lower())
        else:
            result.append(char.lower())
    return ''.join(result)

def batch_primers(start: int = 10000, end: int = 99999, batch_size: int = 1000) -> List[List[int]]:
    all_primers = list(range(start, end + 1))
    return [all_primers[i:i + batch_size] for i in range(0, len(all_primers), batch_size)]

def can_form_word(word: str, text: str) -> bool:
    word = word.upper()
    text = text.upper()
    it = iter(text)
    return all(c in it for c in word)

# --- EXHAUSTIVE AND DICTIONARY ATTACK HELPER FUNCTIONS ---
def try_decrypt_batch(args: Tuple) -> List[Dict]:
    keyword, primers, ciphertext, required_words, alphabet, expected_freqs = args
    results = []
    mixed_alphabet = create_keyed_alphabet(keyword, alphabet)
    for primer in primers:
        try:
            primer_str = str(primer)
            running_key = generate_running_key(primer_str, len(ciphertext))
            decrypted = decrypt_gromark(ciphertext, mixed_alphabet, running_key, alphabet)
            
            match_type = None
            if not required_words: continue
            
            if all(word in decrypted.upper() for word in required_words): match_type = 'substring'
            elif all(can_form_word(word, decrypted) for word in required_words): match_type = 'dragged'

            if match_type:
                ioc = utils.calculate_ioc(decrypted)
                bigram_score = calculate_ngram_score(decrypted, expected_freqs, 2)
                results.append({
                    'keyword': keyword, 'primer': primer_str, 'decrypted': decrypted,
                    'alphabet': alphabet, 'ioc': ioc, 'bigram_score': bigram_score, 'match_type': match_type
                })
        except Exception: continue
    return results

def validate_keyword(keyword: str, known_segments: List[Tuple], alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ") -> bool:
    try:
        mixed_alphabet = create_keyed_alphabet(keyword, alphabet)
        for _, cipher_segment, plain_segment in known_segments:
            for c, p in zip(cipher_segment, plain_segment):
                mixed_pos = mixed_alphabet.find(c)
                if mixed_pos == -1: return False
                straight_letter = alphabet[mixed_pos]
                plain_pos = alphabet.find(p.upper())
                straight_pos = alphabet.find(straight_letter)
                if (straight_pos - plain_pos) % len(alphabet) > 9: return False
        return True
    except Exception: return False

def parallel_process_keywords(keywords_list: List[str], ciphertext: str, required_words: List[str], alphabet: str, expected_freqs: Dict, batch_size: int = 1000) -> List[Dict]:
    all_results = []
    num_processes = max(1, os.cpu_count() - 1)
    primer_batches = batch_primers(batch_size=batch_size)
    total_batches = len(keywords_list) * len(primer_batches)
    processed_batches = 0

    if total_batches == 0: return []
    print(f"Processing {YELLOW}{len(keywords_list):,}{RESET} keywords across {YELLOW}{len(primer_batches)}{RESET} primer batches using {YELLOW}{num_processes}{RESET} processes.")

    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = [executor.submit(try_decrypt_batch, (keyword, batch, ciphertext, required_words, alphabet, expected_freqs)) for keyword in keywords_list for batch in primer_batches]
        for future in as_completed(futures):
            try: all_results.extend(future.result())
            except Exception: pass
            finally:
                processed_batches += 1
                print(f"Progress: {processed_batches}/{total_batches} batches ({(processed_batches / total_batches) * 100:.1f}%)", end='\r')
    print("\n")
    return all_results

def get_alphabets_from_user() -> List[str]:
    alphabets = ["ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    print(f"\n{YELLOW}Enter additional alphabets to test (one per line).{RESET}")
    print(f"{GREY}Press Enter on an empty line when done. Default is '{alphabets[0]}'.{RESET}")
    while True:
        alphabet_input = input(f"Additional alphabet #{len(alphabets)}: ").upper().strip()
        if not alphabet_input: break
        alphabets.append(''.join(dict.fromkeys(alphabet_input)))
    return alphabets

def highlight_phrases(text: str, phrases: List[str], color: str = RED) -> str:
    highlighted_text = text
    for phrase in phrases:
        parts = highlighted_text.split(phrase.lower())
        highlighted_text = (f"{color}{phrase.lower()}{RESET}").join(parts)
    return highlighted_text

def highlight_dragged_crib(text: str, crib: str, color: str = BLUE) -> str:
    text_lower = text.lower()
    crib_lower = crib.lower()
    if not can_form_word(crib_lower, text_lower): return text
    result_chars = list(text)
    text_iter = iter(enumerate(text_lower))
    try:
        for crib_char in crib_lower:
            while True:
                index, text_char = next(text_iter)
                if text_char == crib_char:
                    result_chars[index] = f"{color}{text[index]}{RESET}"
                    break
    except StopIteration: pass
    return "".join(result_chars)

def process_and_display_results(all_results, required_words):
    if not all_results:
        print(f"\n{RED}NO SOLUTIONS FOUND{RESET}")
        return

    min_ioc = float(input(f"Enter minimum IoC for ranking (default: {YELLOW}0.060{RESET}): ") or "0.060")
    max_ioc = float(input(f"Enter maximum IoC for ranking (default: {YELLOW}0.075{RESET}): ") or "0.075")

    all_results.sort(key=lambda x: (0 if min_ioc <= x['ioc'] <= max_ioc else 1, x['bigram_score'], -x['ioc']))

    print(f"\n{YELLOW}--- RANKED SOLUTIONS FOUND ---{RESET}")
    for result in all_results[:20]:
        in_range = min_ioc <= result['ioc'] <= max_ioc
        range_marker = GREEN + " (In Range)" + RESET if in_range else ""
        match_type = result.get('match_type')
        
        if match_type == 'substring':
            highlighted_decrypted = highlight_phrases(result['decrypted'], required_words, RED)
            match_marker = f"{RED}(Substring Match){RESET}"
        elif match_type == 'dragged':
            temp_decrypted = result['decrypted']
            for word in required_words: temp_decrypted = highlight_dragged_crib(temp_decrypted, word, BLUE)
            highlighted_decrypted = temp_decrypted
            match_marker = f"{BLUE}(Dragged Match){RESET}"
        else:
            highlighted_decrypted = result['decrypted']
            match_marker = ""

        print(f"{GREY}-{RESET}" * 50)
        print(f"Keyword: {YELLOW}{result['keyword']}{RESET} {match_marker}")
        print(f"Primer: {YELLOW}{result['primer']}{RESET}")
        print(f"Alphabet: {YELLOW}{result['alphabet']}{RESET}")
        print(f"IoC: {YELLOW}{result['ioc']:.4f}{RESET}{range_marker}")
        print(f"N-gram Score: {YELLOW}{result['bigram_score']:.2f}{RESET} (Lower is better)")
        print(f"Decrypted: {highlighted_decrypted}")

# --- HEURISTIC SEARCH IMPLEMENTATIONS ---
def get_neighbors(keyword: str, primer_str: str, alphabet_for_key: str, num_neighbors: int = 10) -> List[Tuple[str, str]]:
    neighbors = []
    primer_int = int(primer_str)
    for _ in range(num_neighbors):
        if random.random() < 0.7:
            pos = random.randint(0, len(keyword) - 1)
            new_char = random.choice(alphabet_for_key)
            new_keyword = list(keyword)
            new_keyword[pos] = new_char
            neighbors.append((''.join(new_keyword), primer_str))
        else:
            new_primer = (primer_int + random.randint(-100, 100)) % 100000
            if new_primer < 10000: new_primer += 10000
            neighbors.append((keyword, str(new_primer).zfill(5)))
    return neighbors

def run_hill_climbing_attack(config: Dict, expected_freqs: Dict):
    print(f"\n{GREEN}--- Mode 5: Hill Climbing Attack ---{RESET}")
    ciphertext = config['ciphertext']
    evaluate_fitness = get_fitness_evaluator(config, expected_freqs)

    top_results = []
    def add_to_top(kw, pr, s, t):
        if not any(r['keyword'] == kw and r['primer'] == pr for r in top_results):
            top_results.append({'keyword': kw, 'primer': pr, 'score': s, 'text': t})
            top_results.sort(key=lambda x: x['score'])
            if len(top_results) > 5: top_results.pop()

    for r in range(config['num_restarts']):
        current_keyword = ''.join(random.choice(config['alphabet_for_key']) for _ in range(config['key_length']))
        current_primer = str(random.randint(10000, 99999)).zfill(5)
        mixed_alphabet = create_keyed_alphabet(current_keyword, config['alphabet_for_cipher'])
        running_key = generate_running_key(current_primer, len(ciphertext))
        current_text = decrypt_gromark(ciphertext, mixed_alphabet, running_key, config['alphabet_for_cipher'])
        current_best_score = evaluate_fitness(current_text)
        
        add_to_top(current_keyword, current_primer, current_best_score, current_text)
        
        for i in range(config['max_iterations']):
            neighbors = get_neighbors(current_keyword, current_primer, config['alphabet_for_key'])
            best_neighbor_solution, best_neighbor_score, best_neighbor_text = None, current_best_score, ""
            
            for neighbor_keyword, neighbor_primer in neighbors:
                mixed_alphabet = create_keyed_alphabet(neighbor_keyword, config['alphabet_for_cipher'])
                running_key = generate_running_key(neighbor_primer, len(ciphertext))
                dec = decrypt_gromark(ciphertext, mixed_alphabet, running_key, config['alphabet_for_cipher'])
                score = evaluate_fitness(dec)
                if score < best_neighbor_score:
                    best_neighbor_score, best_neighbor_solution, best_neighbor_text = score, (neighbor_keyword, neighbor_primer), dec
            
            if best_neighbor_solution:
                current_keyword, current_primer = best_neighbor_solution
                current_best_score = best_neighbor_score
                current_text = best_neighbor_text
                
                if len(top_results) < 5 or current_best_score < top_results[-1]['score']:
                    add_to_top(current_keyword, current_primer, current_best_score, current_text)
            else: break
            
            display_text = current_text.replace('\n', ' ')[:35]
            print(f"Restart {r+1}/{config['num_restarts']} | Score: {current_best_score:.2f} | Key: {current_keyword} | Text: {display_text}...", end='\r')

    print("\n\n" + "="*80)
    print(f"\n{YELLOW}--- TOP 5 RANKED SOLUTIONS ---{RESET}")
    for i, res in enumerate(top_results):
        print(f"Rank #{i+1}: Key: {YELLOW}{res['keyword']}{RESET} | Primer: {YELLOW}{res['primer']}{RESET} | Score: {YELLOW}{res['score']:.2f}{RESET} | IoC: {YELLOW}{utils.calculate_ioc(res['text']):.4f}{RESET}")
        print(f"Text: {res['text'].lower()}")
        print("-" * 60)

def run_simulated_annealing_attack(config: Dict, expected_freqs: Dict):
    print(f"\n{GREEN}--- Mode 6: Simulated Annealing Attack ---{RESET}")
    ciphertext = config['ciphertext']
    evaluate_fitness = get_fitness_evaluator(config, expected_freqs)
    
    top_results = []
    def add_to_top(kw, pr, s, t):
        if not any(r['keyword'] == kw and r['primer'] == pr for r in top_results):
            top_results.append({'keyword': kw, 'primer': pr, 'score': s, 'text': t})
            top_results.sort(key=lambda x: x['score'])
            if len(top_results) > 5: top_results.pop()

    for r in range(config['num_restarts']):
        current_keyword = ''.join(random.choice(config['alphabet_for_key']) for _ in range(config['key_length']))
        current_primer = str(random.randint(10000, 99999)).zfill(5)
        mixed_alphabet = create_keyed_alphabet(current_keyword, config['alphabet_for_cipher'])
        running_key = generate_running_key(current_primer, len(ciphertext))
        current_text = decrypt_gromark(ciphertext, mixed_alphabet, running_key, config['alphabet_for_cipher'])
        current_score = evaluate_fitness(current_text)
        
        best_solution_so_far, best_score_so_far = (current_keyword, current_primer), current_score
        add_to_top(current_keyword, current_primer, current_score, current_text)
        
        temperature, cooling_rate = 10000.0, 0.9995
        
        while temperature > 1.0:
            neighbor_keyword, neighbor_primer = get_neighbors(current_keyword, current_primer, config['alphabet_for_key'], 1)[0]
            mixed_alphabet = create_keyed_alphabet(neighbor_keyword, config['alphabet_for_cipher'])
            running_key = generate_running_key(neighbor_primer, len(ciphertext))
            neighbor_text = decrypt_gromark(ciphertext, mixed_alphabet, running_key, config['alphabet_for_cipher'])
            neighbor_score = evaluate_fitness(neighbor_text)
            
            score_delta = neighbor_score - current_score
            if score_delta < 0 or random.random() < np.exp(-score_delta / temperature):
                current_keyword, current_primer, current_score, current_text = neighbor_keyword, neighbor_primer, neighbor_score, neighbor_text
            
            if current_score < best_score_so_far:
                best_solution_so_far, best_score_so_far = (current_keyword, current_primer), current_score
                display_text = current_text.replace('\n', ' ')[:35]
                print(f"Restart {r+1}/{config['num_restarts']} | Temp: {temperature:.0f} | Score: {best_score_so_far:.2f} | Key: {best_solution_so_far[0]} | Text: {display_text}...", end='\r')
            
            if len(top_results) < 5 or current_score < top_results[-1]['score']:
                add_to_top(current_keyword, current_primer, current_score, current_text)
                
            temperature *= cooling_rate

    print("\n\n" + "="*80)
    print(f"\n{YELLOW}--- TOP 5 RANKED SOLUTIONS ---{RESET}")
    for i, res in enumerate(top_results):
        print(f"Rank #{i+1}: Key: {YELLOW}{res['keyword']}{RESET} | Primer: {YELLOW}{res['primer']}{RESET} | Score: {YELLOW}{res['score']:.2f}{RESET} | IoC: {YELLOW}{utils.calculate_ioc(res['text']):.4f}{RESET}")
        print(f"Text: {res['text'].lower()}")
        print("-" * 60)

def run_genetic_algorithm_attack(config: Dict, expected_freqs: Dict):
    print(f"\n{GREEN}--- Mode 7: Genetic Algorithm Attack ---{RESET}")
    ciphertext = config['ciphertext']
    evaluate_fitness = get_fitness_evaluator(config, expected_freqs)

    top_results = []
    def add_to_top(kw, pr, s, t):
        if not any(r['keyword'] == kw and r['primer'] == pr for r in top_results):
            top_results.append({'keyword': kw, 'primer': pr, 'score': s, 'text': t})
            top_results.sort(key=lambda x: x['score'])
            if len(top_results) > 5: top_results.pop()

    def mutate(ind, rate=0.05):
        kw_list = list(ind['keyword'])
        for i in range(len(kw_list)):
            if random.random() < rate: kw_list[i] = random.choice(config['alphabet_for_key'])
        ind['keyword'] = "".join(kw_list)
        if random.random() < rate: ind['primer'] = str(random.randint(10000, 99999)).zfill(5)
        return ind

    population = [{'keyword': ''.join(random.choice(config['alphabet_for_key']) for _ in range(config['key_length'])), 'primer': str(random.randint(10000, 99999)).zfill(5)} for _ in range(config['pop_size'])]
    best_overall_ind, best_overall_score = None, float('inf')

    for gen in range(config['gens']):
        scores = []
        for ind in population:
            mixed = create_keyed_alphabet(ind['keyword'], config['alphabet_for_cipher'])
            running = generate_running_key(ind['primer'], len(ciphertext))
            decrypted = decrypt_gromark(ciphertext, mixed, running, config['alphabet_for_cipher'])
            score = evaluate_fitness(decrypted)
            scores.append((ind, score, decrypted))
            
        scores.sort(key=lambda x: x[1])
        
        for ind, score, dec in scores[:5]:
            add_to_top(ind['keyword'], ind['primer'], score, dec)
            
        population = [item[0] for item in scores]
        if scores[0][1] < best_overall_score:
            best_overall_score = scores[0][1]
            best_overall_ind = scores[0][0]
            display_text = scores[0][2].replace('\n', ' ')[:35]
            print(f"\n{GREEN}New best! Gen: {gen+1}, Score: {best_overall_score:.2f}, Key: {best_overall_ind['keyword']}, Text: {display_text}...{RESET}")
        
        print(f"Generation {gen+1}/{config['gens']} | Best Score: {best_overall_score:.2f}", end='\r')

        next_generation = population[:config['elitism']]
        while len(next_generation) < config['pop_size']:
            p1, p2 = random.choice(population[:20]), random.choice(population[:20])
            split = random.randint(1, len(p1['keyword']) - 1)
            child = {
                'keyword': p1['keyword'][:split] + p2['keyword'][split:],
                'primer': "".join(random.choice(p) for p in zip(p1['primer'], p2['primer']))
            }
            # The bug is fixed here!
            next_generation.append(mutate(child))
        population = next_generation

    print("\n\n" + "="*80)
    print(f"\n{YELLOW}--- TOP 5 RANKED SOLUTIONS ---{RESET}")
    for i, res in enumerate(top_results):
        print(f"Rank #{i+1}: Key: {YELLOW}{res['keyword']}{RESET} | Primer: {YELLOW}{res['primer']}{RESET} | Score: {YELLOW}{res['score']:.2f}{RESET} | IoC: {YELLOW}{utils.calculate_ioc(res['text']):.4f}{RESET}")
        print(f"Text: {res['text'].lower()}")
        print("-" * 60)

# --- MAIN SETUP AND LEGACY WRAPPERS ---
def run_test_case():
    print(f"\n{GREEN}--- Mode 1: Run Known-Answer Test Case ---{RESET}")
    ciphertext = "OHRERPHTMNUQDPUYQTGQHABASQXPTHPYSIXJUFVKNGNDRRIOMAEJGZKHCBNDBIWLDGVWDDVLXCSCZS"
    keyword, primer, alphabet = "GRONSFELD", "32941", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    mixed = create_keyed_alphabet(keyword, alphabet)
    running = generate_running_key(primer, len(ciphertext))
    decrypted = decrypt_gromark(ciphertext, mixed, running, alphabet)
    print(f"Ciphertext: {ciphertext}\nKeyword: {YELLOW}{keyword}{RESET} | Primer: {YELLOW}{primer}{RESET}\nDecrypted: {decrypted}")

def run_direct_decryption():
    print(f"\n{GREEN}--- Mode 2: Direct Decryption ---{RESET}")
    ciphertext = input("Enter ciphertext: ").upper()
    keyword = input("Enter keyword: ").upper()
    primer = input("Enter primer (5-digit number): ")
    alphabet = input("Enter alphabet (default: A-Z): ").upper() or "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    mixed = create_keyed_alphabet(keyword, alphabet)
    running = generate_running_key(primer, len(ciphertext))
    print(f"Decrypted Text: {decrypt_gromark(ciphertext, mixed, running, alphabet)}")

def run_dictionary_attack_wrapper(expected_freqs):
    print(f"\n{GREEN}--- Mode 3: Dictionary Attack ---{RESET}")
    ciphertext = input("Enter ciphertext: ").upper()
    words = [w.strip().upper() for w in open(dictionary_path, 'r') if 1 <= len(w.strip()) <= 15]
    results = parallel_process_keywords(words, ciphertext, [], "ABCDEFGHIJKLMNOPQRSTUVWXYZ", expected_freqs)
    process_and_display_results(results, [])

def run_key_length_bruteforce_wrapper(expected_freqs):
    print(f"\n{GREEN}--- Mode 4: Brute-Force by Key Length ---{RESET}")
    ciphertext = input("Enter ciphertext: ").upper()
    key_length = int(input("Enter key length to brute-force: "))
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    keywords = [''.join(p) for p in itertools.product(alphabet, repeat=key_length)]
    results = parallel_process_keywords(keywords, ciphertext, [], alphabet, expected_freqs)
    process_and_display_results(results, [])

def get_config_from_user(mode: str) -> Dict:
    config = {}
    config['ciphertext'] = input("\nEnter ciphertext: ").upper()
    config['key_length'] = int(input(f"Enter keyword length: "))
    
    if mode in ['5', '6']:
        config['num_restarts'] = int(input(f"Enter number of random restarts (e.g., 10): ") or "10")
    if mode == '5':
        config['max_iterations'] = int(input(f"Enter max iterations per climb (e.g., 1000): ") or "1000")
    if mode == '7':
        config['pop_size'] = int(input(f"Enter population size (e.g., 100): ") or "100")
        config['gens'] = int(input(f"Enter number of generations (e.g., 200): ") or "200")
        config['elitism'] = int(input(f"Enter elitism count (e.g., 5): ") or "5")

    config['alphabet_for_cipher'] = input(f"Enter cipher alphabet (default: ABC...): ").upper().strip() or "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    config['alphabet_for_key'] = input(f"Enter keyword char set (default: Same): ").upper().strip() or config['alphabet_for_cipher']
    
    print(f"\n{GREY}Select Ranking/Optimization Metric:{RESET}")
    print(f"  ({YELLOW}1{RESET}) Pure N-Grams")
    print(f"  ({YELLOW}2{RESET}) Pure English IoC Range (~0.060-0.070)")
    print(f"  ({YELLOW}3{RESET}) Combined (N-Grams weighted by IoC Range) [Recommended]")
    config['scoring_mode'] = input(">> ").strip() or '3'
    
    if config['scoring_mode'] in ['1', '3']:
        ng = input(f"Choose n-gram size (2-6, default {YELLOW}{DEFAULT_NGRAM_SIZE}{RESET}): ")
        config['ngram_size'] = int(ng) if ng else DEFAULT_NGRAM_SIZE
        
    if config['scoring_mode'] in ['2', '3']:
        config['min_ioc'] = float(input(f"Enter target MIN IoC (default {YELLOW}0.060{RESET}): ") or 0.060)
        config['max_ioc'] = float(input(f"Enter target MAX IoC (default {YELLOW}0.070{RESET}): ") or 0.070)

    return config

def run():
    print(f"{RED}G{RESET}romark {RED}C{RESET}ipher {RED}T{RESET}oolkit")
    print(f"{GREY}-{RESET}" * 50)
    
    expected_freqs_bigram = load_ngram_frequencies(ngram_path)
    if not expected_freqs_bigram:
        print(f"{RED}Warning: N-gram scores could not be loaded. Some features will be disabled.{RESET}")

    while True:
        print("\nSelect an option:")
        print(f"  {YELLOW}1{RESET}) Run Known-Answer Test Case")
        print(f"  {YELLOW}2{RESET}) Direct Decryption")
        print("-" * 20)
        print(f"  {YELLOW}3{RESET}) Dictionary Attack")
        print(f"  {YELLOW}4{RESET}) Brute-Force by Key Length {GREY}(Computationally Expensive){RESET}")
        print("-" * 20)
        print(f"  {YELLOW}5{RESET}) Hill Climbing Attack")
        print(f"  {YELLOW}6{RESET}) Simulated Annealing Attack {GREEN}(Recommended){RESET}")
        print(f"  {YELLOW}7{RESET}) Genetic Algorithm Attack {GREEN}(Powerful){RESET}")
        print(f"  {YELLOW}8{RESET}) Exit")
        choice = input(">> ")

        if choice == '1': run_test_case()
        elif choice == '2': run_direct_decryption()
        elif choice == '3': run_dictionary_attack_wrapper(expected_freqs_bigram)
        elif choice == '4': run_key_length_bruteforce_wrapper(expected_freqs_bigram)
        elif choice in ['5', '6', '7']:
            config = get_config_from_user(choice)
            freq_path = resolve_ngram_path(config.get('ngram_size', DEFAULT_NGRAM_SIZE))
            expected_freqs = load_ngram_frequencies(freq_path)
            
            if choice == '5': run_hill_climbing_attack(config, expected_freqs)
            elif choice == '6': run_simulated_annealing_attack(config, expected_freqs)
            elif choice == '7': run_genetic_algorithm_attack(config, expected_freqs)
        elif choice == '8': break
        else: print(f"{RED}Invalid choice. Please select a valid option.{RESET}")

if __name__ == "__main__":
    if not os.path.exists(dictionary_path):
        with open(dictionary_path, 'w', encoding='utf-8') as f: f.write("GRONSFELD\nTESTING\n")
    run()