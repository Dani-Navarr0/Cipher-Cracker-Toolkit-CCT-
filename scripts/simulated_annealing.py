"""Tool 13: simple substitution solved by simulated annealing on n-gram
fitness. The search runs in C (native/layered_engine.c, one substitution layer)."""
import math
import time
import re
from pathlib import Path
from collections import Counter
from typing import Tuple, List, Dict

from annealing import Fitness, Schedule
from layered import LayeredSolver, SubstitutionLayer
from ngram_scoring import (
    DEFAULT_NGRAM_PATH,
    NGRAM_DIRECTORY,
    _NGRAM_FILES,
    add_spaces,
    available_spacing_models,
    codes_to_text,
    load_spacing_model,
    load_ngram_scores,
    resolve_ngram_path,
    text_to_codes,
)

# ANSI Colors
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def select_ngram_path() -> Path:
    """Prompts user to select N-gram size or custom path."""
    print(f"\n{GREY}Select N-gram Model:{RESET}")
    sizes = sorted(_NGRAM_FILES.keys())
    for sz in sizes:
        default_tag = " (DEFAULT)" if sz == 5 else ""
        filename = _NGRAM_FILES[sz]
        print(f"  [{sz}] {sz}-gram -> {filename}{default_tag}")

    other_files = []
    if NGRAM_DIRECTORY.exists():
        other_files = [
            f for f in NGRAM_DIRECTORY.iterdir()
            if f.is_file() and f.name not in _NGRAM_FILES.values()
        ]

    if other_files:
        print("\nAdditional N-gram files found:")
        for idx, fpath in enumerate(other_files, start=7):
            print(f"  [{idx}] {fpath.name}")

    choice = input(f"\nEnter size (2-6), file number, or custom path (default: {YELLOW}5{RESET}): ").strip()

    if not choice:
        return DEFAULT_NGRAM_PATH

    if choice.isdigit():
        val = int(choice)
        if val in _NGRAM_FILES:
            return resolve_ngram_path(val)
        if 7 <= val < 7 + len(other_files):
            return other_files[val - 7]

    custom_path = Path(choice)
    if custom_path.exists():
        return custom_path

    rel_path = NGRAM_DIRECTORY / choice
    if rel_path.exists():
        return rel_path

    print(f"{YELLOW}File/size '{choice}' not found. Falling back to default (5-gram).{RESET}")
    return DEFAULT_NGRAM_PATH


def select_spacing_model_path(ngram_path: Path) -> Path:
    models = available_spacing_models()
    if not models:
        raise FileNotFoundError(f"No spacing n-gram models found under {NGRAM_DIRECTORY / 'Spaces'}")

    normalized_ngram_name = re.sub(r"[^a-z0-9]", "", ngram_path.name.casefold())
    default_index = next(
        (
            index for index, model_path in enumerate(models)
            if re.sub(r"[^a-z0-9]", "", model_path.parent.name.casefold()) in normalized_ngram_name
        ),
        0,
    )

    print(f"\n{GREY}Select spacing language:{RESET}")
    for index, model_path in enumerate(models):
        default_tag = " (DEFAULT)" if index == default_index else ""
        print(f"  [{index + 1}] {model_path.parent.name}{default_tag}")

    while True:
        choice = input(f"Language number (default {default_index + 1}): ").strip()
        if not choice:
            return models[default_index]
        if choice.isdigit() and 1 <= int(choice) <= len(models):
            return models[int(choice) - 1]
        print(f"{YELLOW}Choose a number from 1 to {len(models)}.{RESET}")


def parse_ciphertext(text: str):
    if re.search(r'\d', text):
        tokens = re.findall(r'\d+', text)
        if len(tokens) == 1 and len(tokens[0]) > 2 and len(tokens[0]) % 2 == 0:
            tokens = [tokens[0][i:i+2] for i in range(0, len(tokens[0]), 2)]
            
        if len("".join(tokens)) > len(text.replace(" ", "").replace(",", "")) * 0.5:
            unique_tokens = list(dict.fromkeys(tokens))
            if len(unique_tokens) > 26:
                print(f"{YELLOW}Warning: More than 26 unique numeric symbols ({len(unique_tokens)}). Truncating to 26.{RESET}")
                unique_tokens = unique_tokens[:26]
            
            mapping = {t: chr(ord('A') + i) for i, t in enumerate(unique_tokens)}
            mapped_text = "".join(mapping.get(t, '') for t in tokens)
            return mapped_text, mapping
            
    letters = "".join(c for c in text.upper() if "A" <= c <= "Z")
    return letters, None


def calculate_ioc(text: str) -> float:
    text = ''.join(filter(str.isalpha, text.upper()))
    n = len(text)
    if n < 2: return 0.0
    freqs = Counter(text)
    numerator = sum(count * (count - 1) for count in freqs.values())
    denominator = n * (n - 1)
    return numerator / denominator if denominator > 0 else 0.0


def ioc_penalty_for(text_ioc: float, min_ioc: float, max_ioc: float) -> float:
    if min_ioc <= text_ioc <= max_ioc:
        return 0.0
    if text_ioc < min_ioc:
        return min_ioc - text_ioc
    return text_ioc - max_ioc


def annealing_steps(starting_temp: float, cooling_rate: float, steps_per_temp: int) -> int:
    """Steps of a schedule that cools from starting_temp by cooling_rate per
    level of steps_per_temp steps until 0.1 (the tool's parameters)."""
    if starting_temp <= 0.1 or not 0 < cooling_rate < 1:
        return 0
    return steps_per_temp * math.ceil(math.log(0.1 / starting_temp) / math.log(cooling_rate))


def run_simulated_annealing(
    ciphertext: str,
    ngram_model,
    starting_temp: float,
    cooling_rate: float,
    steps_per_temp: int,
    ent_weight: float,
    scoring_mode: str,
    min_ioc: float,
    max_ioc: float
) -> Tuple[str, float, float, str]:
    """One annealing pass in C (layered engine, one substitution layer), then a
    hill climb over every letter swap. The schedule cools geometrically from
    starting_temp to 0.1 over the steps that starting_temp, cooling_rate and
    steps_per_temp give. Returns (key, score, IoC, plaintext); key[p] is the
    cipher letter of plaintext letter p.

    A substitution key only relabels letters, so the IoC and the letter entropy
    of every candidate plaintext equal the ciphertext's: the entropy factor (and
    in Combined mode the IoC factor) is one constant, fixed in the fitness."""
    cipher_codes = text_to_codes(ciphertext)
    text_ioc = calculate_ioc(ciphertext)
    fitness = Fitness(ngram_model, ent_weight, fixed_letters=cipher_codes)
    if scoring_mode == '3':
        fitness.fixed_factor *= 1.0 - ioc_penalty_for(text_ioc, min_ioc, max_ioc) * 20.0
    solver = LayeredSolver(cipher_codes, [SubstitutionLayer()], fitness)
    iterations = annealing_steps(starting_temp, cooling_rate, steps_per_temp)

    print(f"\n{YELLOW}Starting Simulated Annealing (Substitution, C engine)...{RESET}")
    print(f"{GREY}Starting Temp: {starting_temp} | Cooling Rate: {cooling_rate} | Steps/Temp: {steps_per_temp} "
          f"| {iterations:,} steps{RESET}\n")

    def report(step, temperature, best, state):
        sample_text = codes_to_text(cipher_codes.translate(bytes(state[0]) + bytes(230)))[:35]
        print(f"Temp: {temperature:>5.2f} | Best Score: {GREEN}{best:>8.2f}{RESET} | IoC: {YELLOW}{text_ioc:.4f}{RESET} "
              f"| Text: {sample_text}...", end='\r')

    start_time = time.time()
    if iterations:
        solver.anneal(Schedule(iterations, starting_temp, 0.1), report)
    best_score = solver.polish()
    table = solver.snapshot()[0]
    key = [0] * 26
    for cipher, plain in enumerate(table):
        key[plain] = cipher
    best_key = "".join(ALPHABET[code] for code in key)
    best_text = codes_to_text(solver.plaintext())
    print(f"\n{GREEN}Annealing Pass Complete in {time.time() - start_time:.2f}s! Best Score: {best_score:.2f} "
          f"| IoC: {text_ioc:.4f}{RESET}")
    return best_key, best_score, text_ioc, best_text


def save_results_to_file(results: List[Dict], filename: str, numeric_mapping=None):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Simulated Annealing Substitution Results\n")
            f.write("=======================================\n\n")
            for idx, res in enumerate(results, start=1):
                f.write(f"Rank #{idx}\n")
                if numeric_mapping:
                    inv_map = {v: k for k, v in numeric_mapping.items()}
                    f.write(f"Plaintext Mapping:  {ALPHABET}\n")
                    cipher_row = "".join(inv_map.get(c, '-').rjust(3) for c in res['key'])
                    f.write(f"Ciphertext Mapping: {cipher_row}\n")
                else:
                    f.write(f"Plaintext Alphabet:  {ALPHABET}\n")
                    f.write(f"Ciphertext Mapping: {res['key']}\n")
                f.write(f"Fitness Score: {res['score']:.2f}\n")
                f.write(f"IoC Score:     {res['ioc']:.4f}\n")
                f.write(f"Plaintext (Raw):\n{res['text']}\n")
                if res.get('spaced_text'):
                    f.write(f"Plaintext (Spaced):\n{res['spaced_text']}\n")
                f.write("-" * 40 + "\n\n")
        print(f"\n{GREEN}Results successfully saved to {filename}{RESET}")
    except IOError as e:
        print(f"\n{RED}Error saving file: {e}{RESET}")


def run():
    import native
    native.require()            # the search runs in C
    banner("Simulated Annealing: Substitution", "Breaks simple substitution with n-gram scoring")
    
    ciphertext_input = input(f"{GREY}Enter substitution ciphertext: {RESET}").upper()
    if not ciphertext_input:
        return
        
    ciphertext, numeric_mapping = parse_ciphertext(ciphertext_input)
    if not ciphertext:
        print(f"{RED}No valid ciphertext found.{RESET}")
        return

    selected_ngram_path = select_ngram_path()
    print(f"{GREY}Loading N-gram model from: {YELLOW}{selected_ngram_path.name}{RESET}")
    ngram_model = load_ngram_scores(selected_ngram_path)

    print(f"\n{GREY}Select Ranking/Optimization Metric:{RESET}")
    print(f"  [{YELLOW}1{RESET}] Pure N-Grams (Standard AZDecrypt likelihood)")
    print(f"  [{YELLOW}2{RESET}] Pure IoC Target Range (Detect transposed / intermediate output)")
    print(f"  [{YELLOW}3{RESET}] Combined (N-Grams weighted by Target IoC Range) [RECOMMENDED]")
    scoring_mode = input(f"Selection (default {YELLOW}3{RESET}): ").strip() or '3'

    min_ioc, max_ioc = 0.060, 0.070
    if scoring_mode in ['2', '3']:
        min_in = input(f"Enter target MIN IoC (default {YELLOW}0.060{RESET}): ").strip()
        min_ioc = float(min_in) if min_in else 0.060
        max_in = input(f"Enter target MAX IoC (default {YELLOW}0.070{RESET}): ").strip()
        max_ioc = float(max_in) if max_in else 0.070

    # Simple substitution cannot change the IoC (it only relabels letters), so
    # every key has the ciphertext's IoC. Pure-IoC mode would score all keys
    # equally (a random walk), and in combined mode the IoC term is a constant
    # factor that, if <= 0, would make the search minimise English-likeness.
    cipher_ioc = calculate_ioc(ciphertext)
    print(f"{GREY}Ciphertext IoC: {YELLOW}{cipher_ioc:.4f}{GREY} (unchanged by any substitution key){RESET}")
    if scoring_mode == '2':
        print(f"{YELLOW}Pure IoC cannot rank substitution keys; using Combined mode instead.{RESET}")
        scoring_mode = '3'
    if scoring_mode == '3' and 1.0 - ioc_penalty_for(cipher_ioc, min_ioc, max_ioc) * 20.0 <= 0:
        print(f"{YELLOW}IoC is far outside the target range; using Pure N-Grams so the search is not inverted.{RESET}")
        scoring_mode = '1'

    print(f"\n{GREY}Configure Simulated Annealing Parameters:{RESET}")
    
    t_in = input(f"Starting Temperature (default {YELLOW}20.0{RESET}): ")
    starting_temp = float(t_in) if t_in else 20.0
    
    c_in = input(f"Cooling Rate (default {YELLOW}0.995{RESET}): ")
    cooling_rate = float(c_in) if c_in else 0.995
    
    s_in = input(f"Steps per temperature (default {YELLOW}1000{RESET}): ")
    steps_per_temp = int(s_in) if s_in else 1000
    
    r_in = input(f"Number of passes to run (default {YELLOW}3{RESET}): ")
    runs = int(r_in) if r_in else 3
    
    ew_in = input(f"Entropy Weight (AZDecrypt default ~{YELLOW}0.5{RESET}): ")
    ent_weight = float(ew_in) if ew_in else 0.5

    sp_in = input(f"Automatically insert spaces into output? ([Y]/n): ").strip().lower()
    enable_spacing = sp_in != 'n'
    spacing_model = None
    if enable_spacing:
        spacing_path = select_spacing_model_path(selected_ngram_path)
        print(f"{GREY}Loading spacing model from: {YELLOW}{spacing_path.name}{RESET}")
        spacing_model = load_spacing_model(spacing_path)
        _ = spacing_model.scores
    
    all_results = []
    
    for i in range(runs):
        print(f"\n{YELLOW}--- PASS {i+1} OF {runs} ---{RESET}")
        key, score, ioc_val, text = run_simulated_annealing(
            ciphertext, ngram_model, starting_temp, cooling_rate, steps_per_temp, ent_weight, scoring_mode, min_ioc, max_ioc
        )
        
        spaced_text = add_spaces(text, spacing_model) if enable_spacing and spacing_model else ""
        all_results.append({
            'key': key,
            'score': score,
            'ioc': ioc_val,
            'text': text,
            'spaced_text': spaced_text
        })

    all_results.sort(key=lambda x: x['score'], reverse=True)
    best = all_results[0]
            
    print(f"\n{YELLOW}================ FINAL BEST RESULT ================{RESET}")
    if numeric_mapping:
        inv_map = {v: k for k, v in numeric_mapping.items()}
        print(f"Key Mapping: {' '.join(c.rjust(2) for c in ALPHABET)}  <-- Plaintext")
        cipher_row = [inv_map.get(c, '-').rjust(2) for c in best['key']]
        print(f"             {' '.join(cipher_row)}  <-- Ciphertext")
    else:
        print(f"Key Mapping: {ALPHABET}  <-- Plaintext")
        print(f"             {best['key']}  <-- Ciphertext")
        
    print(f"Fitness Score: {GREEN}{best['score']:.2f}{RESET}")
    print(f"Final IoC:     {GREEN}{best['ioc']:.4f}{RESET}")
    print(f"\nPlaintext (Raw):\n{GREEN}{best['text']}{RESET}")

    if best.get('spaced_text'):
        print(f"\nPlaintext (Spaced):\n{CYAN}{best['spaced_text']}{RESET}")

    if len(all_results) > 1:
        print(f"\n{YELLOW}--- TOP RANKED PASSES ---{RESET}")
        for idx, res in enumerate(all_results[:5], start=1):
            print(f"Rank #{idx}: Score: {GREEN}{res['score']:.2f}{RESET} | IoC: {YELLOW}{res['ioc']:.4f}{RESET} | Text: {res['text'][:40]}...")

    save_in = input(f"\nExport results to a .txt file? ({YELLOW}Y/n{RESET}): ").strip().lower()
    if save_in != 'n':
        fname = input("Enter filename (default: substitution_results.txt): ").strip()
        if not fname:
            fname = "substitution_results.txt"
        if not fname.endswith(".txt"):
            fname += ".txt"
        save_results_to_file(all_results, fname, numeric_mapping)

if __name__ == "__main__":
    run()