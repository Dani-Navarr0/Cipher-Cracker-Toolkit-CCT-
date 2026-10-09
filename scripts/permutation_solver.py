import random
import math
import time
import re
from pathlib import Path
from collections import Counter
from typing import Tuple, List, Dict
from itertools import permutations

from ngram_scoring import (
    DEFAULT_NGRAM_PATH,
    NGRAM_DIRECTORY,
    _NGRAM_FILES,
    add_spaces,
    available_spacing_models,
    load_spacing_model,
    load_ngram_scores,
    resolve_ngram_path,
)

# ANSI Colors
RED = '\033[38;5;88m'
YELLOW = '\033[38;5;3m'
GREY = '\033[38;5;238m'
RESET = '\033[0m'
GREEN = '\033[38;5;2m'
CYAN = '\033[38;5;6m'
BLUE = '\033[38;5;4m'

TRANSPOSITION_MODES = {
    '1': ('write_rows_read_rows', 'Write Rows, Permute Cols, Read Rows (Standard Matrix Transposition)'),
    '2': ('write_rows_read_cols', 'Write Rows, Permute Cols, Read Columns'),
    '3': ('write_cols_read_rows', 'Write Columns, Permute Cols, Read Rows'),
    '4': ('write_cols_read_cols', 'Write Columns, Permute Cols, Read Columns'),
}


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


def calculate_ioc(text: str) -> float:
    text = ''.join(filter(str.isalpha, text.upper()))
    n = len(text)
    if n < 2: return 0.0
    freqs = Counter(text)
    numerator = sum(count * (count - 1) for count in freqs.values())
    denominator = n * (n - 1)
    return numerator / denominator if denominator > 0 else 0.0


def get_factors(n: int) -> List[int]:
    """Get all factors of n to determine valid matrix widths."""
    factors = []
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            factors.append(i)
            if i != n // i:
                factors.append(n // i)
    return sorted(factors)


def get_decryption_indices(N: int, W: int, mode: str, perm: List[int]) -> List[int]:
    """Pre-computes index mapping for matrix column permutation."""
    H = (N + W - 1) // W
    r = N % W
    if r == 0: r = W

    indices = [0] * N

    if mode == "write_rows_read_rows":
        row_start = {}
        idx = 0
        for row in range(H):
            row_start[row] = {}
            for k in perm:
                if row < H - 1 or k < r:
                    row_start[row][k] = idx
                    idx += 1
        out_idx = 0
        for row in range(H):
            for col in range(W):
                if row < H - 1 or col < r:
                    indices[out_idx] = row_start[row][col]
                    out_idx += 1

    elif mode == "write_rows_read_cols":
        col_start = {}
        idx = 0
        for k in perm:
            col_start[k] = idx
            idx += (H if k < r else H - 1)
        
        out_idx = 0
        for row in range(H):
            for col in range(W):
                if row < H - 1 or col < r:
                    indices[out_idx] = col_start[col] + row
                    out_idx += 1

    elif mode == "write_cols_read_rows":
        row_start = {}
        idx = 0
        for row in range(H):
            row_start[row] = {}
            for k in perm:
                if row < H - 1 or k < r:
                    row_start[row][k] = idx
                    idx += 1
        out_idx = 0
        for col in range(W):
            col_len = H if col < r else H - 1
            for row in range(col_len):
                indices[out_idx] = row_start[row][col]
                out_idx += 1

    elif mode == "write_cols_read_cols":
        col_start = {}
        idx = 0
        for k in perm:
            col_start[k] = idx
            idx += (H if k < r else H - 1)
        
        out_idx = 0
        for col in range(W):
            col_len = H if col < r else H - 1
            for row in range(col_len):
                indices[out_idx] = col_start[col] + row
                out_idx += 1

    return indices


def decrypt_permutation(ciphertext: str, width: int, perm: List[int], mode: str) -> str:
    indices = get_decryption_indices(len(ciphertext), width, mode, perm)
    return "".join(ciphertext[i] for i in indices)


def calculate_fitness(text: str, ngram_model, ent_weight: float) -> float:
    scores = ngram_model.scores
    ngram_size = ngram_model.size
    letters = "".join(char for char in text.upper() if "A" <= char <= "Z")
    al = len(letters) - ngram_size + 1
    
    if al <= 0:
        return -9999.0

    total_score = 0
    if isinstance(scores, (bytes, bytearray)):
        for index in range(al):
            ngram_index = 0
            for char in letters[index:index + ngram_size]:
                ngram_index = ngram_index * 26 + ord(char) - ord("A")
            total_score += scores[ngram_index]
    else:
        for index in range(al):
            total_score += scores.get(letters[index:index + ngram_size], 0)

    L = len(letters)
    freqs = Counter(letters)
    entropy = sum(abs(math.log2(count / L) * (count / L)) for count in freqs.values())
    return (total_score / al) * (entropy ** ent_weight)


def modify_perm(perm: List[int]) -> List[int]:
    """Mutates permutation array via element swap or sub-segment inversion."""
    new_perm = list(perm)
    if len(perm) < 2:
        return new_perm
        
    if random.random() < 0.7:
        idx1, idx2 = random.sample(range(len(perm)), 2)
        new_perm[idx1], new_perm[idx2] = new_perm[idx2], new_perm[idx1]
    else:
        idx1, idx2 = sorted(random.sample(range(len(perm)), 2))
        new_perm[idx1:idx2] = reversed(new_perm[idx1:idx2])
    return new_perm


def run_simulated_annealing_pass(
    ciphertext: str,
    width: int,
    mode: str,
    ngram_model,
    starting_temp: float,
    cooling_rate: float,
    steps_per_temp: int,
    ent_weight: float
) -> Tuple[List[int], float, str]:
    current_perm = list(range(width))
    random.shuffle(current_perm)
    current_text = decrypt_permutation(ciphertext, width, current_perm, mode)
    current_score = calculate_fitness(current_text, ngram_model, ent_weight)
    
    best_perm = current_perm
    best_score = current_score
    
    temp = starting_temp
    iteration = 0
    start_time = time.time()
    
    try:
        while temp > 0.1:
            for _ in range(steps_per_temp):
                new_perm = modify_perm(current_perm)
                new_text = decrypt_permutation(ciphertext, width, new_perm, mode)
                new_score = calculate_fitness(new_text, ngram_model, ent_weight)
                
                score_diff = new_score - current_score
                
                if score_diff > 0:
                    current_perm = new_perm
                    current_score = new_score
                    
                    if new_score > best_score:
                        best_score = new_score
                        best_perm = new_perm
                        
                elif temp > 0:
                    probability = math.exp(score_diff / temp)
                    if random.random() < probability:
                        current_perm = new_perm
                        current_score = new_score
            
            temp *= cooling_rate
            iteration += 1
            
            if iteration % 10 == 0:
                sample_text = decrypt_permutation(ciphertext, width, best_perm, mode).replace('\n', ' ')[:35]
                print(f"Temp: {temp:>5.2f} | Best Score: {GREEN}{best_score:>8.2f}{RESET} | Text: {sample_text}...", end='\r')
    except KeyboardInterrupt:
        print("\nPass manually interrupted.")

    time_taken = time.time() - start_time
    best_text = decrypt_permutation(ciphertext, width, best_perm, mode)
    print(f"\n{GREEN}Pass Complete in {time_taken:.2f}s! Best Score: {best_score:.2f}{RESET}")
    return best_perm, best_score, best_text


def run_brute_force_for_width(
    ciphertext: str,
    width: int,
    mode: str,
    ngram_model,
    ent_weight: float
) -> Tuple[List[int], float, str]:
    print(f"{GREY}Running Brute Force for Width {width} ({math.factorial(width):,} permutations)...{RESET}")
    cols = list(range(width))
    all_perms = permutations(cols)
    
    best_perm = list(cols)
    best_score = float('-inf')
    best_text = ""
    
    start_time = time.time()
    for p in all_perms:
        perm_list = list(p)
        text = decrypt_permutation(ciphertext, width, perm_list, mode)
        score = calculate_fitness(text, ngram_model, ent_weight)
        
        if score > best_score:
            best_score = score
            best_perm = perm_list
            best_text = text

    time_taken = time.time() - start_time
    print(f"{GREEN}Brute Force Complete in {time_taken:.2f}s! Best Score: {best_score:.2f}{RESET}")
    return best_perm, best_score, best_text


def save_results_to_file(results: List[Dict], filename: str, static_ioc: float):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Matrix Permutation Solver Results\n")
            f.write("=================================\n")
            f.write(f"Monogram IoC: {static_ioc:.4f}\n\n")
            for idx, res in enumerate(results, start=1):
                f.write(f"Rank #{idx}\n")
                f.write(f"Width (Cols): {res['width']}\n")
                f.write(f"Height(Rows): {len(res['text']) // res['width']}\n")
                f.write(f"Layout Mode:  {res['mode_desc']}\n")
                f.write(f"Permutation:  {res['perm']}\n")
                f.write(f"Fitness Score:{res['score']:.2f}\n")
                f.write(f"Plaintext (Raw):\n{res['text']}\n")
                if res.get('spaced_text'):
                    f.write(f"Plaintext (Spaced):\n{res['spaced_text']}\n")
                f.write("-" * 40 + "\n\n")
        print(f"\n{GREEN}Results successfully saved to {filename}{RESET}")
    except IOError as e:
        print(f"\n{RED}Error saving file: {e}{RESET}")


def run():
    print(f"{GREEN}=========================================={RESET}")
    print(f"{GREEN}= Matrix Permutation Solver (Keyless)    ={RESET}")
    print(f"{GREEN}=   (Simulated Annealing & Brute Force)  ={RESET}")
    print(f"{GREEN}=========================================={RESET}")

    ciphertext_input = input(f"\n{GREY}Enter ciphertext: {RESET}").strip().upper()
    ciphertext = "".join(filter(str.isalpha, ciphertext_input))
    if not ciphertext:
        print(f"{RED}No valid ciphertext provided.{RESET}")
        return

    length = len(ciphertext)
    static_ioc = calculate_ioc(ciphertext)
    factors = get_factors(length)
    
    print(f"\n{BLUE}Text Length:{RESET} {length} | Monogram IoC: {YELLOW}{static_ioc:.4f}{RESET}")
    if factors:
        print(f"{BLUE}Possible matrix widths (factors of {length}):{RESET} {factors}")
    else:
        print(f"{RED}Length {length} is prime or has no composite factors. Standard matrix transposition impossible.{RESET}")
        return

    w_in = input(f"\nEnter specific width(s) separated by commas, or blank for all factors: ").strip()
    if w_in:
        try:
            target_widths = [int(w.strip()) for w in w_in.split(",") if int(w.strip()) in factors or int(w.strip()) < length]
        except ValueError:
            target_widths = factors
    else:
        target_widths = factors

    if not target_widths:
        print(f"{RED}No valid widths selected.{RESET}")
        return

    print(f"\n{GREY}Select Layout Mode(s):{RESET}")
    for k, (code, name) in TRANSPOSITION_MODES.items():
        print(f"  [{k}] {name}")
    print(f"  [{YELLOW}A{RESET}] ALL MODES (Evaluate all 4 layout options) [DEFAULT]")
    
    mode_choice = input(f"Select option: ").strip().upper()
    if mode_choice in TRANSPOSITION_MODES:
        active_modes = [TRANSPOSITION_MODES[mode_choice]]
    else:
        active_modes = list(TRANSPOSITION_MODES.values())

    selected_ngram_path = select_ngram_path()
    print(f"{GREY}Loading N-gram model from: {YELLOW}{selected_ngram_path.name}{RESET}")
    ngram_model = load_ngram_scores(selected_ngram_path)

    print(f"\n{GREY}Configure Search Parameters:{RESET}")
    t_in = input(f"Starting Temperature (default {YELLOW}20.0{RESET}): ")
    starting_temp = float(t_in) if t_in else 20.0
    
    c_in = input(f"Cooling Rate (default {YELLOW}0.995{RESET}): ")
    cooling_rate = float(c_in) if c_in else 0.995
    
    s_in = input(f"Steps per temperature (default {YELLOW}1000{RESET}): ")
    steps_per_temp = int(s_in) if s_in else 1000
    
    r_in = input(f"Passes per mode/width (default {YELLOW}3{RESET}): ")
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

    for width in target_widths:
        for mode_code, mode_desc in active_modes:
            print(f"\n{CYAN}================ WIDTH {width} ({length // width} Rows) | MODE: {mode_desc} ================{RESET}")
            
            # Choose Brute Force for small widths (<= 8) or SA for large widths
            if width <= 8:
                bf_choice = input(f"Width {width} has {math.factorial(width):,} permutations. Run Brute Force? ([Y]/n): ").strip().lower()
                use_bf = bf_choice != 'n'
            else:
                use_bf = False

            if use_bf:
                perm, score, text = run_brute_force_for_width(ciphertext, width, mode_code, ngram_model, ent_weight)
                spaced_text = add_spaces(text, spacing_model) if enable_spacing and spacing_model else ""
                all_results.append({
                    'width': width,
                    'perm': perm,
                    'score': score,
                    'text': text,
                    'spaced_text': spaced_text,
                    'mode_code': mode_code,
                    'mode_desc': mode_desc
                })
            else:
                for i in range(runs):
                    print(f"\n{YELLOW}--- WIDTH {width} | {mode_desc} | PASS {i+1} OF {runs} ---{RESET}")
                    perm, score, text = run_simulated_annealing_pass(
                        ciphertext, width, mode_code, ngram_model, starting_temp, cooling_rate, steps_per_temp, ent_weight
                    )
                    
                    spaced_text = add_spaces(text, spacing_model) if enable_spacing and spacing_model else ""
                    all_results.append({
                        'width': width,
                        'perm': perm,
                        'score': score,
                        'text': text,
                        'spaced_text': spaced_text,
                        'mode_code': mode_code,
                        'mode_desc': mode_desc
                    })

    all_results.sort(key=lambda x: x['score'], reverse=True)
    best = all_results[0]

    print(f"\n{YELLOW}================ FINAL BEST RESULT ================{RESET}")
    print(f"Matrix Size:   {best['width']} Columns x {length // best['width']} Rows")
    print(f"Layout Mode:   {CYAN}{best['mode_desc']}{RESET}")
    print(f"Permutation:   {best['perm']}")
    print(f"Fitness Score: {GREEN}{best['score']:.2f}{RESET}")
    print(f"Monogram IoC:  {GREEN}{static_ioc:.4f}{RESET}")
    print(f"\nPlaintext (Raw):\n{GREEN}{best['text']}{RESET}")

    if best.get('spaced_text'):
        print(f"\nPlaintext (Spaced):\n{CYAN}{best['spaced_text']}{RESET}")

    if len(all_results) > 1:
        print(f"\n{YELLOW}--- TOP RANKED SOLUTIONS ACROSS ALL WIDTHS/MODES/PASSES ---{RESET}")
        for rank, res in enumerate(all_results[:5], start=1):
            print(f"Rank #{rank}: Width: {res['width']} | Mode: {res['mode_desc']} | Score: {GREEN}{res['score']:.2f}{RESET}")
            print(f"  Perm: {res['perm']} | Text: {res['text'][:45]}...")

    save_in = input(f"\nExport results to a .txt file? ({YELLOW}Y/n{RESET}): ").strip().lower()
    if save_in != 'n':
        fname = input("Enter filename (default: permutation_results.txt): ").strip()
        if not fname:
            fname = "permutation_results.txt"
        if not fname.endswith(".txt"):
            fname += ".txt"
        save_results_to_file(all_results, fname, static_ioc)


if __name__ == "__main__":
    run()