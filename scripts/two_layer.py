"""Two-layer cipher solver: substitution, transposition and Vigenere-family
layers in any two-layer combination, solved by joint simulated annealing.

How it works: every layer has a key (a substitution alphabet, a column order,
or a periodic shift key). One annealing search changes one layer's key per
step and scores the fully decrypted text with n-grams, so the layers are
solved together rather than one after the other.

Notes on combinations (these follow from the cipher definitions):
  * Two simple substitutions compose into ONE simple substitution, so a double
    substitution is solved exactly like a single one.
  * Substitution and transposition commute (one changes letters, the other
    positions), so their order of application does not matter.
  * A periodic (Vigenere-family) layer depends on letter positions, so its order
    relative to a transposition or substitution DOES matter.
"""
import os
import random
import re
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

from annealing import Fitness, Schedule
from layered import (
    ALPHABET, TRANSPOSITION_MODES, LayeredSolver, PeriodicLayer,
    SubstitutionLayer, TranspositionLayer,
)
from ngram_scoring import (
    DEFAULT_NGRAM_PATH, add_spaces, available_spacing_models, codes_to_text,
    load_ngram_scores, load_spacing_model, resolve_ngram_path, text_to_codes,
)

from theme import BLUE, BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner, option, rule, section

# Combination -> (label, layers in ENCRYPTION order, default iterations per run).
# Default budgets come from success-rate measurements on English text
# (300-600 letters); harder combinations need longer searches.
COMBINATIONS = {
    '1': ("Substitution + Transposition (either order)", ("sub", "trans"), 1_500_000),
    '2': ("Transposition, then Vigenere-family", ("trans", "periodic"), 600_000),
    '3': ("Vigenere-family, then Transposition", ("periodic", "trans"), 1_500_000),
    '4': ("Substitution, then Vigenere-family (Quagmire-like)", ("sub", "periodic"), 600_000),
    '5': ("Vigenere-family, then Substitution", ("periodic", "sub"), 1_500_000),
    '6': ("Transposition + Transposition (double transposition)", ("trans", "trans"), 800_000),
    '7': ("Substitution + Substitution", ("sub",), 300_000),
}
PERIODIC_VARIANTS = {'1': 'vigenere', '2': 'beaufort', '3': 'variant'}


# ---------------------------------------------------------------- building

def build_layers(job, length):
    """Layers in DECRYPTION order for one job description."""
    layers = []
    for kind, parameter in reversed(job['encryption']):
        if kind == "sub":
            layers.append(SubstitutionLayer())
        elif kind == "trans":
            width, mode = parameter
            layers.append(TranspositionLayer(length, width, mode))
        else:
            period, variant = parameter
            layers.append(PeriodicLayer(period, variant))
    # Combination 1 is listed as (sub, trans) so the transposition is undone
    # first: the two commute, and substitution moves then only need one cheap
    # translate of the cached un-transposed text.
    return layers


def solve_job(job):
    """Run one annealing search. Module-level so worker processes can run it."""
    random.seed(job['seed'])
    model = load_ngram_scores(job['ngram_path'])
    cipher = bytes(job['cipher'])
    layers = build_layers(job, len(cipher))
    fixed = cipher if all(layer.preserves_counts for layer in layers) else None
    solver = LayeredSolver(cipher, layers, Fitness(model, job['entropy_weight'], fixed_letters=fixed))
    started = time.time()
    solver.anneal(Schedule(job['iterations']))
    score = solver.polish()
    return {
        'score': score,
        'plaintext': codes_to_text(solver.plaintext()),
        'keys': solver.describe(),
        'label': job['label'],
        'seconds': time.time() - started,
    }


def measure_step_time(job) -> float:
    """Seconds per annealing step for this job, measured on this machine."""
    model = load_ngram_scores(job['ngram_path'])
    cipher = bytes(job['cipher'])
    layers = build_layers(job, len(cipher))
    solver = LayeredSolver(cipher, layers, Fitness(model, job['entropy_weight']))
    steps = 3000
    started = time.perf_counter()
    for _ in range(steps):
        solver.propose()
        solver.undo()
    return (time.perf_counter() - started) / steps


# ---------------------------------------------------------------- input helpers

def ask_int_range(prompt, default):
    text = input(f"{prompt} (e.g. {YELLOW}{default}{RESET} or a range like {YELLOW}5-9{RESET}): ").strip() or str(default)
    match = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d+))?\s*", text)
    if not match:
        print(f"{YELLOW}Could not read '{text}', using {default}.{RESET}")
        return [default]
    low = int(match.group(1))
    high = int(match.group(2) or low)
    return list(range(min(low, high), max(low, high) + 1))


def ask_int(prompt, default, minimum=1):
    text = input(f"{prompt} (default {YELLOW}{default}{RESET}): ").strip()
    try:
        return max(minimum, int(text.replace(",", "").replace("_", ""))) if text else default
    except ValueError:
        print(f"{YELLOW}Not a number; using {default}.{RESET}")
        return default


def ask_modes():
    print(f"{GREY}Transposition layout:{RESET}")
    codes = list(TRANSPOSITION_MODES)
    for index, code in enumerate(codes, start=1):
        option(index, TRANSPOSITION_MODES[code], "(default)" if index == 1 else "")
    option("A", "All four layouts")
    choice = input("Select (Enter = 1): ").strip().upper()
    if choice == 'A':
        return codes
    if choice.isdigit() and 1 <= int(choice) <= len(codes):
        return [codes[int(choice) - 1]]
    return [codes[0]]


def ask_variant():
    print(f"{GREY}Periodic cipher type:{RESET}")
    option(1, "Vigenere", "P = C - K (default)")
    option(2, "Beaufort", "P = K - C")
    option(3, "Variant Beaufort", "P = C + K")
    return PERIODIC_VARIANTS.get(input("Select (Enter = 1): ").strip(), 'vigenere')


def ioc(codes) -> float:
    total = len(codes)
    return sum(codes.count(c) * (codes.count(c) - 1) for c in range(26)) / (total * (total - 1)) if total > 1 else 0.0


def print_hints(codes):
    """Cheap statistics that indicate which layer types are present."""
    from layered import ENGLISH_FREQUENCIES
    total = len(codes)
    value = ioc(codes)
    chi = sum((codes.count(c) - ENGLISH_FREQUENCIES[c] * total / 100) ** 2 / (ENGLISH_FREQUENCIES[c] * total / 100) for c in range(26))
    section("Ciphertext statistics")
    print(f"Letters: {YELLOW}{total}{RESET} | IoC: {YELLOW}{value:.4f}{RESET} {GREY}(English ~0.066, random ~0.038){RESET} "
          f"| Chi-squared vs English: {YELLOW}{chi:.0f}{RESET}")
    if value >= 0.058:
        print(f"{GREY}Hint: IoC is English-like, so letter frequencies were probably not flattened: "
              f"a periodic (Vigenere-family) layer is unlikely.{RESET}")
        if chi < 60:
            print(f"{GREY}Hint: letter frequencies match English closely: possibly transposition only (no substitution).{RESET}")
    elif value <= 0.050:
        print(f"{GREY}Hint: low IoC suggests a periodic (Vigenere-family) layer. Try the Vigenere auto-solver or "
              f"Kasiski/Friedman tools to estimate the period.{RESET}")
    if total < 150:
        print(f"{YELLOW}Warning: two-layer solving usually needs a few hundred letters; short texts may not be uniquely solvable.{RESET}")


# ---------------------------------------------------------------- test cipher maker

def make_test_cipher():
    """Encrypt a sample text with random keys so the solver can be checked.

    Returns the ciphertext (A-Z letters) or None.
    """
    import pydoc_data.topics as topics
    section("Make a test ciphertext (random keys)")
    text = input("Plaintext (blank = a random English passage): ").strip()
    if not text:
        length = ask_int("Passage length in letters", 400, minimum=50)
        prose = " ".join(line.strip() for t in topics.topics.values() for line in t.splitlines()
                         if len(line.strip()) > 40 and not re.search(r"[=()\[\]{}:<>#_*`|\\/@$%^~]", line))
        letters = re.sub("[^A-Z]", "", prose.upper())
        start = random.randrange(0, len(letters) - length)
        text = letters[start:start + length]
    plain = text_to_codes(text)
    for key, (label, _, _) in COMBINATIONS.items():
        option(key, label)
    choice = input("Combination: ").strip()
    if choice not in COMBINATIONS:
        print(f"{RED}Invalid choice.{RESET}")
        return None
    codes, applied = plain, []
    for kind in COMBINATIONS[choice][1] if choice != '7' else ("sub", "sub"):
        if kind == "sub":
            table = bytes(random.sample(range(26), 26))
            codes = codes.translate(table + bytes(230))
            applied.append("Substitution " + "".join(ALPHABET[c] for c in table))
        elif kind == "trans":
            width = ask_int("Transposition width", 8, minimum=2)
            key = random.sample(range(width), width)
            layer = TranspositionLayer(len(codes), width, 'write_rows_read_cols')
            # encryption = inverse of the decryption permutation
            positions = layer.permute(bytes(i % 256 for i in range(len(codes))), key)
            high = layer.permute(bytes(i // 256 for i in range(len(codes))), key)
            out = bytearray(len(codes))
            for target, (h, l) in enumerate(zip(high, positions)):
                out[h * 256 + l] = codes[target]
            codes = bytes(out)
            applied.append(f"Transposition width {width} (standard columnar), column order {key}")
        else:
            period = ask_int("Vigenere period", 7, minimum=1)
            key = [random.randrange(26) for _ in range(period)]
            codes = bytes((c + key[i % period]) % 26 for i, c in enumerate(codes))
            applied.append("Vigenere key " + "".join(ALPHABET[k] for k in key))
    print(f"\n{GREY}Layers applied in order (keep these to check the solver's answer):{RESET}")
    for line in applied:
        print(f"  - {line}")
    print(f"{GREY}Plaintext:{RESET} {codes_to_text(plain)}")
    ciphertext = codes_to_text(codes)
    print(f"\n{GREEN}Ciphertext:{RESET}\n{ciphertext}")
    return ciphertext


# ---------------------------------------------------------------- one search

def configure(cipher, previous=None):
    """Ask which layers and parameters to try. Returns a settings dict or None."""
    section("Which layers? (encryption order)")
    for key, (label, _, _) in COMBINATIONS.items():
        option(key, label)
    default = previous['choice'] if previous else None
    choice = input(f"Select{f' (Enter = {default})' if default else ''}: ").strip() or default
    if choice not in COMBINATIONS:
        print(f"{RED}Invalid choice.{RESET}")
        return None
    label, kinds, default_iterations = COMBINATIONS[choice]
    if choice == '7':
        print(f"{CYAN}Two simple substitutions compose into one simple substitution "
              f"(applying sigma1 then sigma2 equals applying sigma2(sigma1(x))), so this is solved "
              f"as a single substitution. The key found is the combined alphabet.{RESET}")

    parameter_options = []
    for position, kind in enumerate(kinds, start=1):
        if kind == "trans":
            which = f" #{position}" if kinds.count("trans") > 1 else ""
            widths = ask_int_range(f"Transposition{which} width(s)", 8)
            modes = ask_modes()
            parameter_options.append([("trans", (w, m)) for w in widths for m in modes if 2 <= w < len(cipher)])
        elif kind == "periodic":
            periods = ask_int_range("Period(s) of the Vigenere-family key", 7)
            variant = ask_variant()
            parameter_options.append([("periodic", (p, variant)) for p in periods if p >= 1])
        else:
            parameter_options.append([("sub", None)])
    combos = [[]]
    for options in parameter_options:
        combos = [existing + [entry] for existing in combos for entry in options]
    if not combos or not all(combos):
        print(f"{RED}No valid parameter combinations.{RESET}")
        return None

    section("Search budget")
    print(f"{GREY}Recommended values come from tests on 300-600 letter English texts.{RESET}")
    iterations = ask_int("Annealing steps per run", default_iterations, minimum=1000)
    restarts = ask_int("Independent runs per parameter combination", 4)
    return {'choice': choice, 'combos': combos, 'iterations': iterations, 'restarts': restarts}


def describe_combo(combo):
    return " -> ".join(
        "Substitution" if kind == "sub" else
        f"Transposition(w={p[0]}, {p[1]})" if kind == "trans" else
        f"{p[1].title()}(period {p[0]})"
        for kind, p in combo
    )


def execute(cipher, settings, ngram_path=DEFAULT_NGRAM_PATH, entropy_weight=0.5):
    """Run every job for the settings; returns results sorted best first."""
    jobs = []
    for combo in settings['combos']:
        for _ in range(settings['restarts']):
            jobs.append({
                'cipher': cipher, 'encryption': combo, 'iterations': settings['iterations'],
                'ngram_path': str(ngram_path), 'entropy_weight': entropy_weight,
                'seed': random.randrange(2 ** 32), 'label': describe_combo(combo),
            })

    workers = max(1, min(len(jobs), (os.cpu_count() or 2) - 1))
    step_seconds = measure_step_time(jobs[0])
    total_seconds = step_seconds * settings['iterations'] * len(jobs) / workers
    print(f"\n{BLUE}{len(jobs)} runs{RESET} ({len(settings['combos'])} parameter combination(s) x {settings['restarts']}) of "
          f"{settings['iterations']:,} steps on {workers} process(es). Measured {step_seconds * 1e6:.0f} us/step "
          f"-> roughly {YELLOW}{total_seconds / 60:.1f}-{2 * total_seconds / 60 + 0.1:.1f} min{RESET} "
          f"{GREY}(process start-up, final polishing and CPU load add to the raw step time){RESET}.")
    if input("Start? ([Y]/n): ").strip().lower() == 'n':
        return []

    results = []
    started = time.time()
    try:
        if workers == 1:
            for done, job in enumerate(jobs, start=1):
                results.append(solve_job(job))
                print(f"Run {done}/{len(jobs)} done | best fitness so far {max(r['score'] for r in results):.1f}", end='\r')
        else:
            with ProcessPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(solve_job, job) for job in jobs]
                for done, future in enumerate(as_completed(futures), start=1):
                    results.append(future.result())
                    best = max(results, key=lambda r: r['score'])
                    print(f"Run {done}/{len(jobs)} done | best fitness {best['score']:.1f} | "
                          f"{best['plaintext'][:40]}...", end='\r')
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted; showing the runs that finished.{RESET}")
    print(f"\n{GREY}Finished in {(time.time() - started) / 60:.1f} min.{RESET}")
    results.sort(key=lambda r: -r['score'])
    return results


# ---------------------------------------------------------------- results

def show_results(results):
    best = results[0]
    agreeing = sum(1 for r in results if r['plaintext'] == best['plaintext'])
    section("Best result")
    print(f"Layers: {CYAN}{best['label']}{RESET}")
    for line in best['keys']:
        print(f"  {line}")
    print(f"Fitness: {GREEN}{best['score']:.1f}{RESET} {GREY}(higher is better; English text typically scores ~200+ with 5-grams){RESET}")
    print(f"Runs reaching this same plaintext: {YELLOW}{agreeing}/{len(results)}{RESET} "
          f"{GREY}(independent runs agreeing is good evidence of a real solution){RESET}")
    print(f"\nPlaintext:\n{GREEN}{best['plaintext']}{RESET}")

    models = available_spacing_models()
    english = next((p for p in models if p.parent.name.lower() == "english"), models[0] if models else None)
    if english:
        print(f"\nWith word spaces {GREY}(automatic, English model){RESET}:\n{CYAN}{add_spaces(best['plaintext'], load_spacing_model(english))}{RESET}")

    section("Top runs")
    for rank, result in enumerate(results[:8], start=1):
        print(f"{GREY}#{rank}{RESET} fitness {YELLOW}{result['score']:.1f}{RESET} | {result['label']} | {result['plaintext'][:46]}...")


def save_results(results):
    filename = input("Save all runs to file (name, Enter to cancel): ").strip()
    if not filename:
        return
    if not filename.endswith(".txt"):
        filename += ".txt"
    with open(filename, "w", encoding="utf-8") as handle:
        for rank, result in enumerate(results, start=1):
            handle.write(f"Rank #{rank} | fitness {result['score']:.2f} | {result['label']}\n")
            for line in result['keys']:
                handle.write(f"  {line}\n")
            handle.write(f"{result['plaintext']}\n{'-' * 60}\n")
    print(f"{GREEN}Saved {len(results)} runs to {filename}{RESET}")


# ---------------------------------------------------------------- session loop

def ask_ciphertext():
    ciphertext = input(f"\n{GREY}Enter ciphertext:{RESET} ")
    cipher = text_to_codes(ciphertext)
    if len(cipher) < 20:
        print(f"{RED}Need at least 20 letters (A-Z); got {len(cipher)}.{RESET}")
        return None
    return cipher


def session_status(cipher, settings, results):
    rule()
    preview = codes_to_text(cipher)
    print(f"{BOLD}Ciphertext{RESET} {GREY}({len(cipher)} letters, IoC {ioc(cipher):.4f}):{RESET} "
          f"{preview[:48]}{'...' if len(preview) > 48 else ''}")
    if settings:
        print(f"{BOLD}Last search{RESET} {GREY}:{RESET} {COMBINATIONS[settings['choice']][0]} "
              f"{GREY}| {settings['iterations']:,} steps x {settings['restarts']} runs per combination{RESET}")
    if results:
        print(f"{BOLD}Best so far{RESET} {GREY}:{RESET} fitness {YELLOW}{results[0]['score']:.1f}{RESET} "
              f"{GREY}|{RESET} {results[0]['plaintext'][:40]}...")
    rule()


def run():
    """Interactive session: the ciphertext and results are kept between
    searches, so different layer combinations can be tried without leaving
    the module or pasting the ciphertext again."""
    banner("Two-Layer Solver", "Substitution / transposition / Vigenere stacks, solved jointly")
    cipher, settings, results = None, None, []

    while True:
        if cipher is None:
            print()
            option(1, "Enter a ciphertext")
            option(2, "Make a test ciphertext", "(random keys, to check the solver)")
            option(0, "Back to main menu")
            choice = input("Select: ").strip()
            if choice == '1':
                cipher = ask_ciphertext()
                if cipher:
                    print_hints(cipher)
                    settings, results = None, []
            elif choice == '2':
                made = make_test_cipher()
                if made and input("\nSolve this test ciphertext now? ([Y]/n): ").strip().lower() != 'n':
                    cipher, settings, results = text_to_codes(made), None, []
                    print_hints(cipher)
            elif choice in ('0', 'q', 'Q', ''):
                return
            if cipher is None:
                continue
            # A fresh ciphertext goes straight to configuring a search.
            new_settings = configure(cipher)
            if new_settings:
                settings = new_settings
                found = execute(cipher, settings)
                if found:
                    results = found
                    show_results(results)
            continue

        print()
        session_status(cipher, settings, results)
        option(1, "Try another combination / settings", "(same ciphertext)")
        if settings:
            option(2, "Repeat the last search", "(fresh random starts; adds to the results)")
        if results:
            option(3, "Show results again")
            option(4, "Save results to a file")
        option(5, "Show ciphertext statistics and hints")
        option(6, "Enter a new ciphertext")
        option(7, "Make a test ciphertext")
        option(0, "Back to main menu")
        choice = input("Select: ").strip()

        if choice == '1':
            new_settings = configure(cipher, settings)
            if new_settings:
                settings = new_settings
                found = execute(cipher, settings)
                if found:
                    results = sorted(results + found, key=lambda r: -r['score'])
                    show_results(found)
        elif choice == '2' and settings:
            found = execute(cipher, settings)
            if found:
                results = sorted(results + found, key=lambda r: -r['score'])
                show_results(found)
        elif choice == '3' and results:
            show_results(results)
        elif choice == '4' and results:
            save_results(results)
        elif choice == '5':
            print(f"\n{codes_to_text(cipher)}")
            print_hints(cipher)
        elif choice == '6':
            new_cipher = ask_ciphertext()
            if new_cipher:
                cipher, settings, results = new_cipher, None, []
                print_hints(cipher)
        elif choice == '7':
            made = make_test_cipher()
            if made and input("\nSwitch to this test ciphertext? ([Y]/n): ").strip().lower() != 'n':
                cipher, settings, results = text_to_codes(made), None, []
                print_hints(cipher)
        elif choice in ('0', 'q', 'Q'):
            return
        else:
            print(f"{RED}Invalid choice.{RESET}")


if __name__ == "__main__":
    run()
