"""Unknown Cipher Analyzer: a ciphertext with no clues -> statistics, ranked
attack pathways (which tools to open, with what settings), instant attacks,
and optional hill-climbing with the Two-Layer annealing engine.

The statistics and decision rules live in ``cipher_profile``; this module is
the interactive front end.
"""
import importlib
import os
import random
import re
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime

import cipher_profile as cp
import session
from layered import ALPHABET, TranspositionLayer
from ngram_scoring import (
    DEFAULT_NGRAM_PATH, add_spaces, available_spacing_models, codes_to_text, load_spacing_model,
)
from theme import BLUE, BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner, option, rule, width
from two_layer import ask_int, describe_combo, measure_step_time, solve_job

NGRAM_PATH = str(DEFAULT_NGRAM_PATH)
STRENGTH_COLOURS = {"solved": GREEN, "strong": GREEN, "possible": YELLOW, "long shot": GREY}
_ANSI = re.compile(r"\033\[[0-9;?]*[A-Za-z]")


class Report:
    """Collects printed lines so the whole analysis can be saved to a file."""

    def __init__(self):
        self.lines = []

    def __call__(self, text=""):
        print(text)
        self.lines.append(text)

    def section(self, title):
        self(f"\n{BLUE}{BOLD}{title}{RESET}")
        self(f"{GREY}{'─' * width()}{RESET}")

    def plain(self) -> str:
        return "\n".join(_ANSI.sub("", line) for line in self.lines) + "\n"


def wrap(text, indent="    ", first=""):
    """Word-wrap to the terminal width."""
    limit = max(30, width() - len(indent))
    words, lines, line = text.split(), [], ""
    for word in words:
        if line and len(line) + 1 + len(word) > limit:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    if line:
        lines.append(line)
    return "\n".join((first if i == 0 and first else indent) + l for i, l in enumerate(lines))


# ------------------------------------------------------------------ input

def ask_ciphertext():
    """Multi-line paste or a .txt path; Enter alone uses the session ciphertext."""
    current = session.get_ciphertext()
    if current:
        print(f"\n{GREY}Session ciphertext: {session.summary(60)}{RESET}")
        if input("Analyze it? ([Y]/n): ").strip().lower() != "n":
            return current
    return session.read_text()


# ------------------------------------------------------------------ blind test ciphers

def _columnar_encrypt(codes, width_, order, mode="write_rows_read_cols"):
    layer = TranspositionLayer(len(codes), width_, mode)
    layer.key[:] = order
    low = layer.decrypt(bytes(i % 256 for i in range(len(codes))))
    high = layer.decrypt(bytes(i // 256 for i in range(len(codes))))
    out = bytearray(len(codes))
    for target, (h, l) in enumerate(zip(high, low)):
        out[h * 256 + l] = codes[target]
    return bytes(out)


def _substitute(rng, codes):
    table = rng.sample(range(26), 26)
    return codes.translate(bytes(table) + bytes(230)), "".join(ALPHABET[c] for c in table)


def make_blind_test(length):
    """A random English passage under a randomly chosen cipher. Returns
    (ciphertext, description) - the description is shown only on request."""
    rng = random.Random()
    corpus = cp.english_corpus()
    start = rng.randrange(0, len(corpus) - length)
    plain = corpus[start:start + length]
    kind = rng.choice(["caesar", "affine", "substitution", "columnar", "rail", "vigenere", "beaufort",
                       "autokey", "sub+columnar", "quagmire"])
    if kind == "caesar":
        shift = rng.randrange(1, 26)
        cipher, what = bytes((c + shift) % 26 for c in plain), f"Caesar, shift {shift}"
    elif kind == "affine":
        a, b = rng.choice([3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]), rng.randrange(26)
        cipher, what = bytes((a * c + b) % 26 for c in plain), f"Affine, a={a}, b={b}"
    elif kind == "substitution":
        cipher, table = _substitute(rng, plain)
        what = f"Simple substitution, plain A-Z -> {table}"
    elif kind in ("columnar", "sub+columnar"):
        width_ = rng.randint(5, 12)
        order = rng.sample(range(width_), width_)
        source, what = plain, ""
        if kind == "sub+columnar":
            source, table = _substitute(rng, plain)
            what = f"Simple substitution (A-Z -> {table}), then "
        cipher = _columnar_encrypt(source, width_, order)
        what += f"columnar transposition, width {width_}, column order {order}"
    elif kind == "rail":
        rails = rng.randint(3, 9)
        order = cp.rail_fence_order(len(plain), rails)
        cipher, what = bytes(plain[p] for p in order), f"Rail fence, {rails} rails"
    elif kind in ("vigenere", "beaufort", "quagmire"):
        period = rng.randint(3, 10)
        key = [rng.randrange(26) for _ in range(period)]
        source, what = plain, ""
        if kind == "quagmire":
            source, table = _substitute(rng, plain)
            what = f"Simple substitution (A-Z -> {table}), then "
        if kind == "beaufort":
            cipher = bytes((key[i % period] - c) % 26 for i, c in enumerate(source))
        else:
            cipher = bytes((c + key[i % period]) % 26 for i, c in enumerate(source))
        what += f"{'Beaufort' if kind == 'beaufort' else 'Vigenere'}, key {''.join(ALPHABET[k] for k in key)} (period {period})"
    else:
        primer = [rng.randrange(26) for _ in range(rng.randint(3, 7))]
        keystream = primer + list(plain)
        cipher = bytes((c + keystream[i]) % 26 for i, c in enumerate(plain))
        what = f"Autokey (plaintext autokey, Vigenere), primer {''.join(ALPHABET[k] for k in primer)}"
    return codes_to_text(cipher), f"{what}\nPlaintext: {codes_to_text(plain)}"


# ------------------------------------------------------------------ display

def show_statistics(p: cp.Profile, out: Report):
    s, r, n = p.stats, p.refs, p.length
    out.section("1. What the text looks like")
    for note in p.prepared.notes:
        out(wrap(note, "  ", "  "))
    if p.prepared.regrouped:
        out(wrap(f"{CYAN}{p.prepared.regrouped}{RESET}", "  ", "  "))
    preview = codes_to_text(p.prepared.codes)
    out(f"  Letters: {YELLOW}{n}{RESET}   distinct: {YELLOW}{s['distinct']}{RESET}"
        f"{f'   missing: {YELLOW}' + s['missing'] + RESET if s['missing'] else ''}")
    factors = cp.divisors(n, 2, n)
    out(f"  Length factors: {YELLOW}{', '.join(map(str, factors)) or 'none (prime)'}{RESET}"
        f"   {GREY}(grid widths that fill a complete rectangle){RESET}")
    out(f"  {GREY}{preview[:width() - 4]}{'...' if len(preview) > width() - 4 else ''}{RESET}")

    out.section(f"2. Letter statistics vs {n}-letter references")
    out(f"  {GREY}Each value is compared with {cp.REFERENCE_SAMPLES} English passages of the same length, random "
        f"letters, and shuffled English.{RESET}")
    header = f"  {'Statistic':<22}{'Value':>9}  {'English (2nd-98th pct)':>24}  {'Other reference':>22}"
    out(f"{BOLD}{header}{RESET}")

    def row(name, value, english, other, fmt):
        out(f"  {name:<22}{YELLOW}{value:>9{fmt}}{RESET}  "
            f"{english.quantile(cp.LOW_Q):>11{fmt}} - {english.quantile(cp.HIGH_Q):<10{fmt}}  {GREY}{other:>22}{RESET}")

    row("Index of coincidence", s['ioc'], r['english_ioc'], f"random 98th {r['random_ioc'].quantile(cp.HIGH_Q):.4f}", ".4f")
    row("Chi-sq vs English", s['chi'], r['english_chi'], "lower = English letters", ".0f")
    row("Adjacent-pair structure", s['adjacency'], r['english_adjacency'],
        f"shuffled 98th {r['shuffled_adjacency'].quantile(cp.HIGH_Q):.2f}", ".2f")
    row("N-gram fitness", max(s['fitness'], s['fitness_reversed']), r['english_fitness'],
        f"shuffled 98th {r['shuffled_fitness'].quantile(cp.HIGH_Q):.1f}", ".1f")
    f = p.flags
    readings = []
    readings.append("letter counts look English-like (substitution and/or transposition)" if f['counts_kept']
                    else "letter frequencies are flattened like random letters" if f['ioc_random']
                    else "letter frequencies are partly flattened (polyalphabetic, digraphic or fractionated)")
    if f['counts_kept']:
        readings.append("the letters are English letters" if f['letters_english'] else "the letters are disguised")
        readings.append("adjacent letters keep English structure" if f['order_english']
                        else "adjacent letters are as independent as shuffled text" if f['order_scrambled']
                        else "adjacent-letter structure is in between (inconclusive)")
    out(wrap("Reading: " + "; ".join(readings) + ".", "  ", "  "))

    out.section("3. Periodicity (polyalphabetic key length)")
    top = sorted(p.periods[1:], key=lambda row_: -row_['z'])[:6]
    out(f"  {GREY}IoC of every L-th letter. z = standard deviations above shuffled copies; a period passes when z >= "
        f"{cp.z_threshold(len(p.periods) - 1):.2f} (corrected for testing {len(p.periods) - 1} periods) and the "
        f"columns are English-like.{RESET}")
    out(f"{BOLD}  {'Period':>6}  {'Column IoC':>10}  {'z':>6}  {'English 2nd pct':>15}  Passes{RESET}")
    for row_ in top:
        passes = row_['signal'] and row_['english_like']
        out(f"  {row_['period']:>6}  {row_['ioc']:>10.4f}  {row_['z']:>6.1f}  {row_['english_low']:>15.4f}  "
            f"{GREEN + 'yes' + RESET if passes else GREY + 'no' + RESET}")
    if p.period_candidates:
        out(f"  Likely key length: {GREEN}{p.period_candidates[0]}{RESET}"
            f"{GREY} (all passing: {', '.join(map(str, p.period_candidates[:8]))}){RESET}")
    else:
        out(f"  {GREY}No period from 2 to {len(p.periods)} passes.{RESET}")
    friedman = cp.friedman_estimate(s['ioc'])
    kasiski = ", ".join(f"{k} ({v}x)" for k, v in p.kasiski[:5]) or "no repeated trigrams"
    out(f"  {GREY}Friedman estimate: {f'{friedman:.1f}' if friedman else 'unbounded'} | Kasiski factors: {kasiski}{RESET}")


def show_pathways(p: cp.Profile, out: Report):
    out.section("4. Attack pathways, most promising first")
    for index, pathway in enumerate(p.pathways, start=1):
        colour = STRENGTH_COLOURS[pathway.strength]
        out(f"\n  {BOLD}{index}. {pathway.title}{RESET}  {colour}[{pathway.strength}]{RESET}")
        for line in pathway.evidence:
            out(wrap(line, "       ", "     - "))
        for number, what in pathway.tools:
            out(wrap(what, "            ", f"     {YELLOW}{number:>3}{RESET}  "))
        if pathway.plan:
            out(f"     {CYAN}Hill-climb available here (menu option 3).{RESET}")
    if p.ruled_out:
        out.section("Ruled out")
        for what, why in p.ruled_out:
            out(wrap(f"{what}: {why}", "    ", "  - "))
    out(f"\n  {GREY}Strengths come from the rules above, not from a probability model: 'strong' means the statistics "
        f"point to it, 'possible' that they do not rule it out, 'long shot' that it is consistent but not indicated.{RESET}")


def show_candidates(candidates, refs, out: Report, title, limit=5):
    out.section(title)
    low = refs['english_fitness'].quantile(cp.LOW_Q)
    out(f"  {GREY}Verdicts compare the fitness with English of this length (2nd percentile {low:.1f}) and "
        f"shuffled text (98th percentile {refs['shuffled_fitness'].quantile(cp.HIGH_Q):.1f}).{RESET}")
    for rank, candidate in enumerate(candidates[:limit], start=1):
        verdict = cp.judge(candidate.fitness, refs)
        colour = GREEN if verdict == "reads as English" else YELLOW if verdict == "partly English" else GREY
        out(f"  {rank}. {BOLD}{candidate.method}{RESET} {GREY}{candidate.key}{RESET}")
        out(f"     fitness {YELLOW}{candidate.fitness:.1f}{RESET} {colour}[{verdict}]{RESET}  "
            f"{candidate.plaintext[:width() - 40]}{'...' if len(candidate.plaintext) > width() - 40 else ''}")


def spaced(text):
    models = available_spacing_models()
    english = next((m for m in models if m.parent.name.lower() == "english"), None)
    if not english or len(text) > 1500:
        return None
    return add_spaces(text, load_spacing_model(english))


# ------------------------------------------------------------------ hill-climbing

def choose_plan(p: cp.Profile):
    plans = [(pathway, plan) for pathway in p.pathways for plan in pathway.plan]
    if not plans:
        print(f"{YELLOW}No hill-climb is defined for these pathways; use the tools listed.{RESET}")
        return None
    print()
    for index, (pathway, plan) in enumerate(plans, start=1):
        option(index, plan.label, f"[{pathway.strength}] {pathway.title}")
    choice = input("Which search? (number, Enter = 1): ").strip() or "1"
    if not choice.isdigit() or not 1 <= int(choice) <= len(plans):
        print(f"{RED}Invalid choice.{RESET}")
        return None
    pathway, plan = plans[int(choice) - 1]
    plan = cp.AttackPlan(**{**plan.__dict__})
    if plan.layers == ("playfair",):
        return plan          # the Playfair annealer asks for its own budget
    if "trans" in plan.layers:
        default = f"{min(plan.widths)}-{max(plan.widths)}" if plan.widths else "8"
        text = input(f"Transposition widths (Enter = {YELLOW}{default}{RESET}, or e.g. 5-12): ").strip()
        if text:
            plan.widths = [w for w in ask_int_range_text(text) if 2 <= w < p.length] or plan.widths
        if len(plan.modes) == 1 and input("Try all four grid layouts? (y/[N]): ").strip().lower() == "y":
            plan.modes = list(cp.TRANSPOSITION_MODES)
    if "periodic" in plan.layers:
        text = input(f"Key period(s) (Enter = {YELLOW}{', '.join(map(str, plan.periods))}{RESET}, or e.g. 4-9): ").strip()
        if text:
            plan.periods = [q for q in ask_int_range_text(text) if q >= 1] or plan.periods
    plan.steps = ask_int("Annealing steps per run", plan.steps, minimum=1000)
    plan.runs = ask_int("Independent runs per parameter combination", plan.runs)
    return plan


def ask_int_range_text(text):
    match = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d+))?\s*", text)
    if not match:
        return []
    low, high = int(match.group(1)), int(match.group(2) or match.group(1))
    return list(range(min(low, high), max(low, high) + 1))


def run_plan(p: cp.Profile, plan: cp.AttackPlan):
    combos = plan.combos()
    if not combos:
        print(f"{RED}No parameter combinations.{RESET}")
        return []
    jobs = [{'cipher': p.prepared.codes, 'encryption': combo, 'iterations': plan.steps,
             'ngram_path': NGRAM_PATH, 'entropy_weight': 0.5, 'seed': random.randrange(2 ** 32),
             'label': describe_combo(combo)} for combo in combos for _ in range(plan.runs)]
    workers = max(1, min(len(jobs), (os.cpu_count() or 2) - 1))
    step = measure_step_time(jobs[0])
    estimate = step * plan.steps * len(jobs) / workers
    print(f"\n{BLUE}{len(jobs)} runs{RESET} ({len(combos)} combination(s) x {plan.runs}) of {plan.steps:,} steps on "
          f"{workers} process(es); measured {step * 1e6:.0f} us/step -> roughly {YELLOW}{estimate / 60:.1f}-"
          f"{2 * estimate / 60 + 0.1:.1f} min{RESET}. Ctrl+C stops and keeps the finished runs.")
    if input("Start? ([Y]/n): ").strip().lower() == "n":
        return []
    results, started = [], time.time()
    try:
        if workers == 1:
            for done, job in enumerate(jobs, start=1):
                results.append(solve_job(job))
                print(f"Run {done}/{len(jobs)} done", end="\r")
        else:
            with ProcessPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(solve_job, job) for job in jobs]
                for done, future in enumerate(as_completed(futures), start=1):
                    results.append(future.result())
                    best = max(results, key=lambda result: result['score'])
                    print(f"Run {done}/{len(jobs)} done | best fitness {best['score']:.1f} | "
                          f"{best['plaintext'][:36]}...", end="\r")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted; showing the runs that finished.{RESET}")
    print(f"\n{GREY}Finished in {(time.time() - started) / 60:.1f} min.{RESET}")
    results.sort(key=lambda result: -result['score'])
    return results


def show_climb_results(p: cp.Profile, results, out: Report):
    if not results:
        return
    best = results[0]
    verdict = cp.judge(best['score'], p.refs)
    agreeing = sum(1 for result in results if result['plaintext'] == best['plaintext'])
    out.section("Hill-climb result")
    colour = GREEN if verdict == "reads as English" else YELLOW if verdict == "partly English" else GREY
    out(f"  Best: {CYAN}{best['label']}{RESET}  fitness {YELLOW}{best['score']:.1f}{RESET} {colour}[{verdict}]{RESET}")
    for line in best['keys']:
        out(f"    {line}")
    out(f"  Runs reaching this same plaintext: {YELLOW}{agreeing}/{len(results)}{RESET} "
        f"{GREY}(independent runs agreeing is good evidence of a real solution; a single run is not){RESET}")
    out(wrap(best['plaintext'], "  ", "  "))
    with_spaces = spaced(best['plaintext']) if verdict != "not English" else None
    if with_spaces:
        out(f"  {GREY}With word spaces (automatic):{RESET}")
        out(wrap(f"{CYAN}{with_spaces}{RESET}", "  ", "  "))
    if verdict != "reads as English":
        out(wrap(f"{GREY}Not solved by this search. Annealing on a short text can climb to a few English-looking "
                 f"fragments by chance; more steps, more runs, or the next pathway may help.{RESET}", "  ", "  "))
    out(f"  {GREY}Other runs:{RESET}")
    for result in results[1:6]:
        out(f"    fitness {result['score']:.1f} | {result['label']} | {result['plaintext'][:width() - 50]}...")


# ------------------------------------------------------------------ tools

def open_tool(number, ciphertext):
    try:
        launcher = importlib.import_module("main")
        item = next(item for _, items in launcher.CATEGORIES for item in items if str(item[0]) == str(number))
    except (ImportError, StopIteration, AttributeError):
        print(f"{RED}Tool {number} not found.{RESET}")
        return
    session.install_input_hook()
    print(f"\n{GREY}The analyzed text is the session ciphertext: press Enter at the tool's ciphertext prompt "
          f"to use it.{RESET}\n")
    try:
        importlib.import_module(item[2]).run()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}")
    except Exception as error:  # a tool failing must not end the analyzer session
        print(f"{RED}The tool stopped with an error: {type(error).__name__}: {error}{RESET}")
    input(f"\n{GREY}Press Enter to return to the analyzer...{RESET}")


def save_report(out: Report):
    name = input("File name to save the report (Enter = cancel): ").strip()
    if not name:
        return
    if not name.endswith(".txt"):
        name += ".txt"
    with open(name, "w", encoding="utf-8") as handle:
        handle.write(f"Unknown Cipher Analyzer report, {datetime.now():%Y-%m-%d %H:%M}\n")
        handle.write(out.plain())
    print(f"{GREEN}Saved to {name}{RESET}")


# ------------------------------------------------------------------ session

def analyze(raw):
    print(f"{GREY}Measuring the text and its references (a few seconds)...{RESET}")
    started = time.time()
    p = cp.profile(raw, NGRAM_PATH)
    if p is None:
        print(f"{RED}Need at least {cp.MIN_LETTERS} letters (or symbol groups) to analyze.{RESET}")
        return None, None
    session.set_ciphertext(raw)
    out = Report()
    show_statistics(p, out)
    show_pathways(p, out)
    candidates = cp.run_instant_attacks(p, NGRAM_PATH)
    show_candidates(candidates, p.refs, out, "5. Instant attacks (Caesar/affine, routes, rail fence, small columnar, "
                                             "periodic by frequencies)")
    best = candidates[0]
    if cp.judge(best.fitness, p.refs) == "reads as English":
        out(f"\n  {GREEN}{BOLD}Likely solved by {best.method} ({best.key}).{RESET}")
        with_spaces = spaced(best.plaintext)
        if with_spaces:
            out(wrap(f"{CYAN}{with_spaces}{RESET}", "  ", "  "))
    if p.length < 100:
        out(f"\n  {YELLOW}Short text ({p.length} letters): the English and random references overlap more, so every "
            f"reading above is less certain.{RESET}")
    print(f"{GREY}({time.time() - started:.1f} s){RESET}")
    return p, out


def run():
    banner("Unknown Cipher Analyzer", "No clues? Statistics, ranked attack pathways, instant attacks and hill-climbing")
    print(wrap(f"{GREY}Every statistic is compared with English, random and shuffled texts of the same length, so "
               f"the verdicts adapt to short texts. Nothing here proves a cipher type; it ranks where to start.{RESET}",
               " ", " "))
    p = out = None
    raw = secret = ""
    while True:
        print()
        if p is not None:
            rule()
            top = p.pathways[0] if p.pathways else None
            print(f"{BOLD}Ciphertext{RESET} {GREY}({p.length} letters){RESET}"
                  + (f" | top pathway: {CYAN}{top.title}{RESET}" if top else ""))
            rule()
            option(1, "Analyze a new ciphertext")
            option(2, "Make a blind test ciphertext", "(random cipher, hidden until you reveal it)")
            option(3, "Hill-climb a pathway", "(annealing with the Two-Layer engine, uses every CPU core)")
            option(4, "Open a recommended tool", "(by menu number)")
            option(5, "Show the analysis again")
            option(6, "Save the report to a file")
            if secret:
                option(7, "Reveal the blind test cipher")
        else:
            option(1, "Analyze a ciphertext")
            option(2, "Make a blind test ciphertext", "(random cipher, hidden until you reveal it)")
        option(0, "Back to main menu")
        choice = input("Select: ").strip()

        if choice == "1":
            raw = ask_ciphertext()
            if raw.strip():
                secret = ""
                analyzed = analyze(raw)
                if analyzed[0]:
                    p, out = analyzed
        elif choice == "2":
            length = ask_int("Length in letters", 200, minimum=cp.MIN_LETTERS)
            raw, secret = make_blind_test(min(length, 5000))
            print(f"\n{GREEN}Ciphertext:{RESET}\n{raw}")
            analyzed = analyze(raw)
            if analyzed[0]:
                p, out = analyzed
        elif choice == "3" and p is not None:
            plan = choose_plan(p)
            if plan and plan.layers == ("playfair",):
                import playfair_anneal
                playfair_anneal.attack_interactive(codes_to_text(p.prepared.codes), plan.steps, plan.runs)
            elif plan:
                results = run_plan(p, plan)
                show_climb_results(p, results, out)
        elif choice == "4" and p is not None:
            numbers = list(dict.fromkeys(number for pathway in p.pathways for number, _ in pathway.tools))
            print(f"{GREY}Recommended, in order: {', '.join(map(str, numbers))}{RESET}")
            number = input("Tool number: ").strip()
            if number:
                open_tool(number, codes_to_text(p.prepared.codes))
        elif choice == "5" and p is not None:
            print("\n".join(out.lines))
        elif choice == "6" and p is not None:
            save_report(out)
        elif choice == "7" and secret:
            print(f"\n{CYAN}{secret}{RESET}")
        elif choice in ("0", "q", "Q"):
            return
        else:
            print(f"{RED}Invalid choice.{RESET}")


if __name__ == "__main__":
    run()
