"""Tool 21: Vigenere / Beaufort auto-solver (key length in C, per-column
frequency fit of each key letter)."""
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner


def run():
    """Key length from the column IoC (tested against shuffled copies of the
    text), then each key letter from letter frequencies, for Vigenere and
    Beaufort. Every candidate is judged against English of the same length."""
    import cipher_profile as cp
    from ngram_scoring import text_to_codes

    banner("Vigenere Auto-Solver", "Key length plus per-column frequency analysis (Vigenere and Beaufort)")
    ciphertext = input(f"{GREY}Enter Vigenère ciphertext: {RESET}")
    codes = text_to_codes(ciphertext)
    if len(codes) < cp.MIN_LETTERS:
        print(f"{RED}Need at least {cp.MIN_LETTERS} letters.{RESET}")
        return
    default_max = max(2, min(40, len(codes) // 5))
    text = input(f"Longest key length to test (Enter = {YELLOW}{default_max}{RESET}): ").strip()
    max_period = int(text) if text.isdigit() and int(text) >= 2 else default_max
    max_period = min(max_period, len(codes) // 2)

    print(f"\n{YELLOW}Testing key lengths 2-{max_period}...{RESET}")
    rows = cp.periodicity(codes, max_period)
    found = cp.likely_periods(rows)
    ranked = sorted(rows[1:], key=lambda row: -row['z'])
    print(f"{GREY}Column IoC per key length (z = standard deviations above shuffled copies; "
          f"significant at z >= {cp.z_threshold(max_period - 1):.2f}):{RESET}")
    for row in ranked[:6]:
        mark = f"{GREEN}significant{RESET}" if row['signal'] else f"{GREY}not significant{RESET}"
        print(f"  length {YELLOW}{row['period']:>2}{RESET}  column IoC {row['ioc']:.4f}  z {row['z']:5.1f}  {mark}")
    periods = found[:3] if found else [row['period'] for row in ranked[:3]]
    if not found:
        print(f"{YELLOW}No key length stands out: this may not be a periodic cipher, or the key is longer than "
              f"{max_period}. Trying the three strongest lengths anyway.{RESET}")

    refs = cp.references(len(codes))
    candidates = cp.attack_periodic(codes, cp.fitness_function(), periods)
    print(f"\n{YELLOW}Best decryptions{RESET} {GREY}(judged against {len(codes)}-letter English and shuffled text):{RESET}")
    for rank, candidate in enumerate(candidates[:4], start=1):
        verdict = cp.judge(candidate.fitness, refs)
        colour = GREEN if verdict == "reads as English" else YELLOW if verdict == "partly English" else GREY
        print(f"\n{rank}. {candidate.method}, {candidate.key}  fitness {candidate.fitness:.1f} {colour}[{verdict}]{RESET}")
        print(f"   {candidate.plaintext}")
    if cp.judge(candidates[0].fitness, refs) != "reads as English":
        print(f"\n{YELLOW}Not solved. A partly English result usually has a few wrong key letters (short columns): "
              f"anneal that key length in tool 22. A mixed alphabet (Quagmire) needs tool 26, or tool 61, combination 4 or 5.{RESET}")