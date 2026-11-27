"""Known-Plaintext Columnar Search: columnar transposition + periodic key.

Given a ciphertext and some known plaintext letters at known positions, tests
every column order of every width in a range (4 layouts), with a periodic
Vigenere/Beaufort key of every length in a range, in both layer orders, and
keeps the hypotheses on which every known letter agrees. See native/crib.py for
the method. Runs in C, or on the GPU when enabled (menu 91); the C engines
must be built.
"""
import math
import time

from theme import BLUE, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner

from native import crib

KEYWORD_EXAMPLE = "ZEBRAS"


def keyed_alphabet(keyword):
    seen = []
    for ch in keyword.upper() + crib.ALPHABET:
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    return "".join(seen)


def parse_known(text):
    """'WORD@12, OTHER@40' (1-indexed positions) -> sorted [(0-indexed position, letter)]."""
    known = {}
    for item in text.split(","):
        item = item.strip().upper()
        if not item:
            continue
        word, _, position = item.partition("@")
        start = int(position) - 1
        for offset, letter in enumerate(word):
            if not letter.isalpha():
                continue
            if known.get(start + offset, letter) != letter:
                raise ValueError(f"two different letters at position {start + offset + 1}")
            known[start + offset] = letter
    return sorted(known.items())


def parse_range(text, default):
    """'5', '3-9' or '9-3' (either order). Raises ValueError for anything else."""
    text = text.strip()
    if not text:
        return default
    if "-" in text:
        low, _, high = text.partition("-")
        low, high = int(low), int(high)
        return range(min(low, high), max(low, high) + 1)
    return range(int(text), int(text) + 1)


def describe_key(key):
    """Key values (0-25, or None where no known letter fixes the slot) as letters, '?' for unknown."""
    if not key:
        return "-"
    return "".join("?" if value is None else crib.ALPHABET[value] if isinstance(value, int) else str(value)
                   for value in key)


def run_search(ciphertext, known, widths, periods, alphabets, min_checks=None, engine="auto", report=print):
    """Returns (records, tests, min_checks, combos). records: list of dict hits."""
    from ngram_scoring import text_to_codes
    codes = text_to_codes(ciphertext)
    crib_pos = [p for p, _ in known]
    crib_plain = [ord(letter) - 65 for _, letter in known]
    if not crib_pos or max(crib_pos) >= len(codes):
        raise ValueError("known plaintext positions must lie inside the ciphertext")
    combos = crib.make_combos(alphabets)
    valtab = crib.value_table(combos, crib_plain)
    periods = list(periods)
    tests = sum(math.factorial(w) for w in widths) * len(crib.LAYOUTS) * len(periods) * len(combos) * 2
    if min_checks is None:
        min_checks = crib.default_min_checks(tests)
    hits = []
    for width in widths:
        for mode in crib.LAYOUTS:
            started = time.time()
            records, orders = crib.search(codes, crib_pos, valtab, len(combos), width, mode, (), periods, min_checks,
                                          engine=engine)
            report(f"{GREY}width {width:>2} {mode:<21} {orders:>12,} column orders  {len(records):>5} hits  "
                   f"{time.time() - started:6.1f}s{RESET}")
            for column_order, combo, order, period, checks in records:
                plaintext, key = crib.decrypt(codes, crib_pos, crib_plain, combos[combo], width, mode, column_order,
                                              order, period)
                hits.append({"width": width, "layout": mode, "column_order": column_order, "combo": combos[combo][0],
                             "order": crib.ORDERS[order], "period": period, "checks": checks, "key": key,
                             "plaintext": plaintext})
    hits.sort(key=lambda h: -h["checks"])
    return hits, tests, min_checks, combos


def run():
    banner("Known-Plaintext Columnar Search", "Columnar transposition + periodic key, consistent with known letters")
    from native import gpu
    import native
    engine = "GPU" if gpu.enabled() else ("C" if native.available() else "not built")
    print(f"{GREY}Engine: {engine} (menu 91 builds the C engines and enables the GPU){RESET}")
    ciphertext = input("Ciphertext: ").strip()
    known_text = input("Known plaintext as WORD@position, comma-separated (1-indexed), e.g. ATTACK@12: ")
    try:
        known = parse_known(known_text)
        widths = parse_range(input("Column counts to test [2-8]: "), range(2, 9))
        periods = parse_range(input("Key lengths to test [1-20]: "), range(1, 21))
    except ValueError as error:
        print(f"{RED}{error or 'Could not read that range.'}{RESET}")
        return
    if min(widths) < 2 or min(periods) < 1:
        print(f"{RED}Column counts start at 2 and key lengths at 1.{RESET}")
        return
    orders = sum(math.factorial(w) for w in widths)
    if orders > 50_000_000:
        print(f"{YELLOW}Widths {min(widths)}-{max(widths)} mean {orders:,} column orders per layout, key length and "
              f"alphabet: hours even in C (width 12 alone is 479 million).{RESET}")
        if input("Continue anyway? (y/[N]): ").strip().lower() != "y":
            return
    alphabets = {"AZ": crib.ALPHABET}
    keyword = input(f"Keyword for a keyed alphabet (optional, e.g. {KEYWORD_EXAMPLE}): ").strip().upper()
    if keyword:
        alphabets["KW"] = keyed_alphabet(keyword)
    started = time.time()
    try:
        hits, tests, min_checks, combos = run_search(ciphertext, known, widths, periods, alphabets)
    except ValueError as error:
        print(f"{RED}{error}{RESET}")
        return
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}")
        return
    print(f"\n{BLUE}{tests:,} hypotheses tested in {time.time() - started:.1f}s; kept those with at least "
          f"{min_checks} agreeing known letters (expected chance hits: "
          f"{crib.expected_chance(tests, min_checks):.2g}).{RESET}")
    if not hits:
        print(f"{YELLOW}No consistent hypothesis.{RESET}")
        return
    for rank, hit in enumerate(hits[:20], start=1):
        print(f"\n{CYAN}#{rank}{RESET} checks {GREEN}{hit['checks']}{RESET} | width {hit['width']} {hit['layout']} "
              f"order {hit['column_order']} | {hit['combo']} | {hit['order']} | key length {hit['period']}")
        print(f"   key {YELLOW}{describe_key(hit['key'])}{RESET}")
        print(f"   {hit['plaintext']}")
    print(f"\n{GREY}'?' marks letters whose key slot holds no known letter. Each agreement is a 1-in-26 event "
          f"for a wrong hypothesis, so judge hits by whether the rest of the text reads.{RESET}")


if __name__ == "__main__":
    run()
