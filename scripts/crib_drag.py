"""Crib dragging: slide a probable plaintext word along the ciphertext and read
the key fragment it implies at every position.

* Vigenere:          key = C - P
* Beaufort:          key = C + P   (P = K - C)
* Variant Beaufort:  key = P - C

Positions are ranked by how English the key fragment looks (n-gram score),
which is how a running key (a book text) or a word key shows up. A fragment
that repeats itself with a short period points to a periodic key of that length.
"""
from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner, option

VARIANTS = {
    "vigenere": ("Vigenere", lambda c, p: (c - p) % 26),
    "beaufort": ("Beaufort", lambda c, p: (c + p) % 26),
    "variant": ("Variant Beaufort", lambda c, p: (p - c) % 26),
}


def key_fragment(cipher, crib, variant):
    rule = VARIANTS[variant][1]
    return "".join(chr(65 + rule(ord(c) - 65, ord(p) - 65)) for c, p in zip(cipher, crib))


def self_period(fragment, min_confirmations=2):
    """Smallest p with fragment[i] == fragment[i+p] for every i, confirmed by at
    least ``min_confirmations`` letter pairs (len - p), else None. With two
    confirmations a random fragment passes about once in 676 per period."""
    for period in range(1, len(fragment) - min_confirmations + 1):
        if all(fragment[i] == fragment[i + period] for i in range(len(fragment) - period)):
            return period
    return None


def drag(ciphertext, crib, variants=tuple(VARIANTS)):
    """Every position and variant: (score, position, variant, fragment, period).
    Higher score = the fragment looks more like English text."""
    from ngram_scoring import load_ngram_scores, resolve_ngram_path, ngram_total, text_to_codes
    model = load_ngram_scores(resolve_ngram_path(3))
    rows = []
    for position in range(len(ciphertext) - len(crib) + 1):
        piece = ciphertext[position:position + len(crib)]
        for variant in variants:
            fragment = key_fragment(piece, crib, variant)
            codes = text_to_codes(fragment)
            windows = len(codes) - model.size + 1
            score = ngram_total(codes, model.scores, model.size) / windows if windows > 0 else 0.0
            rows.append((score, position, variant, fragment, self_period(fragment)))
    rows.sort(key=lambda row: -row[0])
    return rows


def run():
    banner("Crib Dragging", "Slide a probable word along the ciphertext; rank the key fragments it implies")
    ciphertext = "".join(ch for ch in input(f"{GREY}Enter ciphertext: {RESET}").upper() if "A" <= ch <= "Z")
    crib = "".join(ch for ch in input(f"{GREY}Enter suspected plaintext word (the 'crib'): {RESET}").upper()
                   if "A" <= ch <= "Z")
    if len(crib) < 3 or len(crib) > len(ciphertext):
        print(f"{RED}The crib needs at least 3 letters and must be shorter than the ciphertext.{RESET}")
        return
    option(1, "Vigenere, Beaufort and Variant Beaufort", "(default)")
    option(2, "Vigenere only")
    option(3, "Beaufort only")
    choice = input("Select (Enter = 1): ").strip()
    variants = {"2": ("vigenere",), "3": ("beaufort",)}.get(choice, tuple(VARIANTS))

    rows = drag(ciphertext, crib, variants)
    print(f"\n{BOLD}Most English-looking key fragments{RESET} {GREY}({len(rows):,} position/variant pairs; "
          f"positions are 1-indexed){RESET}")
    print(f"{'Pos':>5}  {'Variant':<17} {'Key fragment':<{max(14, len(crib) + 2)}} Note")
    for score, position, variant, fragment, period in rows[:15]:
        note = f"{YELLOW}repeats every {period}: periodic key of length {period}?{RESET}" if period else ""
        print(f"{position + 1:>5}  {VARIANTS[variant][0]:<17} {GREEN}{fragment:<{max(14, len(crib) + 2)}}{RESET} {note}")
    periodic = sorted((row for row in rows if row[4]), key=lambda row: (-(len(crib) - row[4]), -row[0]))
    if periodic:
        print(f"\n{CYAN}Fragments that repeat themselves{RESET} {GREY}(where a periodic key would repeat inside "
              f"the crib; more confirming letters = less likely chance; try that key length in tools 1, 13 or 30):{RESET}")
        for score, position, variant, fragment, period in periodic[:8]:
            print(f"  position {position + 1}, {VARIANTS[variant][0]}: {fragment} (period {period}, "
                  f"{len(crib) - period} letters confirm)")
    print(f"\n{GREY}A real word or text fragment as the key means a word key or a running key (tool 16). "
          f"Short cribs (under ~6 letters) give many chance words.{RESET}")
    if input("Show every position? (y/[N]): ").strip().lower() == "y":
        for score, position, variant, fragment, period in sorted(rows, key=lambda row: (row[1], row[2])):
            print(f"{position + 1:>5}  {VARIANTS[variant][0]:<17} {fragment}")


if __name__ == "__main__":
    run()
