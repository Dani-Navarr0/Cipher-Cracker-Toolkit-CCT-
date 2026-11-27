"""Periodic ciphers on keyword-mixed alphabets (Quagmire I, II, III), with
every dictionary word tried as the alphabet keyword.

A keyword alphabet is the keyword's distinct letters followed by the rest of
the alphabet in order (KRYPTOS -> KRYPTOSABCDEFGHIJLMNQUVWXZ, as on Kryptos).

    encrypt c = CA[(PA.index(p) + k) mod 26]      (Vigenere-style)
    Quagmire I:   PA = keyword alphabet, CA = straight
    Quagmire II:  PA = straight,         CA = keyword alphabet
    Quagmire III: PA = CA = keyword alphabet (Kryptos K1/K2)
    (Beaufort-style: c = CA[(k - PA.index(p)) mod 26])

For a given alphabet and period, every column's shift is chosen by letter
frequencies (chi-squared), so only the alphabet is searched. The C kernel
scores every dictionary alphabet; the best are decrypted and ranked by n-grams.
Quagmire IV (two different keyword alphabets) is not searched exhaustively.
"""
import os

from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner, option

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
WORDLIST = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")
ENGLISH = [8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61,
           6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07]
EXPECTED = [f / 100 for f in ENGLISH]
MODES = {1: "Quagmire I (keyed plaintext alphabet)", 2: "Quagmire II (keyed cipher alphabet)",
         3: "Quagmire III (both keyed, like Kryptos)"}
STORY_WORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "PROVENANCE", "PORTAL", "PELLEGRIN",
               "KNOT", "THREAD", "NEEDLE", "ARCHIVE", "ACCESSION", "UNRAVEL"]


def keyword_alphabet(word: str) -> str:
    seen = dict.fromkeys(ch for ch in word.upper() if ch in ALPHABET)
    return "".join(seen) + "".join(ch for ch in ALPHABET if ch not in seen)


def distinct_alphabets(words):
    """{alphabet: first word giving it}, straight alphabet excluded."""
    found = {}
    for word in words:
        alphabet = keyword_alphabet(word)
        if alphabet != ALPHABET:
            found.setdefault(alphabet, word)
    return found


def load_words(min_len=3, max_len=14):
    with open(WORDLIST, encoding="utf-8") as handle:
        words = [w.strip().upper() for w in handle if min_len <= len(w.strip()) <= max_len]
    return STORY_WORDS + words


def chi(counts, total):
    return sum((counts[p] - EXPECTED[p] * total) ** 2 / (EXPECTED[p] * total) for p in range(26))


def solve_alphabet(codes, period, alphabet, mode, variant):
    """Best key for one alphabet: (plaintext codes, key letters)."""
    pa = alphabet if mode in (1, 3) else ALPHABET
    ca = alphabet if mode in (2, 3) else ALPHABET
    ct_pos = [ca.index(ALPHABET[c]) for c in range(26)]
    pt_letter = [ord(ch) - 65 for ch in pa]
    plain = bytearray(len(codes))
    key = []
    for column in range(period):
        letters = codes[column::period]
        best = None
        for k in range(26):
            if variant == 0:
                table = bytes(pt_letter[(ct_pos[c] - k) % 26] for c in range(26)) + bytes(230)
            else:
                table = bytes(pt_letter[(k - ct_pos[c]) % 26] for c in range(26)) + bytes(230)
            decrypted = letters.translate(table)
            score = chi([decrypted.count(p) for p in range(26)], len(decrypted))
            if best is None or score < best[0]:
                best = (score, k, decrypted)
        key.append(ca[best[1]])
        plain[column::period] = best[2]
    return bytes(plain), "".join(key)


def _chi_chunk(args):
    """Every (mode, variant) for one slice of alphabets: {(mode, variant): scores}."""
    from native import fast
    counts, period, packed, combos = args
    return {combo: fast.keyed_periodic_chi(counts, period, packed, combo[0], combo[1], EXPECTED) for combo in combos}


def _parallel_chi(counts, period, packed, combos):
    """C kernel over all alphabets and combos, split across processes (one
    pool) for long lists. Returns {(mode, variant): scores} or None."""
    import native
    if not native.available():
        return None
    workers = max(1, (os.cpu_count() or 2) - 1)
    if len(packed) < 20_000 or workers == 1:
        return _chi_chunk((counts, period, packed, combos))
    from concurrent.futures import ProcessPoolExecutor
    size = -(-len(packed) // workers)
    chunks = [(counts, period, packed[i:i + size], combos) for i in range(0, len(packed), size)]
    with ProcessPoolExecutor(max_workers=workers) as pool:
        parts = list(pool.map(_chi_chunk, chunks))
    return {combo: [score for part in parts for score in part[combo]] for combo in combos}


def search(codes, period, alphabets, modes=(1, 2, 3), variants=(0, 1), keep=40, fitness=None):
    """Rank every (alphabet, mode, variant) by letter frequencies (C kernel, or
    Python for short lists), decrypt the best ``keep`` and rank by n-grams.
    Returns [(fitness, word, mode, variant, key, plaintext text)]."""
    from native import fast
    import cipher_profile as cp
    fitness = fitness or cp.fitness_function()
    alphabet_list = list(alphabets)
    packed = [bytes(ord(ch) - 65 for ch in a) for a in alphabet_list]
    counts = [[codes[column::period].count(c) for c in range(26)] for column in range(period)]
    ranked = []
    combos = [(mode, variant) for mode in modes for variant in variants]
    native_scores = _parallel_chi(counts, period, packed, combos)
    for mode in modes:
        for variant in variants:
            scores = native_scores[(mode, variant)] if native_scores else None
            if scores is None:          # Python fallback (slow: keep the list short)
                scores = []
                for alphabet in alphabet_list:
                    plain, _ = solve_alphabet(codes, period, alphabet, mode, variant)
                    scores.append(chi([plain.count(p) for p in range(26)], len(plain)) * period)
            ranked += [(score, i, mode, variant) for i, score in enumerate(scores)]
    ranked.sort()
    results, seen = [], set()
    for score, i, mode, variant in ranked[:keep]:
        alphabet = alphabet_list[i]
        plain, key = solve_alphabet(codes, period, alphabet, mode, variant)
        if plain in seen:
            continue
        seen.add(plain)
        from ngram_scoring import codes_to_text
        results.append((fitness(plain), alphabets[alphabet], mode, variant, key, codes_to_text(plain)))
    results.sort(key=lambda r: -r[0])
    return results


def run():
    import native
    import cipher_profile as cp
    from ngram_scoring import text_to_codes
    banner("Quagmire / Keyword-Alphabet Periodic", "Every dictionary word as the alphabet keyword, Quagmire I-III")
    codes = text_to_codes(input(f"{GREY}Enter ciphertext: {RESET}"))
    if len(codes) < cp.MIN_LETTERS:
        print(f"{RED}Need at least {cp.MIN_LETTERS} letters.{RESET}")
        return
    rows = cp.periodicity(codes, max(2, min(30, len(codes) // 6)))
    found = cp.likely_periods(rows)
    default = found[0] if found else None
    hint = f"Enter = {default}, the likely key length found" if default else "no key length stands out; give one"
    text = input(f"Key length(s), e.g. 6 or 4-8 ({hint}): ").strip()
    if text:
        low, _, high = text.partition("-")
        periods = list(range(int(low), int(high or low) + 1)) if low.isdigit() and (not high or high.isdigit()) else []
    else:
        periods = [default] if default else []
    if not periods:
        print(f"{RED}No key length.{RESET}")
        return
    option(1, "Dictionary words + Kryptos/story words", "(default; needs the C engines for speed)")
    option(2, "Only Kryptos/story words", "(fast in Python)")
    option(3, "My own keywords")
    choice = input("Select (Enter = 1): ").strip() or "1"
    if choice == "3":
        words = [w.strip().upper() for w in input("Keywords (comma-separated): ").split(",") if w.strip()]
    elif choice == "2" or not native.available():
        if choice == "1":
            print(f"{YELLOW}C engines not built (menu 45): using the short list only.{RESET}")
        words = STORY_WORDS
    else:
        words = load_words()
    alphabets = distinct_alphabets(words)
    print(f"{GREY}{len(alphabets):,} distinct keyword alphabets x 3 Quagmire types x Vigenere/Beaufort x "
          f"{len(periods)} key length(s)...{RESET}")
    refs = cp.references(len(codes))
    results = []
    for period in periods:
        results += [(r, period) for r in search(codes, period, alphabets)]
    results.sort(key=lambda entry: -entry[0][0])
    print(f"\n{BOLD}Best results{RESET} {GREY}(fitness: higher = more English){RESET}")
    for (score, word, mode, variant, key, plain), period in results[:10]:
        verdict = cp.judge(score, refs)
        colour = GREEN if verdict == "reads as English" else YELLOW if verdict == "partly English" else GREY
        print(f"\n{CYAN}{MODES[mode]}{RESET}, {'Vigenere' if variant == 0 else 'Beaufort'}, alphabet keyword "
              f"{YELLOW}{word}{RESET} ({keyword_alphabet(word)}), period {period}, key {YELLOW}{key}{RESET}")
        print(f"   fitness {score:.1f} {colour}[{verdict}]{RESET}  {plain[:100]}")


if __name__ == "__main__":
    run()
