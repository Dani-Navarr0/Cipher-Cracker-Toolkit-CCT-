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


def _shifts_kernel():
    import ctypes
    import native
    i32 = ctypes.c_int32
    return native.function("cct_keyed_periodic_shifts", None,
                           [ctypes.POINTER(i32), i32, ctypes.c_char_p, i32, i32, ctypes.POINTER(ctypes.c_double),
                            ctypes.POINTER(i32)])


def column_counts(codes, period):
    """Cipher-letter counts of every column (period lists of 26)."""
    return [[codes[column::period].count(c) for c in range(26)] for column in range(period)]


def solve_alphabet(codes, period, alphabet, mode, variant):
    """Best key for one alphabet: (plaintext codes, key letters). Each column's
    shift is the one whose decryption is closest to English letter frequencies
    (chi-squared, chosen in C: cct_keyed_periodic_shifts); then one decryption."""
    import ctypes
    pa = alphabet if mode in (1, 3) else ALPHABET
    ca = alphabet if mode in (2, 3) else ALPHABET
    ct_pos = [ca.index(ALPHABET[c]) for c in range(26)]
    pt_letter = [ord(ch) - 65 for ch in pa]
    counts = (ctypes.c_int32 * (26 * period))(*[x for column in column_counts(codes, period) for x in column])
    shifts = (ctypes.c_int32 * period)()
    _shifts_kernel()(counts, period, bytes(ord(ch) - 65 for ch in alphabet), mode, variant,
                     (ctypes.c_double * 26)(*EXPECTED), shifts)
    plain = bytearray(len(codes))
    key = []
    for column, k in enumerate(shifts):
        if variant == 0:
            table = bytes(pt_letter[(ct_pos[c] - k) % 26] for c in range(26)) + bytes(230)
        else:
            table = bytes(pt_letter[(k - ct_pos[c]) % 26] for c in range(26)) + bytes(230)
        plain[column::period] = codes[column::period].translate(table)
        key.append(ca[k])
    return bytes(plain), "".join(key)


def _best_kernel():
    import ctypes
    import native
    i32, f64 = ctypes.c_int32, ctypes.c_double
    return native.function("cct_keyed_periodic_best", i32,
                           [ctypes.POINTER(i32), i32, ctypes.c_char_p, i32, i32, i32, i32, ctypes.POINTER(f64), i32,
                            ctypes.POINTER(f64), ctypes.POINTER(i32)])


_PACK = bytes.maketrans(ALPHABET.encode(), bytes(range(26)))


def _best_chi(counts, period, packed, count, combos, keep):
    """The ``keep`` lowest total chi-squared values of every (mode, variant) in
    ``combos`` over ``count`` packed alphabets (26 letter codes each), from the C
    kernel; long lists are split over threads (the C call releases the GIL).
    Returns [(chi, alphabet index, mode, variant)], unsorted."""
    import ctypes
    from concurrent.futures import ThreadPoolExecutor
    import native
    native.require()
    kernel = _best_kernel()
    flat = (ctypes.c_int32 * (26 * period))(*[x for column in counts for x in column])
    expected = (ctypes.c_double * 26)(*EXPECTED)
    import compute
    workers = compute.workers() if count >= 20_000 else 1
    size = -(-count // workers) if count else 1

    def job(task):
        (mode, variant), start = task
        part = packed[26 * start:26 * min(count, start + size)]
        chi, index = (ctypes.c_double * keep)(), (ctypes.c_int32 * keep)()
        kept = kernel(flat, period, part, len(part) // 26, start, mode, variant, expected, keep, chi, index)
        if kept < 0:
            raise MemoryError("keyed periodic search: out of memory")
        return [(chi[j], index[j], mode, variant) for j in range(kept)]

    tasks = [(combo, start) for combo in combos for start in range(0, count, size)]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [entry for part in pool.map(job, tasks) for entry in part]


def search(codes, period, alphabets, modes=(1, 2, 3), variants=(0, 1), keep=40, fitness=None):
    """Rank every (alphabet, mode, variant) by letter frequencies (C kernel),
    decrypt the best ``keep`` and rank by n-grams.
    Returns [(fitness, word, mode, variant, key, plaintext text)].
    Raises ValueError for a period outside 1..len(codes)."""
    import cipher_profile as cp
    if not 1 <= period <= len(codes):
        raise ValueError(f"Key length {period} is outside 1-{len(codes)} (the text length).")
    if keep < 1:
        return []
    from ngram_scoring import codes_to_text
    fitness = fitness or cp.fitness_function()
    alphabet_list = list(alphabets)
    packed = "".join(alphabet_list).encode("ascii").translate(_PACK)
    combos = [(mode, variant) for mode in modes for variant in variants]
    ranked = sorted(_best_chi(column_counts(codes, period), period, packed, len(alphabet_list), combos, keep))
    results, seen = [], set()
    for score, i, mode, variant in ranked[:keep]:
        alphabet = alphabet_list[i]
        plain, key = solve_alphabet(codes, period, alphabet, mode, variant)
        if plain in seen:
            continue
        seen.add(plain)
        results.append((fitness(plain), alphabets[alphabet], mode, variant, key, codes_to_text(plain)))
    results.sort(key=lambda r: -r[0])
    return results


def run():
    import native
    import cipher_profile as cp
    from ngram_scoring import text_to_codes
    native.require()
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
    if not all(1 <= period <= len(codes) for period in periods):
        print(f"{RED}Key lengths must be 1-{len(codes)} (the number of letters).{RESET}")
        return
    option(1, "Dictionary words + Kryptos/story words", "(default)")
    option(2, "Only Kryptos/story words", "(instant)")
    option(3, "My own keywords")
    choice = input("Select (Enter = 1): ").strip() or "1"
    if choice == "3":
        words = [w.strip().upper() for w in input("Keywords (comma-separated): ").split(",") if w.strip()]
    elif choice == "2":
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
