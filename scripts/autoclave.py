"""Autokey (autoclave) cipher: decrypt, encrypt, a primer search that needs
no word list, and a word-list primer search (both in C).

Two kinds of autokey, each with a Vigenere or Beaufort tableau:

* Plaintext autokey: the key is the primer followed by the plaintext.
* Ciphertext autokey: the key is the primer followed by the ciphertext.

Why the primer-free attacks work:

* Ciphertext autokey: after the first L letters every key letter is a
  ciphertext letter, which is public. So for each primer length L
  everything after position L decrypts with no search at all; only the
  first L letters (the primer's) are then fitted.
* Plaintext autokey: plaintext position i depends only on plaintext
  position i - L, so the text splits into L independent chains
  (positions j, j+L, j+2L, ...), each fixed by ONE primer letter: 26
  choices per chain. Each chain is fitted by letter frequencies, then all
  chains together are hill-climbed on n-gram fitness.

The word-list search (dictionary_attack, scripts/native/keystream_dict.c)
tries every word as the primer for both kinds and both tableaux and ranks by
the same fitness. It helps on short texts, where the primer-free search often
returns a wrong primer because each chain has only a few letters.
"""
import os
from functools import lru_cache

from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner, option

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
WORDLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "words_alpha.txt")
VARIANTS = ("vigenere", "beaufort")
KINDS = ("plaintext", "ciphertext")


# ------------------------------------------------------------------ cipher (codes 0-25)

def decrypt_codes(cipher, primer, kind="plaintext", variant="vigenere"):
    """``cipher`` and ``primer``: sequences of 0-25. Returns a bytearray."""
    L = len(primer)
    plain = bytearray(len(cipher))
    for i, c in enumerate(cipher):
        if i < L:
            k = primer[i]
        else:
            k = plain[i - L] if kind == "plaintext" else cipher[i - L]
        plain[i] = (c - k) % 26 if variant == "vigenere" else (k - c) % 26
    return plain


def encrypt_codes(plain, primer, kind="plaintext", variant="vigenere"):
    L = len(primer)
    cipher = bytearray(len(plain))
    for i, p in enumerate(plain):
        if i < L:
            k = primer[i]
        else:
            k = plain[i - L] if kind == "plaintext" else cipher[i - L]
        cipher[i] = (p + k) % 26 if variant == "vigenere" else (k - p) % 26
    return cipher


def to_codes(text):
    return bytes(ord(ch) - 65 for ch in text.upper() if "A" <= ch <= "Z")


def to_text(codes):
    return "".join(ALPHABET[c] for c in codes)


def decrypt_autokey(ciphertext, primer, kind="plaintext", variant="vigenere"):
    """Text interface: letters A-Z only (other characters are dropped)."""
    return to_text(decrypt_codes(to_codes(ciphertext), to_codes(primer), kind, variant))


# ------------------------------------------------------------------ primer-free attack (C)

ROUNDS = 6


def _fitness_args(fitness):
    """(score table pointer, keep-alive, n-gram size, entropy weight, fixed factor or -1)
    of an annealing.Fitness: the C engine computes the same fitness itself."""
    import ctypes
    try:
        scores, size, weight = fitness.scores, fitness.size, fitness.entropy_weight
    except AttributeError:
        raise TypeError("fitness must be an annealing.Fitness (cipher_profile.fitness_function()); "
                        "the C engine computes it from the n-gram table") from None
    fixed = getattr(fitness, "fixed_factor", None)
    if isinstance(scores, bytearray):
        keep = (ctypes.c_uint8 * len(scores)).from_buffer(scores)
    else:
        keep = ctypes.c_char_p(bytes(scores))
    return ctypes.cast(keep, ctypes.POINTER(ctypes.c_uint8)), keep, size, weight, -1.0 if fixed is None else float(fixed)


def _engine():
    import ctypes
    import native
    p8 = ctypes.POINTER(ctypes.c_uint8)
    i32, f64 = ctypes.c_int32, ctypes.c_double
    return native.function("cct_autokey_solve", f64, [p8, i32, i32, i32, i32, p8, i32, f64, f64, i32, p8, p8])


def solve_primer(cipher, length, kind, variant, fitness, rounds=ROUNDS):
    """Best primer of ``length`` for one autokey kind and tableau (C engine:
    chi-squared start per chain, then a coordinate hill-climb on ``fitness``,
    which must be an annealing.Fitness).
    Returns (fitness, primer codes, plaintext codes)."""
    import ctypes
    if kind not in KINDS or variant not in VARIANTS:
        raise ValueError(f"kind must be one of {KINDS}, variant one of {VARIANTS}")
    if length < 1:
        raise ValueError("the primer needs at least one letter")
    cipher = bytes(cipher)
    n = len(cipher)
    scores, keep, size, weight, fixed = _fitness_args(fitness)
    codes = (ctypes.c_uint8 * max(1, n)).from_buffer_copy(cipher or b"\0")
    primer = (ctypes.c_uint8 * length)()
    plain = (ctypes.c_uint8 * max(1, n))()
    score = _engine()(codes, n, length, KINDS.index(kind), VARIANTS.index(variant), scores, size, weight, fixed,
                      rounds, primer, plain)
    return score, list(primer), bytearray(plain[:n])


def attack(cipher, max_length, fitness, kinds=KINDS, variants=VARIANTS, report=None):
    """Every primer length 1..max_length for every kind and tableau, best first.
    Each entry: (fitness, kind, variant, primer codes, plaintext codes).
    ``fitness`` must be an annealing.Fitness (cipher_profile.fitness_function()):
    the C engine computes that same fitness itself."""
    import native
    native.require()
    results = []
    for length in range(1, max_length + 1):
        for kind in kinds:
            for variant in variants:
                score, primer, plain = solve_primer(cipher, length, kind, variant, fitness)
                results.append((score, kind, variant, primer, plain))
        if report:
            report(length)
    results.sort(key=lambda result: -result[0])
    return results


# ------------------------------------------------------------------ word-list primer search (C)

DICT_CHUNK = 20_000      # words per C call (progress line and Ctrl+C between calls)


def _word_codes(words):
    joined = "".join(words).encode("ascii").translate(bytes.maketrans(ALPHABET.encode(), bytes(range(26))))
    offsets = [0]
    for word in words:
        offsets.append(offsets[-1] + len(word))
    return joined, offsets


@lru_cache(maxsize=2)
def read_words(path=WORDLIST_PATH):
    """The word list as (tuple of words, joined letter codes, offsets):
    stripped, upper-cased, de-duplicated in file order; words with characters
    other than A-Z are skipped."""
    with open(path, "r", encoding="utf-8") as handle:
        words = (line.strip().upper() for line in handle)
        words = tuple(dict.fromkeys(word for word in words if word and word.isascii() and word.isalpha()))
    return (words,) + _word_codes(words)


def _phrase_codes(phrases):
    """Known phrases as letter codes (spaces and case ignored); any other
    character becomes 255, which never matches (as in attack_support)."""
    out = []
    for phrase in phrases:
        compact = phrase.upper().replace(" ", "")
        if compact:
            out.append(bytes(ord(ch) - 65 if "A" <= ch <= "Z" else 255 for ch in compact))
    return out


def dictionary_attack(cipher, fitness, words=None, kinds=KINDS, variants=VARIANTS, phrases=(), keep=20,
                      report=None, workers=None):
    """Every word as the primer, for each kind and tableau (C engine,
    scripts/native/keystream_dict.c, on several threads). ``words``: a list of
    words (default: the toolkit word list). ``fitness`` must be an
    annealing.Fitness (cipher_profile.fitness_function()). ``phrases``: known
    plaintext words; a candidate matches when all of them occur.
    Returns the best ``keep`` as (fitness, kind, variant, primer codes,
    plaintext codes, phrase match): phrase matches first, then higher fitness
    (ties: word-list order, then kind and tableau). The result is the exact
    top ``keep`` of the whole list. Ctrl+C returns the best of the chunks
    finished so far."""
    import ctypes
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import native
    native.require()
    combos = 0
    for kind in kinds:
        for variant in variants:
            if kind not in KINDS or variant not in VARIANTS:
                raise ValueError(f"kind must be one of {KINDS}, variant one of {VARIANTS}")
            combos |= 1 << (KINDS.index(kind) * 2 + VARIANTS.index(variant))
    if not combos or keep < 1:
        return []
    cipher = bytes(cipher)
    if cipher and max(cipher) > 25:
        raise ValueError("cipher codes must be 0-25 (A-Z)")
    if words is None:
        words, joined, offsets = read_words()
    else:
        words = [word.upper() for word in words]
        if any(not (word.isascii() and word.isalpha()) for word in words):
            raise ValueError("words must be letters A-Z only")
        joined, offsets = _word_codes(words)
    if not words:
        return []
    scores, keep_alive, size, weight, fixed = _fitness_args(fitness)
    p8 = ctypes.POINTER(ctypes.c_uint8)
    i32, i64, f64 = ctypes.c_int32, ctypes.c_int64, ctypes.c_double
    engine = native.function("cct_autokey_dict", i32,
                             [p8, i32, p8, ctypes.POINTER(i64), i64, i64, i32, p8, i32, f64, f64, p8,
                              ctypes.POINTER(i32), i32, i32, ctypes.POINTER(i64), ctypes.POINTER(i32),
                              ctypes.POINTER(f64), ctypes.POINTER(i32)])
    n = len(cipher)
    codes = (ctypes.c_uint8 * max(1, n)).from_buffer_copy(cipher or b"\0")
    key_codes = (ctypes.c_uint8 * max(1, len(joined))).from_buffer_copy(joined or b"\0")
    key_offsets = (i64 * len(offsets))(*offsets)
    phrase_list = _phrase_codes(phrases)
    phrase_joined, bounds = b"".join(phrase_list), [0]
    for phrase in phrase_list:
        bounds.append(bounds[-1] + len(phrase))
    phrase_codes = (ctypes.c_uint8 * max(1, len(phrase_joined))).from_buffer_copy(phrase_joined or b"\0")
    phrase_offsets = (i32 * len(bounds))(*bounds)

    def chunk(first):
        count = min(DICT_CHUNK, len(words) - first)
        out_word, out_combo, out_score, out_phrase = (i64 * keep)(), (i32 * keep)(), (f64 * keep)(), (i32 * keep)()
        kept = engine(codes, n, key_codes, key_offsets, first, count, combos, scores, size, weight, fixed,
                      phrase_codes, phrase_offsets, len(phrase_list), keep, out_word, out_combo, out_score,
                      out_phrase)
        if kept < 0:
            raise RuntimeError("cct_autokey_dict failed (bad input or out of memory)")
        return [(out_phrase[r], out_score[r], out_word[r], out_combo[r]) for r in range(kept)]

    firsts = list(range(0, len(words), DICT_CHUNK))
    if workers is None:
        import compute
        workers = compute.workers()
    rows = []
    executor = ThreadPoolExecutor(max_workers=max(1, min(workers, len(firsts))))
    futures = [executor.submit(chunk, first) for first in firsts]
    try:
        for done, future in enumerate(as_completed(futures), start=1):
            rows.extend(future.result())
            if report:
                report(done, len(firsts))
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted; showing the words searched so far.{RESET}")
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    rows.sort(key=lambda row: (-row[0], -row[1], row[2], row[3]))
    results = []
    for phrase, score, index, combo in rows[:keep]:
        kind, variant = KINDS[combo >> 1], VARIANTS[combo & 1]
        primer = list(joined[offsets[index]:offsets[index + 1]])
        results.append((score, kind, variant, primer, decrypt_codes(cipher, primer, kind, variant), bool(phrase)))
    return results


def describe(kind, variant, primer):
    return f"{kind} autokey, {'Vigenere' if variant == 'vigenere' else 'Beaufort'}, primer {to_text(primer)}"


# ------------------------------------------------------------------ interface

def ask_kind_variant():
    option(1, "Plaintext autokey, Vigenere tableau", "(the classic autoclave; default)")
    option(2, "Plaintext autokey, Beaufort tableau")
    option(3, "Ciphertext autokey, Vigenere tableau")
    option(4, "Ciphertext autokey, Beaufort tableau")
    choice = input("Select (Enter = 1): ").strip() or "1"
    return {"1": ("plaintext", "vigenere"), "2": ("plaintext", "beaufort"),
            "3": ("ciphertext", "vigenere"), "4": ("ciphertext", "beaufort")}.get(choice, ("plaintext", "vigenere"))


def show_ranked(results, cipher_length, limit=8, marks=None):
    import cipher_profile as cp
    refs = cp.references(cipher_length) if cipher_length >= cp.MIN_LETTERS else None
    for rank, (score, kind, variant, primer, plain) in enumerate(results[:limit], start=1):
        verdict = cp.judge(score, refs) if refs else ""
        colour = GREEN if verdict == "reads as English" else YELLOW if verdict == "partly English" else GREY
        mark = marks[rank - 1] if marks else ""
        print(f"\n{rank}. {CYAN}{describe(kind, variant, primer)}{RESET}  fitness {score:.1f} "
              f"{colour}{'[' + verdict + ']' if verdict else ''}{RESET}{mark}")
        print(f"   {to_text(plain)}")


def run():
    banner("Autoclave (Autokey) Cipher", "Decrypt, encrypt, or recover the primer (with or without a word list)")
    option(1, "Recover the primer (no word list)", "(every primer length, both kinds, both tableaux; recommended)")
    option(2, "Decrypt with a known primer")
    option(3, "Word-list attack: every word as the primer", "(both kinds, both tableaux; helps on short texts)")
    option(4, "Encrypt")
    mode = input("Select (Enter = 1): ").strip() or "1"

    if mode == "4":
        plain = to_codes(input(f"{GREY}Plaintext: {RESET}"))
        primer = to_codes(input("Primer: "))
        if not plain or not primer:
            print(f"{RED}Need letters in both.{RESET}")
            return
        kind, variant = ask_kind_variant()
        print(f"\n{GREEN}{to_text(encrypt_codes(plain, primer, kind, variant))}{RESET}")
        return

    cipher = to_codes(input(f"{GREY}Enter ciphertext: {RESET}"))
    if len(cipher) < 2:
        print(f"{RED}Need some letters (A-Z).{RESET}")
        return

    if mode == "2":
        primer = to_codes(input("Primer: "))
        if not primer:
            print(f"{RED}The primer needs letters.{RESET}")
            return
        kind, variant = ask_kind_variant()
        print(f"\n{GREEN}{to_text(decrypt_codes(cipher, primer, kind, variant))}{RESET}")
        return

    import native
    import cipher_profile as cp
    native.require()
    fitness = cp.fitness_function()
    if mode == "3":
        phrases = [p.strip() for p in input("Known plaintext words (comma-separated, optional): ").split(",")
                   if p.strip()]
        print(f"{GREY}Trying every word of the word list as the primer (plaintext and ciphertext autokey, "
              f"Vigenere and Beaufort, C engine)...{RESET}")
        results = dictionary_attack(cipher, fitness, phrases=phrases,
                                    report=lambda done, total: print(f"  {done / total:.0%}", end="\r"))
        print(" " * 40, end="\r")
        print(f"{BOLD}Best primers{RESET} {GREY}(phrase matches first, then higher fitness = more English){RESET}")
        show_ranked([result[:5] for result in results], len(cipher), limit=10,
                    marks=[f" {GREEN}[phrase match]{RESET}" if result[5] else "" for result in results])
        return

    default_max = max(1, min(20, len(cipher) // 4))
    answer = input(f"Longest primer to try (Enter = {YELLOW}{default_max}{RESET}): ").strip()
    max_length = int(answer) if answer.isdigit() and int(answer) >= 1 else default_max
    print(f"{GREY}Trying primer lengths 1-{max_length}, plaintext and ciphertext autokey, Vigenere and Beaufort...{RESET}")
    results = attack(cipher, max_length, fitness,
                     report=lambda length: print(f"  primer length {length} done", end="\r"))
    print(" " * 40, end="\r")
    print(f"{BOLD}Best results{RESET} {GREY}(higher fitness = more English){RESET}")
    show_ranked(results, len(cipher))
    print(f"\n{GREY}The primer letters only affect the first letters of each chain; a result that reads as "
          f"English with an odd-looking primer is still a solution (the primer may be a word you can now "
          f"guess). Short texts can give several near-equal primers.{RESET}")


if __name__ == "__main__":
    run()
