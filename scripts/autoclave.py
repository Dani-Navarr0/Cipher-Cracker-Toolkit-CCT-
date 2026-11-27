"""Autokey (autoclave) cipher: decrypt, encrypt, and attacks that need no
word list.

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
"""
import os

from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner, option

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")
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


# ------------------------------------------------------------------ primer-free attack

ENGLISH = [8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61,
           6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07]


def _chi(letters):
    total = len(letters) or 1
    return sum((letters.count(c) - ENGLISH[c] * total / 100) ** 2 / (ENGLISH[c] * total / 100) for c in range(26))


def solve_primer(cipher, length, kind, variant, fitness, rounds=6):
    """Best primer of ``length`` for one autokey kind and tableau.
    Returns (fitness, primer codes, plaintext codes)."""
    n = len(cipher)
    primer = [0] * length
    # Start: each chain's primer letter chosen by English letter frequencies.
    for j in range(length):
        best = None
        for s in range(26):
            primer[j] = s
            chain = decrypt_codes(cipher, primer, kind, variant)[j::length]
            score = _chi(chain)
            if best is None or score < best[0]:
                best = (score, s)
        primer[j] = best[1]
    plain = decrypt_codes(cipher, primer, kind, variant)
    score = fitness(plain) if n > 5 else 0.0
    for _ in range(rounds):
        improved = False
        for j in range(length):
            keep = primer[j]
            for s in range(26):
                if s == keep:
                    continue
                primer[j] = s
                trial = decrypt_codes(cipher, primer, kind, variant)
                trial_score = fitness(trial)
                if trial_score > score + 1e-9:
                    score, plain, keep, improved = trial_score, trial, s, True
            primer[j] = keep
        if not improved:
            break
    return score, list(primer), plain


def attack(cipher, max_length, fitness, kinds=KINDS, variants=VARIANTS, report=None):
    """Every primer length 1..max_length for every kind and tableau, best first.
    Each entry: (fitness, kind, variant, primer codes, plaintext codes)."""
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


# ------------------------------------------------------------------ dictionary attack

def _dictionary_decrypt(ciphertext, word, alphabet_str):
    """attack_support interface (variant and kind fixed to the classic
    plaintext autokey on the Vigenere tableau)."""
    return decrypt_autokey(ciphertext, word)


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


def show_ranked(results, cipher_length, limit=8):
    import cipher_profile as cp
    refs = cp.references(cipher_length) if cipher_length >= cp.MIN_LETTERS else None
    for rank, (score, kind, variant, primer, plain) in enumerate(results[:limit], start=1):
        verdict = cp.judge(score, refs) if refs else ""
        colour = GREEN if verdict == "reads as English" else YELLOW if verdict == "partly English" else GREY
        print(f"\n{rank}. {CYAN}{describe(kind, variant, primer)}{RESET}  fitness {score:.1f} "
              f"{colour}{'[' + verdict + ']' if verdict else ''}{RESET}")
        print(f"   {to_text(plain)}")


def run():
    banner("Autoclave (Autokey) Cipher", "Decrypt, encrypt, or recover the primer with no word list")
    option(1, "Recover the primer (no word list)", "(every primer length, both kinds, both tableaux; recommended)")
    option(2, "Decrypt with a known primer")
    option(3, "Dictionary attack: every word as the primer", "(classic plaintext autokey only)")
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

    import cipher_profile as cp
    fitness = cp.fitness_function()
    if mode == "3":
        from attack_support import load_dictionary, run_batches, sort_results
        words = load_dictionary(WORDLIST_PATH, ALPHABET, 1, 20)
        phrases = [p.strip() for p in input("Known plaintext words (comma-separated, optional): ").split(",") if p.strip()]
        from ngram_scoring import load_ngram_scores
        results = sort_results(run_batches(_dictionary_decrypt, words, to_text(cipher), ALPHABET, phrases,
                                           load_ngram_scores(), 0.060, 0.075))
        print(f"\n{BOLD}Best primers{RESET} {GREY}(lowest n-gram cost first; phrase matches on top){RESET}")
        for rank, result in enumerate(results[:10], start=1):
            mark = f" {GREEN}[phrase match]{RESET}" if result['is_phrase_match'] else ""
            print(f"{rank:>2}. {YELLOW}{result['key']}{RESET} cost {result['bigram_score']:.1f}{mark}\n    {result['plaintext']}")
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
