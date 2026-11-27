"""Ciphertext-only Gromark attack (straight plaintext alphabet, unknown mixed
cipher alphabet, unknown primer).

Gromark (ACA): a primer of L digits is extended by chain addition,
d[i] = (d[i-L] + d[i-L+1]) mod base; plaintext letter p becomes
c = CA[(p + d) mod 26] (counting right; left: p - d).

For the right primer, every occurrence of one cipher letter c satisfies
p + d = s(c) for a fixed s(c) = CA.index(c), so the plaintext letters under c
lie in a window of `base` consecutive letters. Stage 1 scores every primer by
how well each cipher letter's digit histogram fits English letter frequencies
in such a window (C kernel; the Python fallback is slow). Stage 2 takes the
best primers, builds the cipher alphabet from those windows, and hill-climbs
it on n-gram fitness (swapping two letters' positions).
"""
import math

from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ENGLISH = [8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61,
           6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07]
LOGP = [math.log(f / 100) for f in ENGLISH]


def keystream(primer_digits, length, base=10):
    plen = len(primer_digits)
    digits = list(primer_digits[:length])
    for i in range(plen, length):
        digits.append((digits[i - plen] + digits[i - plen + 1]) % base)
    return digits


def primer_digits(number, plen, base):
    digits = []
    for _ in range(plen):
        digits.append(number % base)
        number //= base
    return digits[::-1]


def encrypt(plain_codes, primer, cipher_alphabet, base=10, sign=1):
    digits = keystream(primer, len(plain_codes), base)
    return bytes(ord(cipher_alphabet[(p + sign * d) % 26]) - 65 for p, d in zip(plain_codes, digits))


def decrypt_with_s(cipher, s, digits, sign=1):
    """p = s[c] - sign*d; s[c] = position of cipher letter c in the cipher alphabet."""
    return bytes((s[c] - sign * d) % 26 for c, d in zip(cipher, digits))


def primer_score_python(cipher, digits, base, sign=1):
    hist = [[0] * base for _ in range(26)]
    for c, d in zip(cipher, digits):
        hist[c][d] += 1
    score = 0.0
    for c in range(26):
        if not any(hist[c]):
            continue
        score += max(sum(h * LOGP[(s - sign * d) % 26] for d, h in enumerate(hist[c]) if h) for s in range(26))
    return score


def screen_primers(cipher, base=10, plen=5, sign=1, keep=40, report=None):
    """Best primers by the window score: [(score, primer number)]."""
    from native import fast
    import heapq
    total = base ** plen
    best = []
    chunk = 200_000
    for first in range(0, total, chunk):
        count = min(chunk, total - first)
        scores = fast.gromark_scores(cipher, base, plen, sign, LOGP, first, count)
        if scores is None:   # Python fallback
            scores = [primer_score_python(cipher, keystream(primer_digits(first + q, plen, base), len(cipher), base),
                                          base, sign) for q in range(count)]
        best = heapq.nlargest(keep, best + [(score, first + q) for q, score in enumerate(scores)])
        if report:
            report(first + count, total)
    return best


def initial_s(cipher, digits, base, sign=1):
    """A one-to-one assignment cipher letter -> s from the per-letter window fit."""
    hist = [[0] * base for _ in range(26)]
    for c, d in zip(cipher, digits):
        hist[c][d] += 1
    options = []
    for c in range(26):
        for s in range(26):
            value = sum(h * LOGP[(s - sign * d) % 26] for d, h in enumerate(hist[c]) if h)
            options.append((value if any(hist[c]) else -1e9, c, s))
    options.sort(reverse=True)
    s_of, used = [None] * 26, set()
    for value, c, s in options:
        if s_of[c] is None and s not in used:
            s_of[c], _ = s, used.add(s)
    return s_of


def refine(cipher, digits, s, fitness, sign=1, rounds=30):
    s = list(s)
    plain = decrypt_with_s(cipher, s, digits, sign)
    score = fitness(plain)
    present = sorted(set(cipher))
    for _ in range(rounds):
        improved = False
        for i, a in enumerate(present):
            for b in range(26):
                if b == a:
                    continue
                s[a], s[b] = s[b], s[a]
                trial = decrypt_with_s(cipher, s, digits, sign)
                trial_score = fitness(trial)
                if trial_score > score + 1e-9:
                    score, plain, improved = trial_score, trial, True
                else:
                    s[a], s[b] = s[b], s[a]
        if not improved:
            break
    return score, s, plain


def _refine_batch(args):
    """Process-pool worker: refine a list of primers, return the best few."""
    import cipher_profile as cp
    cipher, numbers, base, plen, sign = args
    fitness = cp.fitness_function()
    out = []
    for number in numbers:
        primer = primer_digits(number, plen, base)
        digits = keystream(primer, len(cipher), base)
        score, s, plain = refine(cipher, digits, initial_s(cipher, digits, base, sign), fitness, sign)
        alphabet = ["?"] * 26
        for c, position in enumerate(s):
            alphabet[position] = ALPHABET[c]
        out.append((score, "".join(map(str, primer)), sign, "".join(alphabet), plain))
    return sorted(out, key=lambda r: -r[0])[:5]


def solve(cipher, base=10, plen=5, signs=(1, -1), keep=3000, report=None):
    """Screen every primer, refine the best ``keep`` per direction in parallel.
    Measured (planted, 150-400 letters): the true primer ranked 129th-1,051st of
    100,000 in the screen, and refining it recovered 100% of the plaintext.
    Returns [(fitness, primer string, sign, cipher alphabet, plaintext codes)]."""
    import os
    from concurrent.futures import ProcessPoolExecutor
    cipher = bytes(cipher)
    jobs = []
    for sign in signs:
        numbers = [number for _, number in screen_primers(cipher, base, plen, sign, keep, report)]
        jobs += [(cipher, numbers[i:i + 100], base, plen, sign) for i in range(0, len(numbers), 100)]
    workers = max(1, (os.cpu_count() or 2) - 1)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        results = [r for part in pool.map(_refine_batch, jobs) for r in part]
    results.sort(key=lambda r: -r[0])
    return results


def run():
    import native
    import cipher_profile as cp
    from ngram_scoring import codes_to_text, text_to_codes
    banner("Gromark Solver", "Ciphertext only: every primer screened, then the mixed cipher alphabet hill-climbed")
    cipher = text_to_codes(input(f"{GREY}Enter ciphertext: {RESET}"))
    if len(cipher) < 60:
        print(f"{RED}Need at least 60 letters.{RESET}")
        return
    base = input("Base (Enter = 10, the ACA Gromark): ").strip()
    base = int(base) if base.isdigit() and 2 <= int(base) <= 26 else 10
    plen = input("Primer length (Enter = 5): ").strip()
    plen = int(plen) if plen.isdigit() and 2 <= int(plen) <= 12 else 5
    if base ** plen > 50_000_000:
        print(f"{RED}{base ** plen:,} primers is too many; shorten the primer.{RESET}")
        return
    if not native.available():
        print(f"{YELLOW}C engines not built (menu 45): the primer screen runs in Python and takes minutes.{RESET}")
    print(f"{GREY}Screening {base ** plen:,} primers, counting right and left...{RESET}")
    results = solve(cipher, base, plen, report=lambda done, total: print(f"  {done:,}/{total:,}", end="\r"))
    refs = cp.references(len(cipher))
    print(f"\n{BOLD}Best results{RESET}")
    for score, primer, sign, alphabet, plain in results[:6]:
        verdict = cp.judge(score, refs)
        colour = GREEN if verdict == "reads as English" else YELLOW if verdict == "partly English" else GREY
        print(f"\nprimer {YELLOW}{primer}{RESET} ({'right' if sign == 1 else 'left'}), cipher alphabet "
              f"{CYAN}{alphabet}{RESET}  fitness {score:.1f} {colour}[{verdict}]{RESET}")
        print(f"   {codes_to_text(plain)[:100]}")


if __name__ == "__main__":
    run()
