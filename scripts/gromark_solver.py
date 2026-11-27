"""Ciphertext-only Gromark attack (straight plaintext alphabet, unknown mixed
cipher alphabet, unknown primer).

Gromark (ACA): a primer of L digits is extended by chain addition,
d[i] = (d[i-L] + d[i-L+1]) mod base; plaintext letter p becomes
c = CA[(p + d) mod 26] (counting right; left: p - d).

For the right primer, every occurrence of one cipher letter c satisfies
p + d = s(c) for a fixed s(c) = CA.index(c), so the plaintext letters under c
lie in a window of `base` consecutive letters. Stage 1 scores every primer by
how well each cipher letter's digit histogram fits English letter frequencies
in such a window. Stage 2 takes the best primers, builds the cipher alphabet
from those windows, and hill-climbs it on n-gram fitness (swapping two
letters' positions). Both stages run in C (scripts/native/gromark.c); stage 2
is spread over worker processes. Without the C library they raise
native.NativeUnavailable with the build instructions.
"""
import ctypes
import math

from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ENGLISH = [8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61,
           6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07]
LOGP = [math.log(f / 100) for f in ENGLISH]
MAX_BASE = 32            # the C histograms hold 32 digit values
REFINE_ROUNDS = 30
SCREEN_CHUNK = 200_000   # primers per C call (progress line and Ctrl+C between calls)
REFINE_JOB = 100         # primers per worker job

_i32, _i64, _f64 = ctypes.c_int32, ctypes.c_int64, ctypes.c_double
_P8, _P32, _P64, _PF = (ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(_i32), ctypes.POINTER(_i64),
                        ctypes.POINTER(_f64))


# ------------------------------------------------------------------ one-shot helpers

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


def alphabet_from_s(s):
    alphabet = ["?"] * 26
    for c, position in enumerate(s):
        alphabet[position] = ALPHABET[c]
    return "".join(alphabet)


# ------------------------------------------------------------------ C engines

def _c(name, restype, argtypes):
    import native
    return native.function(name, restype, argtypes)


def _check_base(base):
    if not 2 <= base <= MAX_BASE:
        raise ValueError(f"base must be 2-{MAX_BASE}")


def _check_plen(plen):
    if plen < 2:
        raise ValueError("the primer needs at least 2 digits (chain addition adds two digits)")


def _check_codes(cipher):
    """Cipher as bytes; every code must be 0-25 (the C histograms are 26 rows)."""
    cipher = bytes(cipher)
    if cipher and max(cipher) > 25:
        raise ValueError("cipher codes must be 0-25 (A-Z)")
    return cipher


def _fitness_args(fitness):
    """(score table pointer, keep-alive, n-gram size, entropy weight, fixed factor or -1)
    of an annealing.Fitness: the C engine computes the same fitness itself."""
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
    return ctypes.cast(keep, _P8), keep, size, weight, -1.0 if fixed is None else float(fixed)


def _u8(data):
    data = bytes(data)
    return (ctypes.c_uint8 * max(1, len(data))).from_buffer_copy(data or b"\0")


def screen_primers(cipher, base=10, plen=5, sign=1, keep=40, report=None):
    """Best ``keep`` primers by the window score, best first: [(score, primer number)]
    (ties: the larger primer number first, as Python tuples compare)."""
    import native
    native.require()
    _check_base(base)
    _check_plen(plen)
    screen = _c("cct_gromark_screen_top", None, [_P8, _i32, _i32, _i32, _i32, _PF, _i64, _i64, _i32, _PF, _P64,
                                                  _P32])
    cipher = _check_codes(cipher)
    codes, logp = _u8(cipher), (_f64 * 26)(*LOGP)
    keep = max(0, int(keep))
    heap_scores, heap_primers, heap_size = (_f64 * max(1, keep))(), (_i64 * max(1, keep))(), _i32(0)
    total = base ** plen
    for first in range(0, total, SCREEN_CHUNK):
        count = min(SCREEN_CHUNK, total - first)
        screen(codes, len(cipher), base, plen, sign, logp, first, count, keep, heap_scores, heap_primers,
               ctypes.byref(heap_size))
        if report:
            report(first + count, total)
    return sorted(((heap_scores[i], heap_primers[i]) for i in range(heap_size.value)), reverse=True)


def initial_s(cipher, digits, base, sign=1):
    """A one-to-one assignment cipher letter -> s from the per-letter window fit (C)."""
    _check_base(base)
    initial = _c("cct_gromark_initial_s", _i32, [_P8, _i32, _P32, _i32, _i32, _PF, _P8])
    cipher = _check_codes(cipher)
    digits = list(digits[:len(cipher)])
    if len(digits) < len(cipher):
        raise ValueError("need one digit per cipher letter")
    if any(not 0 <= d < base for d in digits):
        raise ValueError(f"digits must be 0-{base - 1}")
    out = (ctypes.c_uint8 * 26)()
    if initial(_u8(cipher), len(cipher), (_i32 * max(1, len(cipher)))(*digits), base, sign,
               (_f64 * 26)(*LOGP), out) != 0:
        raise ValueError("cct_gromark_initial_s refused the input")
    return list(out)


def refine(cipher, digits, s, fitness, sign=1, rounds=REFINE_ROUNDS):
    """Hill-climb the cipher alphabet ``s`` (C): swap two letters' positions, keep
    a swap that raises ``fitness`` by more than 1e-9. Returns (score, s, plaintext)."""
    climb = _c("cct_gromark_refine", _f64, [_P8, _i32, _P32, _i32, _P8, _P8, _i32, _f64, _f64, _i32, _P8])
    cipher = _check_codes(cipher)
    n = len(cipher)
    if len(digits) < n:
        raise ValueError("need one digit per cipher letter")
    if len(s) != 26 or any(not 0 <= x <= 25 for x in s):
        raise ValueError("s must hold 26 positions 0-25")
    scores, keep, size, weight, fixed = _fitness_args(fitness)
    s_io = (ctypes.c_uint8 * 26)(*s)
    plain = (ctypes.c_uint8 * max(1, n))()
    score = climb(_u8(cipher), n, (_i32 * max(1, n))(*digits[:n]), sign, s_io, scores, size, weight, fixed,
                  rounds, plain)
    return score, list(s_io), bytes(plain[:n])


def refine_primers(cipher, numbers, base, plen, sign, fitness, rounds=REFINE_ROUNDS):
    """keystream + initial_s + refine for each primer number, in one C call.
    Returns [(score, s)] in the order of ``numbers``."""
    _check_base(base)
    _check_plen(plen)
    batch = _c("cct_gromark_refine_primers", None, [_P8, _i32, _i32, _i32, _i32, _PF, _P64, _i32, _P8, _i32, _f64,
                                                     _f64, _i32, _P8, _PF])
    cipher = _check_codes(cipher)
    m = len(numbers)
    scores, keep, size, weight, fixed = _fitness_args(fitness)
    s_out, fit_out = (ctypes.c_uint8 * (26 * max(1, m)))(), (_f64 * max(1, m))()
    batch(_u8(cipher), len(cipher), base, plen, sign, (_f64 * 26)(*LOGP), (_i64 * max(1, m))(*numbers), m,
          scores, size, weight, fixed, rounds, s_out, fit_out)
    return [(fit_out[q], list(s_out[26 * q:26 * q + 26])) for q in range(m)]


def _refine_batch(args):
    """Process-pool worker: refine a list of primers in C, return the best few."""
    import cipher_profile as cp
    cipher, numbers, base, plen, sign = args
    out = []
    for number, (score, s) in zip(numbers, refine_primers(cipher, numbers, base, plen, sign,
                                                           cp.fitness_function())):
        out.append((score, number, s))
    out.sort(key=lambda r: -r[0])
    results = []
    for score, number, s in out[:5]:
        primer = primer_digits(number, plen, base)
        plain = decrypt_with_s(cipher, s, keystream(primer, len(cipher), base), sign)
        results.append((score, "".join(map(str, primer)), sign, alphabet_from_s(s), plain))
    return results


def solve(cipher, base=10, plen=5, signs=(1, -1), keep=3000, report=None, workers=None):
    """Screen every primer, refine the best ``keep`` per direction in parallel
    (both stages in C). Measured on planted texts (150-400 letters, random
    mixed alphabets, 5-digit primers): the true primer ranked 129th-1,051st of
    100,000 in an earlier screen run; an independent review found it ranked
    1,303rd and 2,571st in two other trials. Refining from initial_s does not
    always reach the true alphabet: in that review's 7 trials, 5 were solved
    exactly and in 2 the climb stalled, and the best result was the
    complementary key of the opposite direction, which read 88-93% of the
    plaintext correctly (the former Python refine behaves the same). Short
    texts may not be solved: tool 71's 78-letter known-answer text is not.
    Returns [(fitness, primer string, sign, cipher alphabet, plaintext codes)],
    the best 5 of every job of 100 primers, best first."""
    import os
    from concurrent.futures import ProcessPoolExecutor
    import native
    native.require()
    _check_base(base)
    _check_plen(plen)
    cipher = _check_codes(cipher)
    jobs = []
    for sign in signs:
        numbers = [number for _, number in screen_primers(cipher, base, plen, sign, keep, report)]
        jobs += [(cipher, numbers[i:i + REFINE_JOB], base, plen, sign) for i in range(0, len(numbers), REFINE_JOB)]
    if workers is None:
        import compute
        workers = compute.workers()
    workers = max(1, min(workers, len(jobs)))
    if workers == 1:
        results = [r for job in jobs for r in _refine_batch(job)]
    else:
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
    native.require()
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
