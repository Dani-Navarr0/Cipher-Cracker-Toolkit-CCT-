"""Keyless Playfair attack: simulated annealing over the 5x5 key square, run
entirely in C (native/digraphic.c; same fitness as the other solvers, cooling
from 8 to 0.1, then a polish over every letter swap).

Moves on the square: swap two letters (90%), swap two rows (4%), swap two
columns (4%), flip top-bottom (1%), flip left-right (0.5%), transpose (0.5%).
The letter swaps find the square's content; the structural moves fix its
arrangement, since squares that differ by a row/column rotation decrypt
identically. Square below is the one-shot encrypt/decrypt helper.
"""
import random

SQUARE_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"   # J merged into I


def prepare(ciphertext: str) -> bytes:
    """Ciphertext letters as 0-24 square indices (J -> I); odd length drops the last letter."""
    text = ciphertext.upper().replace("J", "I")
    codes = bytes(SQUARE_ALPHABET.index(ch) for ch in text if ch in SQUARE_ALPHABET)
    return codes[:len(codes) // 2 * 2]


def to_az(letters: bytes) -> bytes:
    """Square indices -> 0-25 letter codes (for n-gram scoring)."""
    return bytes(ord(SQUARE_ALPHABET[i]) - 65 for i in letters)


class Square:
    def __init__(self, order=None):
        self.grid = list(order) if order is not None else random.sample(range(25), 25)
        self._index()

    def _index(self):
        self.pos = [0] * 25
        for cell, letter in enumerate(self.grid):
            self.pos[letter] = cell

    def decrypt(self, cipher: bytes) -> bytes:
        grid, pos = self.grid, self.pos
        out = bytearray(len(cipher))
        for i in range(0, len(cipher), 2):
            a, b = pos[cipher[i]], pos[cipher[i + 1]]
            ra, ca = divmod(a, 5)
            rb, cb = divmod(b, 5)
            if ra == rb:
                out[i] = grid[ra * 5 + (ca - 1) % 5]
                out[i + 1] = grid[rb * 5 + (cb - 1) % 5]
            elif ca == cb:
                out[i] = grid[((ra - 1) % 5) * 5 + ca]
                out[i + 1] = grid[((rb - 1) % 5) * 5 + cb]
            else:
                out[i] = grid[ra * 5 + cb]
                out[i + 1] = grid[rb * 5 + ca]
        return bytes(out)

    def encrypt(self, plain: bytes) -> bytes:
        grid, pos = self.grid, self.pos
        out = bytearray(len(plain))
        for i in range(0, len(plain), 2):
            a, b = pos[plain[i]], pos[plain[i + 1]]
            ra, ca = divmod(a, 5)
            rb, cb = divmod(b, 5)
            if ra == rb:
                out[i] = grid[ra * 5 + (ca + 1) % 5]
                out[i + 1] = grid[rb * 5 + (cb + 1) % 5]
            elif ca == cb:
                out[i] = grid[((ra + 1) % 5) * 5 + ca]
                out[i + 1] = grid[((rb + 1) % 5) * 5 + cb]
            else:
                out[i] = grid[ra * 5 + cb]
                out[i + 1] = grid[rb * 5 + ca]
        return bytes(out)

    def key(self) -> str:
        return "".join(SQUARE_ALPHABET[i] for i in self.grid)


def _cipher(cipher: bytes, ngram_model):
    from native import digraphic
    return digraphic.make_cipher(digraphic.PLAYFAIR, cipher, 25, to_az(bytes(range(25))), ngram_model)


def solve(ciphertext: str, ngram_model, iterations: int = 1_000_000, seed=None, report=None, t_start: float = 8.0):
    """One annealing run (C). Returns (fitness, square string, plaintext).
    ``report(step, temperature, best fitness, [best square])`` is called after every chunk of moves."""
    from native import digraphic
    if seed is not None:
        random.seed(seed)
    cipher = prepare(ciphertext)
    native_cipher = _cipher(cipher, ngram_model)
    start = random.sample(range(25), 25)
    final, keys = digraphic.anneal(native_cipher, [start], iterations, t_start, 0.1, random.getrandbits(64),
                                   polish_rounds=20, report=report)
    square = Square(keys[0])
    plain = "".join(SQUARE_ALPHABET[i] for i in square.decrypt(cipher))
    return final, square.key(), plain


def attack_interactive(ciphertext: str, default_steps: int = 1_000_000, default_runs: int = 8):
    """Several independent runs in parallel; reports agreement and a verdict."""
    import os
    import time
    from concurrent.futures import ProcessPoolExecutor, as_completed
    from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores
    from theme import CYAN, GREEN, GREY, RED, RESET, YELLOW
    import cipher_profile as cp

    cipher = prepare(ciphertext)
    if len(cipher) < 40:
        print(f"{RED}Need at least 40 letters; Playfair keys are rarely recoverable from short texts.{RESET}")
        return None
    letters = ciphertext.upper()
    if sum(ch.isalpha() for ch in letters) % 2:
        print(f"{YELLOW}Odd number of letters: a Playfair ciphertext always has an even length; the last letter "
              f"is ignored.{RESET}")

    def ask(prompt, default):
        text = input(f"{prompt} (default {YELLOW}{default:,}{RESET}): ").strip().replace(",", "").replace("_", "")
        return int(text) if text.isdigit() and int(text) > 0 else default

    steps = ask("Annealing steps per run", default_steps)
    runs = ask("Independent runs", default_runs)
    import compute
    workers = compute.workers(runs)
    import native
    from native import digraphic
    native.require()
    model = load_ngram_scores()
    trial = 20_000
    started = time.perf_counter()
    digraphic.anneal(_cipher(cipher, model), [random.sample(range(25), 25)], trial, 8.0, polish_rounds=0)
    per_step = (time.perf_counter() - started) / trial
    estimate = per_step * steps * -(-runs // workers)
    print(f"{GREY}{runs} runs x {steps:,} steps on {workers} process(es): roughly {estimate:.0f}-"
          f"{2 * estimate + 1:.0f} s. Measured on one 300-letter text: 6 of 16 runs of 1,000,000 steps "
          f"found the key; failed runs stall at about half the fitness, so more runs raise the chance.{RESET}")
    if input("Start? ([Y]/n): ").strip().lower() == "n":
        return None
    jobs = [{'ciphertext': ciphertext, 'ngram_path': str(DEFAULT_NGRAM_PATH), 'iterations': steps,
             'seed': random.randrange(2 ** 32)} for _ in range(runs)]
    results = []
    try:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(solve_job, job) for job in jobs]
            for done, future in enumerate(as_completed(futures), start=1):
                results.append(future.result())
                best = max(results)
                print(f"Run {done}/{runs} | best fitness {best[0]:.1f} | {best[2][:40]}...", end="\r")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted; showing the finished runs.{RESET}")
    print()
    if not results:
        return None
    results.sort(reverse=True)
    best = results[0]
    agreeing = sum(1 for result in results if result[2] == best[2])
    refs = cp.references(len(cipher)) if len(cipher) >= cp.MIN_LETTERS else None
    verdict = cp.judge(best[0], refs) if refs else ""
    colour = GREEN if verdict == "reads as English" else YELLOW
    print(f"Best square {CYAN}{best[1]}{RESET} (rows: {' '.join(best[1][i:i + 5] for i in range(0, 25, 5))})")
    print(f"Fitness {best[0]:.1f} {colour}[{verdict}]{RESET} | runs reaching this plaintext: {agreeing}/{len(results)}")
    print(f"{GREEN}{best[2]}{RESET}")
    print(f"{GREY}Squares that differ by moving rows or columns round decrypt the same way, so the square shown "
          f"may be a rotation of the one used. X between doubled letters and at the end is Playfair padding.{RESET}")
    if verdict != "reads as English":
        print(f"{YELLOW}Not solved: try more runs or steps.{RESET}")
    return results


def solve_job(job):
    """Process-pool entry point."""
    from ngram_scoring import load_ngram_scores
    return solve(job['ciphertext'], load_ngram_scores(job['ngram_path']), job['iterations'], job['seed'],
                 t_start=job.get('t_start', 8.0))
