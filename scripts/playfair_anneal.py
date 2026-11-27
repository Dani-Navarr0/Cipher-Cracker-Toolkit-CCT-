"""Keyless Playfair attack: simulated annealing over the 5x5 key square on the
shared engine (same fitness as the other solvers; cooling from 8 to 0.1).

Moves on the square: swap two letters (most moves), swap two rows, swap two
columns, flip top-bottom, flip left-right, transpose. The letter swaps find
the square's content; the structural moves fix its arrangement, since
squares that differ by a row/column rotation decrypt identically.
"""
import random

from annealing import Fitness, Schedule, anneal, hill_climb

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

    def move(self):
        self._saved = self.grid[:]
        grid = self.grid
        roll = random.random()
        if roll < 0.9:
            i, j = random.sample(range(25), 2)
            grid[i], grid[j] = grid[j], grid[i]
        elif roll < 0.94:
            r1, r2 = random.sample(range(5), 2)
            grid[r1 * 5:r1 * 5 + 5], grid[r2 * 5:r2 * 5 + 5] = grid[r2 * 5:r2 * 5 + 5], grid[r1 * 5:r1 * 5 + 5]
        elif roll < 0.98:
            c1, c2 = random.sample(range(5), 2)
            for r in range(5):
                grid[r * 5 + c1], grid[r * 5 + c2] = grid[r * 5 + c2], grid[r * 5 + c1]
        elif roll < 0.99:
            self.grid = [grid[(4 - r) * 5 + c] for r in range(5) for c in range(5)]
        elif roll < 0.995:
            self.grid = [grid[r * 5 + (4 - c)] for r in range(5) for c in range(5)]
        else:
            self.grid = [grid[c * 5 + r] for r in range(5) for c in range(5)]
        self._index()

    def undo(self):
        self.grid = self._saved
        self._index()

    def key(self) -> str:
        return "".join(SQUARE_ALPHABET[i] for i in self.grid)


def solve(ciphertext: str, ngram_model, iterations: int = 1_000_000, seed=None, report=None, t_start: float = 8.0):
    """One annealing run. Returns (fitness, square string, plaintext)."""
    if seed is not None:
        random.seed(seed)
    cipher = prepare(ciphertext)
    fitness = Fitness(ngram_model, 0.5)
    square = Square()

    def score():
        return fitness(to_az(square.decrypt(cipher)))

    def propose():
        square.move()
        return score()

    best_grid, _ = anneal(score(), propose, square.undo, lambda: square.grid[:], Schedule(iterations, t_start), report)
    square.grid = list(best_grid)
    square._index()

    # Polish: every single letter swap until none helps.
    moves = [(i, j) for i in range(25) for j in range(i + 1, 25)]

    def apply_move(move):
        square._saved = square.grid[:]
        i, j = move
        square.grid[i], square.grid[j] = square.grid[j], square.grid[i]
        square._index()
        return score()

    final = hill_climb(score(), moves, apply_move, square.undo, max_rounds=20)
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
    workers = max(1, min(runs, (os.cpu_count() or 2) - 1))
    model = load_ngram_scores()
    square = Square()
    fitness = Fitness(model, 0.5)
    started = time.perf_counter()
    for _ in range(300):
        square.move()
        fitness(to_az(square.decrypt(cipher)))
    per_step = (time.perf_counter() - started) / 300
    estimate = per_step * steps * runs / workers
    print(f"{GREY}{runs} runs x {steps:,} steps on {workers} process(es): roughly {estimate / 60:.1f}-"
          f"{2 * estimate / 60 + 0.1:.1f} min. Measured on a 304-letter text: 2 of 8 runs of 1,000,000 steps "
          f"found the key (1 of 8 with a hotter start); failed runs stall at about half the fitness, so more "
          f"runs raise the chance.{RESET}")
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
