"""Ciphertext-only Bifid and Trifid: simulated annealing over the key square
(5x5, J = I) or cube (3x3x3: 26 letters + '+'), for a given period.

Bifid/Trifid with period P: each block of P plaintext letters is written as
coordinates (rows, columns[, layers]) in rows, read off row by row in groups,
and the groups become ciphertext letters (period 0 = the whole text as one
block). Decryption runs in C when the native engines are built.
"""
import ctypes
import math
import os
import random

from annealing import Fitness, Schedule, anneal, hill_climb
from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner

KINDS = {
    "bifid": {"symbols": "ABCDEFGHIKLMNOPQRSTUVWXYZ", "dims": 2, "side": 5},
    "trifid": {"symbols": "ABCDEFGHIJKLMNOPQRSTUVWXYZ+", "dims": 3, "side": 3},
}


def to_symbols(text, kind):
    symbols = KINDS[kind]["symbols"]
    text = text.upper()
    if kind == "bifid":
        text = text.replace("J", "I")
    return bytes(symbols.index(ch) for ch in text if ch in symbols)


def decrypt_python(cipher, period, dims, side, cell_of, grid):
    n = len(cipher)
    out = bytearray(n)
    block = period if period > 0 else n
    for b in range(0, n, block):
        length = min(block, n - b)
        seq = []
        for k in range(length):
            cell = cell_of[cipher[b + k]]
            coords = []
            for _ in range(dims):
                coords.append(cell % side)
                cell //= side
            seq.extend(reversed(coords))
        for k in range(length):
            cell = 0
            for j in range(dims):
                cell = cell * side + seq[j * length + k]
            out[b + k] = grid[cell]
    return bytes(out)


def encrypt(plain, period, dims, side, cell_of, grid):
    n = len(plain)
    out = bytearray(n)
    block = period if period > 0 else n
    for b in range(0, n, block):
        length = min(block, n - b)
        rows = [[0] * length for _ in range(dims)]
        for k in range(length):
            cell = cell_of[plain[b + k]]
            for j in range(dims - 1, -1, -1):
                rows[j][k] = cell % side
                cell //= side
        seq = [value for row in rows for value in row]
        for k in range(length):
            cell = 0
            for j in range(dims):
                cell = cell * side + seq[k * dims + j]
            out[b + k] = grid[cell]
    return bytes(out)


def make_decryptor(cipher, period, kind):
    """decrypt(cell_of, grid) -> plaintext symbols; C when available."""
    spec = KINDS[kind]
    dims, side = spec["dims"], spec["side"]
    try:
        import native
        i32, p = ctypes.c_int32, ctypes.c_char_p
        function = native.function("cct_fraction_decrypt", None, [p, i32, i32, i32, i32, p, p, p])
    except Exception:
        function = None
    if function is not None:
        cipher = bytes(cipher)
        out = ctypes.create_string_buffer(len(cipher))

        def decrypt(cell_of, grid):
            function(cipher, len(cipher), period, dims, side, bytes(cell_of), bytes(grid), out)
            return out.raw
        return decrypt
    return lambda cell_of, grid: decrypt_python(cipher, period, dims, side, cell_of, grid)


def _to_az_table(kind):
    """Plaintext symbol -> 0-25 letter code for n-gram scoring ('+' counts as X)."""
    symbols = KINDS[kind]["symbols"]
    return bytes((ord(ch) - 65) if ch != "+" else 23 for ch in symbols) + bytes(256 - len(symbols))


def solve(ciphertext, period, kind="bifid", iterations=400_000, seed=None, t_start=10.0):
    """One annealing run. Returns (fitness, key string, plaintext string)."""
    import cipher_profile as cp
    if seed is not None:
        random.seed(seed)
    spec = KINDS[kind]
    symbols = spec["symbols"]
    count = len(symbols)
    cipher = to_symbols(ciphertext, kind)
    decrypt = make_decryptor(cipher, period, kind)
    to_az = _to_az_table(kind)
    fitness = cp.fitness_function()
    grid = random.sample(range(count), count)
    cell_of = [0] * count
    for cell, symbol in enumerate(grid):
        cell_of[symbol] = cell
    last = []

    def score():
        return fitness(decrypt(cell_of, grid).translate(to_az))

    def swap(i, j):
        grid[i], grid[j] = grid[j], grid[i]
        cell_of[grid[i]], cell_of[grid[j]] = i, j

    def propose():
        i, j = random.sample(range(count), 2)
        swap(i, j)
        last[:] = [i, j]
        return score()

    def undo():
        swap(*last)

    best_grid, _ = anneal(score(), propose, undo, lambda: grid[:], Schedule(iterations, t_start))
    grid[:] = best_grid
    for cell, symbol in enumerate(grid):
        cell_of[symbol] = cell

    def apply_move(move):
        swap(*move)
        last[:] = list(move)
        return score()
    final = hill_climb(score(), [(i, j) for i in range(count) for j in range(i + 1, count)], apply_move, undo, 10)
    plain = "".join(symbols[s] for s in decrypt(cell_of, grid))
    return final, "".join(symbols[s] for s in grid), plain


def solve_job(job):
    return (job['period'],) + solve(job['ciphertext'], job['period'], job['kind'], job['iterations'], job['seed'])


def run():
    import time
    from concurrent.futures import ProcessPoolExecutor, as_completed
    import native
    import cipher_profile as cp
    banner("Bifid / Trifid Solver", "Ciphertext only: anneal the square (Bifid) or cube (Trifid) for each period")
    text = input(f"{GREY}Enter ciphertext: {RESET}")
    kind = "trifid" if input("Cipher: (1) Bifid 5x5 [default]  (2) Trifid 3x3x3: ").strip() == "2" else "bifid"
    cipher = to_symbols(text, kind)
    if len(cipher) < 60:
        print(f"{RED}Need at least 60 letters.{RESET}")
        return
    if kind == "bifid" and "J" in text.upper():
        print(f"{YELLOW}The text contains J: a 5x5 Bifid has no J (J is read as I here).{RESET}")
    answer = input("Periods, e.g. 5 or 3-10, 0 = whole text (Enter = 3-12 and 0): ").strip()
    if answer:
        low, _, high = answer.partition("-")
        periods = list(range(int(low), int(high or low) + 1))
    else:
        periods = list(range(3, 13)) + [0]
    steps = input("Annealing steps per run (Enter = 400,000): ").strip().replace(",", "")
    steps = int(steps) if steps.isdigit() else 400_000
    runs = input("Runs per period (Enter = 4): ").strip()
    runs = int(runs) if runs.isdigit() and int(runs) > 0 else 4
    jobs = [{'ciphertext': text, 'period': p, 'kind': kind, 'iterations': steps, 'seed': random.randrange(2 ** 32)}
            for p in periods for _ in range(runs)]
    workers = max(1, min(len(jobs), (os.cpu_count() or 2) - 1))
    if not native.available():
        print(f"{YELLOW}C engines not built (menu 45): decryption runs in Python, about 10x slower.{RESET}")
    print(f"{GREY}{len(jobs)} runs on {workers} processes...{RESET}")
    started, results = time.time(), []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(solve_job, job) for job in jobs]
        for done, future in enumerate(as_completed(futures), start=1):
            results.append(future.result())
            best = max(results, key=lambda r: r[1])
            print(f"  {done}/{len(jobs)} runs | best: period {best[0]}, fitness {best[1]:.1f}", end="\r")
    results.sort(key=lambda r: -r[1])
    refs = cp.references(len(cipher))
    print(f"\n{BOLD}Best results{RESET} {GREY}({time.time() - started:.0f} s){RESET}")
    for period, score, key, plain in results[:6]:
        agreeing = sum(1 for r in results if r[3] == plain)
        verdict = cp.judge(score, refs)
        colour = GREEN if verdict == "reads as English" else YELLOW if verdict == "partly English" else GREY
        print(f"\nperiod {period or 'whole text'}: key {CYAN}{key}{RESET} fitness {score:.1f} "
              f"{colour}[{verdict}]{RESET} ({agreeing} run(s) agree)\n   {plain[:100]}")


if __name__ == "__main__":
    run()
