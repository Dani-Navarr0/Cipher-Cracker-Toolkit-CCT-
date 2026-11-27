"""Route and irregular transpositions: screen a text against every family in
transposition_families.py and rank the readings by n-gram fitness.

Use it on a text whose letters are already the plaintext letters (a
transposition only: English-like IoC and letter frequencies), or on what is
left after removing a substitution/periodic layer. For a transposition plus a
simple substitution, use tool 37 instead.
"""
import os
import time
from concurrent.futures import ProcessPoolExecutor

import transposition_families as tf
from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner, option

WORDLIST = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")


def describe(info):
    return ", ".join(f"{key}={value}" for key, value in info.items())


def _score_sources(args):
    """Score a list of (info, src) on codes; return the best ``top``."""
    codes, sources, top = args
    import cipher_profile as cp
    fitness = cp.fitness_function()
    best = []
    for info, src in sources:
        for reverse in (False, True):
            source = codes[::-1] if reverse else codes
            plain = bytes(source[i] for i in src)
            best.append((fitness(plain), dict(info, text_reversed=reverse), plain))
        if len(best) > 20 * top:
            best = sorted(best, key=lambda b: -b[0])[:top]
    return sorted(best, key=lambda b: -b[0])[:top]


def keyless_sources(n, max_width=None, offsets=False):
    max_width = max_width or min(60, n // 2)
    yield from tf.route_sources(n, range(2, max_width + 1))
    yield from tf.rail_fence_sources(n, range(2, min(60, n - 1) + 1))
    yield from tf.redefence_sources(n, range(3, 8))
    yield from tf.double_rotation_sources(n, range(2, min(40, n // 2) + 1))
    if offsets:
        yield from tf.offset_grid_sources(n, range(2, min(40, n // 2) + 1))


def keyword_ranks(word):
    """Letter ranks of a keyword (equal letters share a rank), for Myszkowski."""
    letters = sorted(set(word))
    return [letters.index(ch) for ch in word]


def keyword_sources(n, words):
    """Myszkowski and AMSCO for every distinct keyword pattern."""
    seen_mysz, seen_amsco = set(), set()
    for word in words:
        if not 3 <= len(word) < n // 2:
            continue
        ranks = tuple(keyword_ranks(word))
        if len(set(ranks)) < len(ranks) and ranks not in seen_mysz:   # Myszkowski differs only with repeats
            seen_mysz.add(ranks)
            for direction, src in tf.both_directions(tf.myszkowski_order(n, list(ranks))).items():
                yield {"transposition": "myszkowski", "keyword": word, "direction": direction}, src
        order = tuple(index for _, index in sorted((ch, i) for i, ch in enumerate(word)))
        if order not in seen_amsco:
            seen_amsco.add(order)
            for first in (1, 2):
                for rule in ("continue", "alternate_rows"):
                    for direction, src in tf.both_directions(tf.amsco_order(n, list(order), first, rule)).items():
                        yield ({"transposition": "amsco", "keyword": word, "first_cell": first, "rows": rule,
                                "direction": direction}, src)


def exhaustive_irregular_sources(n, max_width=7):
    """Every column order up to ``max_width`` for AMSCO, and every rank pattern
    with ties up to ``max_width`` for Myszkowski."""
    from itertools import permutations, product
    for width in range(2, max_width + 1):
        for order in permutations(range(width)):
            for first in (1, 2):
                for rule in ("continue", "alternate_rows"):
                    for direction, src in tf.both_directions(tf.amsco_order(n, list(order), first, rule)).items():
                        yield ({"transposition": "amsco", "order": list(order), "first_cell": first, "rows": rule,
                                "direction": direction}, src)
        seen = set()
        for ranks in product(range(width), repeat=width):
            used = sorted(set(ranks))
            if used != list(range(len(used))) or len(used) == width or ranks in seen:
                continue
            seen.add(ranks)
            for direction, src in tf.both_directions(tf.myszkowski_order(n, list(ranks))).items():
                yield {"transposition": "myszkowski", "ranks": list(ranks), "direction": direction}, src


def screen(codes, sources, top=10, workers=None, chunk=4000, report=None):
    """Score every source in parallel; returns the best ``top`` (score, info, plain)."""
    workers = workers or max(1, (os.cpu_count() or 2) - 1)
    best, batch, tested, futures = [], [], 0, []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for info, src in sources:
            batch.append((info, src))
            if len(batch) >= chunk:
                futures.append(pool.submit(_score_sources, (codes, batch, top)))
                tested += len(batch)
                batch = []
                if len(futures) >= 4 * workers:          # keep memory bounded
                    best += futures.pop(0).result()
                    if report:
                        report(tested)
        if batch:
            futures.append(pool.submit(_score_sources, (codes, batch, top)))
            tested += len(batch)
        for future in futures:
            best += future.result()
    return sorted(best, key=lambda b: -b[0])[:top], tested


def run():
    import cipher_profile as cp
    from ngram_scoring import codes_to_text, text_to_codes
    banner("Route & Irregular Transpositions", "Routes, spirals, rail/redefence, double rotation, Myszkowski, AMSCO")
    codes = text_to_codes(input(f"{GREY}Enter ciphertext: {RESET}"))
    n = len(codes)
    if n < 12:
        print(f"{RED}Need at least 12 letters.{RESET}")
        return
    if n >= cp.MIN_LETTERS and cp.ioc(codes) < 0.055:
        print(f"{YELLOW}The IoC is {cp.ioc(codes):.4f}: letter frequencies look flattened, so this is probably not a "
              f"transposition alone. Remove the other layer first (tool 39 shows which).{RESET}")
    option(1, "Keyless: routes, spirals, diagonals, rail fence, redefence, double rotation", "(seconds)")
    option(2, "As 1, plus routes starting part-way into the first row", "(slower)")
    option(3, "Myszkowski and AMSCO with every dictionary keyword", "(about a minute)")
    option(4, "Myszkowski and AMSCO, every key up to width 7", "(about a minute)")
    choice = input("Select (Enter = 1): ").strip() or "1"
    if choice in ("1", "2"):
        sources = keyless_sources(n, offsets=choice == "2")
    elif choice == "3":
        with open(WORDLIST, encoding="utf-8") as handle:
            words = [w.strip().upper() for w in handle if w.strip()]
        sources = keyword_sources(n, words)
    elif choice == "4":
        sources = exhaustive_irregular_sources(n)
    else:
        print(f"{RED}Invalid choice.{RESET}")
        return
    started = time.time()
    results, tested = screen(codes, sources, report=lambda done: print(f"  {done:,} tested...", end="\r"))
    refs = cp.references(n) if n >= cp.MIN_LETTERS else None
    print(f"\n{BOLD}{tested:,} transpositions tested (each also on the reversed text) in "
          f"{time.time() - started:.0f} s{RESET}")
    for rank, (score, info, plain) in enumerate(results, start=1):
        verdict = cp.judge(score, refs) if refs else ""
        colour = GREEN if verdict == "reads as English" else YELLOW if verdict == "partly English" else GREY
        print(f"\n{rank}. {CYAN}{describe(info)}{RESET}\n   fitness {score:.1f} {colour}[{verdict}]{RESET}  "
              f"{codes_to_text(plain)[:90]}")


if __name__ == "__main__":
    run()
