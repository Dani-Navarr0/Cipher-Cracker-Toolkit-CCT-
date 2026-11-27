"""Route and irregular transpositions: screen a text against every family in
transposition_families.py and rank the readings by n-gram fitness.

Use it on a text whose letters are already the plaintext letters (a
transposition only: English-like IoC and letter frequencies), or on what is
left after removing a substitution/periodic layer. For a transposition plus a
simple substitution, use tool 61 instead.
"""
import os
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import native
import transposition_families as tf
from native.screens import AMSCO, BOTH, MYSZKOWSKI, Sources
from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner, option

WORDLIST = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")


def describe(info):
    return ", ".join(f"{key}={value}" for key, value in info.items())


def keyless_sources(n, max_width=None, offsets=False):
    """Routes, rail fence, redefence and double rotation (plus offset grids):
    a native.screens.Sources, generated and scored in C."""
    max_width = max_width or min(60, n // 2)
    parts = [tf.route_sources(n, range(2, max_width + 1)),
             tf.rail_fence_sources(n, range(2, min(60, n - 1) + 1)),
             tf.redefence_sources(n, range(3, 8)),
             tf.double_rotation_sources(n, range(2, min(40, n // 2) + 1))]
    if offsets:
        parts.append(tf.offset_grid_sources(n, range(2, min(40, n // 2) + 1)))
    return Sources.chain(n, parts)


def keyword_ranks(word):
    """Letter ranks of a keyword (equal letters share a rank), for Myszkowski."""
    letters = sorted(set(word))
    return [letters.index(ch) for ch in word]


def keyword_sources(n, words):
    """Myszkowski and AMSCO for every distinct keyword pattern. Per word of
    3 <= length < n // 2: Myszkowski (ranks of keyword_ranks) when the word
    repeats a letter and that rank pattern is new; then AMSCO with the columns in
    alphabetical order of their letters (ties left to right) when that order is
    new, with first cell 1/2 x rows continue/alternate_rows, each in both
    directions. The words are turned into these records in C."""
    from native.screens import keyword_sources as records
    return records(n, words)


def _weak_orders(width):
    """Rank patterns of ``width`` columns that use ranks 0..k-1 with at least one
    tie (k < width), in lexicographic order (itertools.product order)."""
    ranks = [0] * width

    def place(position, used, top):
        if position == width:
            if len(used) < width and top + 1 == len(used):
                yield tuple(ranks)
            return
        remaining = width - position
        for value in range(width):
            new_top = max(top, value)
            missing = new_top + 1 - len(used | {value})
            if missing > remaining - 1:          # ranks below the top that could no longer be filled
                continue
            ranks[position] = value
            yield from place(position + 1, used | {value}, new_top)

    yield from place(0, frozenset(), -1)


def exhaustive_irregular_sources(n, max_width=7):
    """Every column order up to ``max_width`` for AMSCO, and every rank pattern
    with ties up to ``max_width`` for Myszkowski."""
    from itertools import permutations
    sources = Sources(n)
    for width in range(2, max_width + 1):
        for order in permutations(range(width)):
            sources.add(AMSCO, key=order, meta=("amsco", "order", order))
        for ranks in _weak_orders(width):
            sources.add(MYSZKOWSKI, key=ranks, meta=("myszkowski", "ranks", ranks))
    return sources


def _explicit_blocks(n, sources, chunk):
    """Arbitrary (info, src) pairs, in Sources blocks of ``chunk`` explicit sources."""
    block = Sources(n)
    for info, src in sources:
        block.add_explicit(info, src)
        if len(block) >= chunk:
            yield block
            block = Sources(n)
    if len(block):
        yield block


def _family_blocks(sources, workers):
    """Slices of a Sources, small enough for progress lines and Ctrl+C."""
    per_record = max(1, sources.max_sources() // max(1, len(sources)))
    size = max(1, min(-(-len(sources) // (4 * workers)), 40_000 // per_record))
    for start in range(0, len(sources), size):
        yield sources.block(start, min(len(sources), start + size)), start


def screen(codes, sources, top=10, workers=None, chunk=4000, report=None):
    """Score every source on the text and on its reverse (C engine, several
    threads); returns the best ``top`` (score, info, plain) and the number of
    sources tested. ``sources``: a native.screens.Sources (generated in C) or
    any iterable of (info, src)."""
    import cipher_profile as cp
    native.require()
    n = len(codes)
    fitness = cp.fitness_function()
    import compute
    workers = workers or compute.workers()
    if isinstance(sources, Sources):
        blocks = _family_blocks(sources, workers)
    else:
        blocks = ((block, 0) for block in _explicit_blocks(n, sources, chunk))

    def run_block(block, base):
        tested, best = block.score(codes, fitness, top=top, text=BOTH)
        plains = block.plain(codes, [ident for _, ident in best])
        return tested, [(score, base, ident, dict(block.info(ident), text_reversed=bool(ident & 1)), plain)
                        for (score, ident), plain in zip(best, plains)]

    best, tested, pending, index = [], 0, set(), 0
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        for block, base in blocks:
            pending.add(pool.submit(run_block, block, (index, base)))
            index += 1
            while len(pending) >= 2 * workers:
                done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                tested, best = _collect(done, tested, best, top, report)
        while pending:
            done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
            tested, best = _collect(done, tested, best, top, report)
    except KeyboardInterrupt:
        print("\nScreen interrupted; showing the best readings so far.")
    finally:
        pool.shutdown(wait=True, cancel_futures=True)     # running C blocks are short
    return [(score, info, plain) for score, _, _, info, plain in best], tested


def _collect(done, tested, best, top, report):
    for future in done:
        count, found = future.result()
        tested += count
        best += found
    # ties keep the generation order (block index, then id), as a stable sort would
    best = sorted(best, key=lambda b: (-b[0], b[1], b[2]))[:top]
    if report and done:
        report(tested)
    return tested, best


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
              f"transposition alone. Remove the other layer first (tool 1 shows which).{RESET}")
    option(1, "Keyless: routes, spirals, diagonals, rail fence, redefence, double rotation", "(under a second)")
    option(2, "As 1, plus routes starting part-way into the first row", "(under a second)")
    option(3, "Myszkowski and AMSCO with every dictionary keyword", "(a few seconds)")
    option(4, "Myszkowski and AMSCO, every key up to width 7", "(under a second)")
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
