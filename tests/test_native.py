"""The native (C) and GPU (OpenCL) engines must give the Python code's results.

Run from the repository root:  python -m unittest discover -s tests -t .
Tests that need the C library or a GPU are skipped when those are missing
(build with: python -m pip install ziglang && python scripts/native_tools.py build).
"""
import os
import random
import sys
import unittest
from itertools import permutations

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import native  # noqa: E402
from native import crib  # noqa: E402
from ngram_scoring import load_ngram_scores, ngram_total, resolve_ngram_path, text_to_codes  # noqa: E402
from transposition_core import make_decryptor, make_permuter  # noqa: E402

LAYOUTS = ("write_rows_read_cols", "write_rows_read_rows", "write_cols_read_rows", "write_cols_read_cols")
ENGLISH = ("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGWHILETHEFARMERWATCHESFROMTHEPORCHANDTHESUNSETSBEHINDTHE"
           "HILLSTHECHILDRENPLAYINTHEFIELDUNTILTHEIRMOTHERCALLSTHEMHOMEFORSUPPERANDTHEDAYCOMESTOANEND")


def need_native(test):
    if not native.available():
        test.skipTest("native engines not built (python scripts/native_tools.py build)")


def encrypt_columnar(plain_codes, width, layout, order):
    """Ciphertext c with make_permuter(c, order) == plain (encryption for the layout)."""
    n = len(plain_codes)
    src = make_permuter(n, width, layout)(bytes(range(n)), list(order))
    out = [0] * n
    for i, s in enumerate(src):
        out[s] = plain_codes[i]
    return bytes(out)



def reference_records(codes, crib_pos, valtab, ncombo, width, mode, prefix, periods, min_checks,
                   start_tail=None, max_orders=None):
    """Test-only reference search (the toolkit runs the C engine): ([(column order, combo, order, period, checks)], orders)."""
    ncrib = len(crib_pos)
    fixed = [(period, crib.same_slot_pairs(crib_pos, period)) for period in periods]
    rest = sorted(c for c in range(width) if c not in prefix)
    records, orders = [], 0
    tails = permutations(rest)
    if start_tail is not None:
        tails = (t for t in permutations(rest) if list(t) >= list(start_tail))
    for tail in tails:
        if max_orders is not None and orders >= max_orders:
            break
        key = list(prefix) + list(tail)
        src = crib.source_positions(len(codes), width, mode, key)
        slots = [src[p] for p in crib_pos]
        letters = [codes[s] for s in slots]
        moving = [(period, crib.same_slot_pairs(slots, period)) for period in periods]
        orders += 1
        for combo in range(ncombo):
            values = [valtab[(combo * ncrib + k) * 26 + letters[k]] for k in range(ncrib)]
            for order, plan in ((0, fixed), (1, moving)):
                for period, pairs in plan:
                    if len(pairs) >= min_checks and all(values[a] == values[b] for a, b in pairs):
                        records.append((key, combo, order, period, len(pairs)))
    return records, orders


class DescriptorTests(unittest.TestCase):
    def test_descriptors_match_make_permuter(self):
        rng = random.Random(1)
        for length in (13, 50, 97, 98, 200, 256):
            for width in range(2, 17):
                if width > length:
                    continue
                for layout in LAYOUTS:
                    read_rows, lengths, remainder, partial_base, desc = native.columnar_descriptors(
                        length, width, layout, range(length))
                    permute = make_permuter(length, width, layout)
                    for _ in range(3):
                        key = rng.sample(range(width), width)
                        start, rank, prank, s, pr = {}, {}, {}, 0, 0
                        for j, c in enumerate(key):
                            start[c], rank[c] = s, j
                            s += lengths[c]
                            if c < remainder:
                                prank[c], pr = pr, pr + 1
                        got = [start[c] + b if k == 0 else rank[c] + b if k == 1 else partial_base + prank[c]
                               for c, b, k in desc]
                        self.assertEqual(got, list(permute(bytes(range(length)), key)), (length, width, layout))

    def test_long_text_positions_match_make_permuter_on_letters(self):
        rng = random.Random(2)
        for length in (300, 517):
            for width in (7, 13):
                for layout in LAYOUTS:
                    key = rng.sample(range(width), width)
                    src = crib.source_positions(length, width, layout, key)
                    for _ in range(2):
                        codes = bytes(rng.randrange(26) for _ in range(length))
                        self.assertEqual(bytes(codes[s] for s in src), make_decryptor(codes, width, layout)(key))


class TranspositionSearchTests(unittest.TestCase):
    def setUp(self):
        need_native(self)

    def test_bruteforce_matches_the_python_loop(self):
        from native import perm
        rng = random.Random(3)
        for size in (3, 4):
            model = load_ngram_scores(resolve_ngram_path(size))
            for width in range(2, 8):
                for layout in LAYOUTS:
                    order = rng.sample(range(width), width)
                    for text in (encrypt_columnar(text_to_codes(ENGLISH[:90]), width, layout, order),
                                 bytes(rng.randrange(26) for _ in range(61))):
                        ciphertext = "".join(chr(c + 65) for c in text)
                        decrypt = make_decryptor(text, width, layout)
                        best, best_total = None, -1
                        for p in permutations(range(width)):          # the solver's loop, by n-gram total
                            total = ngram_total(decrypt(p), model.scores, size)
                            if total > best_total:
                                best, best_total = list(p), total
                        self.assertEqual(perm.best_order(ciphertext, width, layout, model), best,
                                         (size, width, layout))

    def test_order_total_matches_ngram_total(self):
        from native import perm
        rng = random.Random(4)
        model = load_ngram_scores(resolve_ngram_path(5))
        codes = bytes(rng.randrange(26) for _ in range(333))
        for width in (3, 9, 20):
            for layout in LAYOUTS:
                order = rng.sample(range(width), width)
                self.assertEqual(perm.order_total(codes, width, layout, model, order),
                                 ngram_total(make_decryptor(codes, width, layout)(order), model.scores, 5))

    def test_annealing_recovers_a_planted_transposition(self):
        from native import perm
        from transposition_core import letter_entropy
        model = load_ngram_scores(resolve_ngram_path(4))
        rng = random.Random(5)
        random.seed(5)
        plain = text_to_codes(ENGLISH)
        for width, layout in ((8, "write_rows_read_cols"), (11, "write_cols_read_rows")):
            order = rng.sample(range(width), width)
            ciphertext = "".join(chr(c + 65) for c in encrypt_columnar(plain, width, layout, order))
            factor = letter_entropy(plain) ** 0.5
            start = list(range(width))
            random.shuffle(start)
            best, score = perm.anneal(ciphertext, width, layout, model, factor, start, 20.0, 0.97, 300, 1)
            count = len(plain) - 3
            found = make_decryptor(text_to_codes(ciphertext), width, layout)(best)
            # the reported score is the solvers' fitness of the returned order ...
            self.assertEqual(score, (ngram_total(found, model.scores, 4) / count) * factor)
            # ... and the climb reached at least the true key's fitness. (It may find a better-scoring
            # neighbour: with width 8 here, shifting every column by one reads the text one letter later,
            # which this 4-gram model scores higher than the true text.)
            self.assertGreaterEqual(score, (ngram_total(plain, model.scores, 4) / count) * factor, (width, layout))


class KnownPlaintextTests(unittest.TestCase):
    def setUp(self):
        need_native(self)

    def cases(self):
        rng = random.Random(6)
        for length in (60, 97, 300):
            codes = bytes(rng.randrange(26) for _ in range(length))
            start = rng.randrange(0, length - 30)
            crib_pos = list(range(start, start + 12)) + list(range(start + 20, start + 28))
            crib_plain = [rng.randrange(26) for _ in crib_pos]
            yield codes, crib_pos, crib_plain

    def test_python_c_and_gpu_agree(self):
        from native import gpu, opencl
        combos = crib.make_combos({"AZ": crib.ALPHABET, "KW": "ZEBRASCDFGHIJKLMNOPQTUVWXY"})
        for codes, crib_pos, crib_plain in self.cases():
            valtab = crib.value_table(combos, crib_plain)
            for width, prefix in ((5, ()), (7, ()), (9, (3, 0))):
                for layout in LAYOUTS:
                    args = (codes, crib_pos, valtab, len(combos), width, layout, prefix, list(range(1, 31)), 2)
                    python = reference_records(*args)
                    self.assertEqual(python, crib.native_records(*args), (len(codes), width, layout))
                    if opencl.pick_device() is not None and len(codes) <= 256:
                        self.assertEqual(sorted(python[0]), sorted(gpu.crib_records(*args)[0]))

    def test_planted_solution_is_found(self):
        rng = random.Random(7)
        plain = text_to_codes(ENGLISH[:120])
        width, layout, order, period = 7, "write_rows_read_cols", [3, 0, 6, 2, 5, 1, 4], 6
        key = [rng.randrange(26) for _ in range(period)]
        middle = bytes((p + key[i % period]) % 26 for i, p in enumerate(plain))        # Vigenere, then transpose
        ciphertext = "".join(chr(c + 65) for c in encrypt_columnar(middle, width, layout, order))
        known = [(i, chr(plain[i] + 65)) for i in list(range(10, 22)) + list(range(60, 70))]
        from crib_columnar_search import run_search
        hits, tests, min_checks, combos = run_search(ciphertext, known, range(7, 8), range(1, 13),
                                                     {"AZ": crib.ALPHABET}, report=lambda *_: None)
        found = [h for h in hits if h["column_order"] == order and h["layout"] == layout and h["period"] == period
                 and h["combo"] == "AZ/AZ vigenere" and h["order"] == crib.ORDERS[0]]
        self.assertTrue(found)
        self.assertTrue(all(ch == "?" or ch == chr(p + 65) for ch, p in zip(found[0]["plaintext"], plain)))


class GpuTests(unittest.TestCase):
    def setUp(self):
        from native import opencl
        need_native(self)
        if opencl.pick_device() is None:
            self.skipTest("no OpenCL GPU")

    def test_gpu_bruteforce_matches_cpu(self):
        from native import gpu, opencl
        model = load_ngram_scores(resolve_ngram_path(4))
        rng = random.Random(8)
        for _, _, props in opencl.devices():
            os.environ["CCT_GPU_DEVICE"] = props["name"]
            gpu._contexts.clear()
            try:
                for width in (6, 8, 9):
                    for layout in LAYOUTS:
                        codes = bytes(rng.randrange(26) for _ in range(150))
                        ciphertext = "".join(chr(c + 65) for c in codes)
                        os.environ["CCT_GPU"] = "0"
                        from native import perm
                        cpu = perm.best_order(ciphertext, width, layout, model)
                        self.assertEqual(gpu.best_order(codes, width, layout, model), cpu, (props["name"], width))
            finally:
                os.environ.pop("CCT_GPU_DEVICE", None)
                os.environ.pop("CCT_GPU", None)
                gpu._contexts.clear()


if __name__ == "__main__":
    unittest.main()
