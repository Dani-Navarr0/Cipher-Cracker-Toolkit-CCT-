"""Tests for the square-key C engines (native/digraphic.c, digraphic_hill.c):
Playfair / Four-square / Bifid-Trifid annealing, the Playfair keyword attack
and the Hill row attack. Planted ciphertexts and known answers; the few-line
Python versions below are test-only references.
Run: python -m unittest tests.test_c_digraphic"""
import math
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts"), os.path.join(ROOT, "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

import native  # noqa: E402
from ngram_scoring import codes_to_text, load_ngram_scores, text_to_codes  # noqa: E402
from test_cipher_profile import PLAINTEXT  # noqa: E402

NATIVE = native.available()
PLAIN = codes_to_text(PLAINTEXT).replace("J", "I")
SQ = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def fitness():
    import cipher_profile as cp
    return cp.fitness_function()


# ---- test-only references

def ref_playfair_encrypt(plain, grid, dim=5):
    """Playfair encryption on a dim x dim square (cell -> symbol); plain: symbol indices, even length."""
    pos = {s: c for c, s in enumerate(grid)}
    out = []
    for i in range(0, len(plain), 2):
        (ra, ca), (rb, cb) = divmod(pos[plain[i]], dim), divmod(pos[plain[i + 1]], dim)
        if ra == rb:
            out += [grid[ra * dim + (ca + 1) % dim], grid[rb * dim + (cb + 1) % dim]]
        elif ca == cb:
            out += [grid[((ra + 1) % dim) * dim + ca], grid[((rb + 1) % dim) * dim + cb]]
        else:
            out += [grid[ra * dim + cb], grid[rb * dim + ca]]
    return out


def ref_foursquare_encrypt(plain, tr, bl):
    out = []
    for i in range(0, len(plain), 2):
        (ra, ca), (rb, cb) = divmod(plain[i], 5), divmod(plain[i + 1], 5)
        out += [tr[ra * 5 + cb], bl[rb * 5 + ca]]
    return out


ENGLISH_PERCENT = [8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61,
                   6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07]


def ref_hill_rows(cipher, size, keep):
    """Stage 1 of the old Python row attack: (chi, row) of the `keep` best rows."""
    import itertools
    scored = []
    for row in itertools.product(range(26), repeat=size):
        g = 0
        for value in row:
            g = math.gcd(g, value)
        if math.gcd(g, 26) != 1:
            continue
        out = bytes(sum(r * c for r, c in zip(row, cipher[i:i + size])) % 26 for i in range(0, len(cipher), size))
        total = len(out)
        chi = sum((out.count(c) - ENGLISH_PERCENT[c] * total / 100) ** 2 / (ENGLISH_PERCENT[c] * total / 100)
                  for c in range(26))
        scored.append((chi, row))
    scored.sort(key=lambda entry: entry[0])
    return scored[:keep]


def ref_ioc(text):
    letters = [ch for ch in text if "A" <= ch <= "Z"]
    n = len(letters)
    return sum(letters.count(c) * (letters.count(c) - 1) for c in set(letters)) / (n * (n - 1)) if n > 1 else 0.0


def swapped(key, rng, count=2):
    key = list(key)
    for _ in range(count):
        i, j = rng.sample(range(len(key)), 2)
        key[i], key[j] = key[j], key[i]
    return key


@unittest.skipUnless(NATIVE, "native library not built")
class AnnealEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = load_ngram_scores()

    def test_playfair_decrypt_and_fitness_match_python(self):
        import playfair_anneal as pa
        from native import digraphic
        rng = random.Random(1)
        fit = fitness()
        cipher = pa.prepare(PLAIN[:200])
        native_cipher = pa._cipher(cipher, self.model)
        for _ in range(20):
            grid = rng.sample(range(25), 25)
            score, plain = digraphic.score(native_cipher, [grid])
            self.assertEqual(plain, pa.Square(grid).decrypt(cipher))
            self.assertAlmostEqual(score, fit(pa.to_az(plain)), places=9)

    def test_foursquare_and_fraction_decrypt_match_python(self):
        import four_square as fq
        import fractionation_solver as fs
        from native import digraphic
        rng = random.Random(2)
        fit = fitness()
        text = PLAIN[:200]
        symbols = bytes(SQ.index(ch) for ch in text)
        cipher = digraphic.make_cipher(digraphic.FOURSQUARE, symbols, 25, fq.TO_AZ, self.model)
        for _ in range(10):
            tr, bl = rng.sample(range(25), 25), rng.sample(range(25), 25)
            score, plain = digraphic.score(cipher, [tr, bl])
            expected = fq.decrypt_foursquare(text, "".join(SQ[x] for x in tr), "".join(SQ[x] for x in bl))
            self.assertEqual("".join(SQ[x] for x in plain), expected)
            self.assertAlmostEqual(score, fit(text_to_codes(expected)), places=9)
        for kind in ("bifid", "trifid"):
            spec = fs.KINDS[kind]
            count = len(spec["symbols"])
            plain = fs.to_symbols(PLAIN[:200], kind)
            for period in (0, 5, 7):
                grid = rng.sample(range(count), count)
                cell_of = [0] * count
                for cell, symbol in enumerate(grid):
                    cell_of[symbol] = cell
                encrypted = fs.encrypt(plain, period, spec["dims"], spec["side"], cell_of, grid)
                cipher = digraphic.make_cipher(digraphic.FRACTION, encrypted, count, fs._to_az_table(kind),
                                               self.model, period=period, dims=spec["dims"], side=spec["side"])
                score, decrypted = digraphic.score(cipher, [grid])
                self.assertEqual(decrypted, plain)
                self.assertEqual(decrypted, fs.make_decryptor(encrypted, period, kind)(cell_of, grid))
                self.assertAlmostEqual(score, fit(bytes(fs._to_az_table(kind)[s] for s in plain)), places=9)

    def test_polish_recovers_a_nearby_key(self):
        import fractionation_solver as fs
        import playfair_anneal as pa
        from native import digraphic
        rng = random.Random(3)
        # Playfair
        grid = rng.sample(range(25), 25)
        plain = pa.prepare(PLAIN[:300])
        cipher = bytes(ref_playfair_encrypt(plain, grid))
        native_cipher = pa._cipher(cipher, self.model)
        _, keys = digraphic.anneal(native_cipher, [swapped(grid, rng)], 1, 1e-9, 1e-9, seed=1, polish_rounds=20)
        self.assertEqual(digraphic.score(native_cipher, keys)[1], plain)
        # Four-square
        tr, bl = rng.sample(range(25), 25), rng.sample(range(25), 25)
        plain = bytes(SQ.index(ch) for ch in PLAIN[:300])
        cipher = digraphic.make_cipher(digraphic.FOURSQUARE, bytes(ref_foursquare_encrypt(plain, tr, bl)), 25,
                                       bytes(ord(ch) - 65 for ch in SQ), self.model)
        _, keys = digraphic.anneal(cipher, [swapped(tr, rng, 1), swapped(bl, rng, 1)], 1, 1e-9, 1e-9, seed=1)
        self.assertEqual(keys, [tr, bl])
        # Trifid
        spec = fs.KINDS["trifid"]
        grid = rng.sample(range(27), 27)
        cell_of = [0] * 27
        for cell, symbol in enumerate(grid):
            cell_of[symbol] = cell
        plain = fs.to_symbols(PLAIN[:300], "trifid")
        cipher = digraphic.make_cipher(digraphic.FRACTION, fs.encrypt(plain, 6, 3, 3, cell_of, grid), 27,
                                       fs._to_az_table("trifid"), self.model, period=6, dims=spec["dims"],
                                       side=spec["side"])
        _, keys = digraphic.anneal(cipher, [swapped(grid, rng)], 1, 1e-9, 1e-9, seed=1)
        self.assertEqual(digraphic.score(cipher, keys)[1], plain)

    def test_chunked_runs_are_resumable(self):
        """The same seed gives the same run whatever the chunk size (the state carries over)."""
        import four_square as fq
        from native import digraphic
        rng = random.Random(4)
        tr, bl = rng.sample(range(25), 25), rng.sample(range(25), 25)
        plain = bytes(SQ.index(ch) for ch in PLAIN[:200])
        cipher = digraphic.make_cipher(digraphic.FOURSQUARE, bytes(ref_foursquare_encrypt(plain, tr, bl)), 25,
                                       fq.TO_AZ, self.model)
        start = [rng.sample(range(25), 25), rng.sample(range(25), 25)]
        reports = []
        one = digraphic.anneal(cipher, start, 30_000, 20.0, seed=77)
        many = digraphic.anneal(cipher, start, 30_000, 20.0, seed=77, chunk=7_000,
                                report=lambda step, temp, best, keys: reports.append((step, temp)))
        self.assertEqual(one, many)
        self.assertEqual([step for step, _ in reports], [7_000, 14_000, 21_000, 28_000, 30_000])
        self.assertAlmostEqual(reports[-1][1], 0.1, places=9)      # cooled to t_end

    def test_ctrl_c_between_chunks_keeps_the_best_key(self):
        import fractionation_solver as fs
        from native import digraphic
        rng = random.Random(6)
        cipher = digraphic.make_cipher(digraphic.FRACTION, fs.to_symbols(PLAIN[:200], "bifid"), 25,
                                       fs._to_az_table("bifid"), self.model, period=5, dims=2, side=5)
        steps = []

        def stop(step, temp, best, keys):
            steps.append(step)
            raise KeyboardInterrupt
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            score, keys = digraphic.anneal(cipher, [rng.sample(range(25), 25)], 1_000_000, 10.0, seed=3,
                                           chunk=5_000, report=stop)
        self.assertEqual(steps, [5_000])
        self.assertIn("interrupted", printed.getvalue())
        self.assertEqual(sorted(keys[0]), list(range(25)))
        self.assertAlmostEqual(score, digraphic.score(cipher, keys)[0], places=9)

    def test_solvers_return_consistent_results(self):
        import four_square as fq
        import fractionation_solver as fs
        import playfair_anneal as pa
        fit = fitness()
        grid = random.Random(5).sample(range(25), 25)
        cipher = "".join(SQ[x] for x in ref_playfair_encrypt(pa.prepare(PLAIN[:200]), grid))
        score, key, plain = pa.solve(cipher, self.model, 20_000, seed=1)
        self.assertEqual(sorted(key), sorted(SQ))
        self.assertEqual(plain, "".join(SQ[x] for x in pa.Square([SQ.index(c) for c in key]).decrypt(pa.prepare(cipher))))
        self.assertAlmostEqual(score, fit(text_to_codes(plain)), places=9)
        score, tr, bl, plain = fq.solve(cipher, 20_000, seed=1)
        self.assertEqual(plain, fq.decrypt_foursquare(cipher, tr, bl))
        self.assertAlmostEqual(score, fit(text_to_codes(plain)), places=9)
        self.assertEqual(pa.solve(cipher, self.model, 20_000, seed=9), pa.solve(cipher, self.model, 20_000, seed=9))

    def test_bifid_solver_recovers_planted_key(self):
        """Ciphertext-only Bifid, period 7, 300 letters (a measured, seeded run)."""
        import fractionation_solver as fs
        grid = random.Random(13).sample(range(25), 25)
        cell_of = [0] * 25
        for cell, symbol in enumerate(grid):
            cell_of[symbol] = cell
        cipher = fs.encrypt(fs.to_symbols(PLAIN[:300], "bifid"), 7, 2, 5, cell_of, grid)
        score, key, plain = fs.solve("".join(SQ[s] for s in cipher), 7, "bifid", 200_000, seed=1)
        self.assertEqual(plain, PLAIN[:300])
        self.assertAlmostEqual(score, fitness()(text_to_codes(plain)), places=9)


@unittest.skipUnless(NATIVE, "native library not built")
class PlayfairKeywordTests(unittest.TestCase):
    WORDS = ["APPLE", "ZEBRA", "LIGHTHOUSE", "MONASTERY", "KRYPTOS", "LIGHTHOUSES", "QUICK"]

    def test_planted_keyword_ranks_first_and_crib_flags_it(self):
        import playfair
        alphabet = playfair.DEFAULT_ALPHABET
        grid = [alphabet.index(ch) for row in playfair.create_playfair_matrix("LIGHTHOUSE", alphabet) for ch in row]
        plain = PLAIN[:240]
        cipher = "".join(alphabet[x] for x in ref_playfair_encrypt([alphabet.index(ch) for ch in plain], grid))
        best, crib_rows = playfair.keyword_attack(cipher, self.WORDS, alphabet, cribs=["the valley"])
        self.assertIn(best[0]['key'], ("LIGHTHOUSE", "LIGHTHOUSES"))     # same square, same plaintext
        self.assertEqual(best[0]['plaintext'], plain)
        self.assertEqual(len(best), len(self.WORDS) - 1)                  # LIGHTHOUSES deduplicated
        self.assertEqual([r['plaintext'] for r in crib_rows], [plain])
        fit = fitness()
        for row in best:
            self.assertEqual(row['plaintext'], playfair.decrypt_playfair(cipher, row['key'], alphabet))
            self.assertAlmostEqual(row['fitness'], fit(text_to_codes(row['plaintext'])), places=9)
            self.assertAlmostEqual(row['ioc'], ref_ioc(row['plaintext']), places=12)
        self.assertEqual(playfair.keyword_attack(cipher, self.WORDS, alphabet, cribs=["JUNGLE Q"])[1], [])

    def test_six_by_six_alphabet(self):
        import playfair
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        grid = [alphabet.index(ch) for row in playfair.create_playfair_matrix("KRYPTOS", alphabet) for ch in row]
        plain = (codes_to_text(PLAINTEXT[:120]) + "1999" + codes_to_text(PLAINTEXT[120:240]))
        cipher = "".join(alphabet[x] for x in ref_playfair_encrypt([alphabet.index(ch) for ch in plain], grid, 6))
        # (a digit crib would match every word here: letter keywords leave the digits in the same cells)
        best, crib_rows = playfair.keyword_attack(cipher, self.WORDS, alphabet, cribs=["VALLEY", "1999"])
        self.assertEqual((best[0]['key'], best[0]['plaintext']), ("KRYPTOS", plain))
        self.assertEqual([r['key'] for r in crib_rows], ["KRYPTOS"])
        fit = fitness()
        for row in best:
            self.assertAlmostEqual(row['fitness'], fit(text_to_codes(row['plaintext'])), places=9)
            self.assertAlmostEqual(row['ioc'], ref_ioc(row['plaintext']), places=12)

    def test_symbol_encoder(self):
        import playfair
        encode = playfair.symbol_encoder(playfair.DEFAULT_ALPHABET)
        self.assertEqual(encode("Jam, bé\x80!"), bytes([8, 0, 11, 1]))     # J -> I, other symbols dropped


@unittest.skipUnless(NATIVE, "native library not built")
class HillTests(unittest.TestCase):
    def test_row_stage_matches_reference(self):
        import hill
        from native import digraphic
        for size, key in ((2, [[3, 3], [2, 5]]), (3, [[6, 24, 1], [13, 16, 10], [20, 17, 15]])):
            cipher = text_to_codes(hill.encrypt_hill(PLAIN[:120], key))
            scored, rows = digraphic.hill_best_rows(cipher, size, hill.ENGLISH_PERCENT, 40)
            reference = ref_hill_rows(cipher, size, 40)
            self.assertEqual([row for _, row in rows], [row for _, row in reference])
            for (chi, _), (ref_chi, _) in zip(rows, reference):
                self.assertAlmostEqual(chi, ref_chi, places=9)

    def test_row_attack_recovers_keys(self):
        import hill
        for key, length in (([[3, 3], [2, 5]], 120), ([[6, 24, 1], [13, 16, 10], [20, 17, 15]], 150)):
            results = hill.row_attack(hill.encrypt_hill(PLAIN[:length], key), len(key))
            self.assertEqual(results[0]['key_matrix'], key)
            self.assertEqual(results[0]['plaintext'][:length], PLAIN[:length])
            self.assertEqual(results[0]['inverse'], hill.modular_inverse(key, 26))
            fits = [r['fitness'] for r in results]
            self.assertEqual(fits, sorted(fits, reverse=True))
            self.assertAlmostEqual(fits[0], fitness()(text_to_codes(results[0]['plaintext'])), places=9)
            for r in results:
                self.assertTrue(hill.is_valid_key_matrix(r['inverse'], 26))

    def test_row_attack_report_and_odd_length(self):
        import hill
        seen = []
        cipher = hill.encrypt_hill(PLAIN[:121], [[3, 3], [2, 5]])     # padded to 122
        results = hill.row_attack(cipher[:121], 2, report=seen.append)
        valid_rows = sum(1 for a in range(26) for b in range(26) if math.gcd(math.gcd(a, b), 26) == 1)
        self.assertEqual(seen, [valid_rows])
        self.assertEqual(len(results[0]['plaintext']), 122)

    def test_exhaustive_mode_is_gone(self):
        import hill
        self.assertFalse(hasattr(hill, "brute_force_hill_all_keys"))


if __name__ == "__main__":
    unittest.main()
