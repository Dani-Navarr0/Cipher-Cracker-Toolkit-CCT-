"""Tests for the version-3 native kernels and the new solvers (Quagmire,
transposition families, Gromark, Bifid/Trifid, Four-square).
Run: python -m unittest discover -s tests -t ."""
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts"), os.path.join(ROOT, "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

import native  # noqa: E402
import ngram_scoring as ns  # noqa: E402
from ngram_scoring import codes_to_text  # noqa: E402
from test_cipher_profile import PLAINTEXT  # noqa: E402

NATIVE = native.available()


# ---- test-only references (the toolkit itself runs only the C engines)

def reference_ngram_total(codes, scores, size):
    """Plain loop over every n-gram: what cct_ngram_total must return."""
    total = 0
    for i in range(len(codes) - size + 1):
        index = 0
        for code in codes[i:i + size]:
            index = index * 26 + code
        total += scores[index]
    return total


def reference_gromark_score(cipher, digits, base, logp, sign=1):
    """What cct_gromark_scores must return for one primer's keystream."""
    hist = [[0] * base for _ in range(26)]
    for c, d in zip(cipher, digits):
        hist[c][d] += 1
    score = 0.0
    for c in range(26):
        if any(hist[c]):
            score += max(sum(h * logp[(s - sign * d) % 26] for d, h in enumerate(hist[c]) if h) for s in range(26))
    return score


@unittest.skipUnless(NATIVE, "native library not built")
class NativeKernelTests(unittest.TestCase):
    def test_ngram_total_matches_python(self):
        from native import fast
        rng = random.Random(1)
        for size in (3, 4, 5):
            scores = ns.load_ngram_scores(ns.resolve_ngram_path(size)).scores
            for _ in range(100):
                codes = bytes(rng.randrange(26) for _ in range(rng.randrange(0, 400)))
                self.assertEqual(fast.ngram_total(codes, scores, size), reference_ngram_total(codes, scores, size))

    def test_keyed_chi_matches_python(self):
        import keyword_periodic as kp
        from native import fast
        alphabets = [kp.keyword_alphabet(w) for w in ("KRYPTOS", "LIGHTHOUSE", "PALIMPSEST", "ZEBRAS")]
        packed = [bytes(ord(ch) - 65 for ch in a) for a in alphabets]
        for period in (1, 5):
            counts = [[PLAINTEXT[c::period].count(x) for x in range(26)] for c in range(period)]
            for mode in (1, 2, 3):
                for variant in (0, 1):
                    native_chi = fast.keyed_periodic_chi(counts, period, packed, mode, variant, kp.EXPECTED)
                    python_chi = []
                    for alphabet in alphabets:
                        plain, _ = kp.solve_alphabet(PLAINTEXT, period, alphabet, mode, variant)
                        python_chi.append(sum(kp.chi([plain[c::period].count(x) for x in range(26)],
                                                     len(plain[c::period])) for c in range(period)))
                    for a, b in zip(native_chi, python_chi):
                        self.assertAlmostEqual(a, b, places=6)

    def test_gromark_scores_match_python(self):
        import gromark_solver as g
        from native import fast
        cipher = PLAINTEXT[:200]
        native_scores = fast.gromark_scores(cipher, 10, 5, 1, g.LOGP, 31000, 30)
        for q, value in enumerate(native_scores):
            digits = g.keystream(g.primer_digits(31000 + q, 5, 10), len(cipher))
            self.assertAlmostEqual(value, reference_gromark_score(cipher, digits, 10, g.LOGP), places=6)

    def test_fraction_and_foursquare_decrypt_match_python(self):
        import fractionation_solver as fs
        import four_square as fq
        rng = random.Random(2)
        for kind in ("bifid", "trifid"):
            spec = fs.KINDS[kind]
            count = len(spec["symbols"])
            grid = rng.sample(range(count), count)
            cell_of = [0] * count
            for cell, symbol in enumerate(grid):
                cell_of[symbol] = cell
            plain = fs.to_symbols(codes_to_text(PLAINTEXT), kind)
            for period in (0, 5, 7):
                cipher = fs.encrypt(plain, period, spec["dims"], spec["side"], cell_of, grid)
                self.assertEqual(fs.make_decryptor(cipher, period, kind)(cell_of, grid), plain)
        tr, bl = rng.sample(range(25), 25), rng.sample(range(25), 25)
        text = codes_to_text(PLAINTEXT).replace("J", "I")
        decrypt = fq.make_decryptor(text)
        expected = fq.decrypt_foursquare(text, "".join(fq.ALPHABET[x] for x in tr), "".join(fq.ALPHABET[x] for x in bl))
        tr_pos, bl_pos = [0] * 25, [0] * 25
        for cell in range(25):
            tr_pos[tr[cell]], bl_pos[bl[cell]] = cell, cell
        self.assertEqual("".join(fq.ALPHABET[x] for x in decrypt(tr_pos, bl_pos)), expected[:len(expected) // 2 * 2])


class SolverTests(unittest.TestCase):
    def test_bifid_textbook(self):
        import fractionation_solver as fs
        symbols = fs.KINDS["bifid"]["symbols"]
        grid = [symbols.index(ch) for ch in "BGWKZQPNDSIOAXEFCLUMTHYVR"]
        cell_of = [0] * 25
        for cell, symbol in enumerate(grid):
            cell_of[symbol] = cell
        cipher = fs.encrypt(fs.to_symbols("FLEEATONCE", "bifid"), 0, 2, 5, cell_of, grid)
        self.assertEqual("".join(symbols[s] for s in cipher), "UAEOLWRINS")

    def test_quagmire_finds_keyword_alphabet(self):
        import keyword_periodic as kp
        alphabet, key = kp.keyword_alphabet("LIGHTHOUSE"), "SECRET"
        cipher = bytes(ord(alphabet[(alphabet.index(chr(65 + p)) + alphabet.index(key[i % 6])) % 26]) - 65
                       for i, p in enumerate(PLAINTEXT))
        best = kp.search(cipher, 6, kp.distinct_alphabets(kp.STORY_WORDS + ["LIGHTHOUSE"]))[0]
        self.assertEqual((best[1], best[2], best[4], best[5]), ("LIGHTHOUSE", 3, "SECRET", codes_to_text(PLAINTEXT)))

    def test_transposition_families(self):
        import transposition_families as tf
        import transposition_screen as ts
        plain = PLAINTEXT[:240]
        n = len(plain)
        for order, words in ((tf.myszkowski_order(n, ts.keyword_ranks("TOMATO")), ["TOMATO", "BANANA"]),
                             (tf.amsco_order(n, [i for _, i in sorted((c, i) for i, c in enumerate("BALLOON"))]),
                              ["BALLOON", "KRYPTOS"]),
                             (tf.route_orders(n, 12)["spiral_clockwise"], None)):
            cipher = bytes(plain[i] for i in order)
            sources = ts.keyword_sources(n, words) if words else ts.keyless_sources(n, 14)
            results, _ = ts.screen(cipher, sources, top=1, workers=2)
            self.assertEqual(results[0][2], plain)

    def test_gromark_with_true_primer(self):
        import gromark_solver as g
        import cipher_profile as cp
        rng = random.Random(4)
        alphabet = "".join(rng.sample(g.ALPHABET, 26))
        primer = [2, 3, 4, 5, 2]
        cipher = g.encrypt(PLAINTEXT[:250], primer, alphabet)
        digits = g.keystream(primer, len(cipher))
        _, s, plain = g.refine(cipher, digits, g.initial_s(cipher, digits, 10), cp.fitness_function())
        self.assertEqual(plain, PLAINTEXT[:250])


if __name__ == "__main__":
    unittest.main()
