"""Tests for the Unknown Cipher Analyzer's statistics and pathway rules.
Run: python -m unittest discover -s tests -t ."""
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import cipher_profile as cp  # noqa: E402
from layered import TranspositionLayer  # noqa: E402
from ngram_scoring import codes_to_text, text_to_codes  # noqa: E402
from rail_fence import decrypt_rail_fence  # noqa: E402

# Plain English that is not taken from the analyzer's reference corpus.
PLAINTEXT = text_to_codes(
    "When the expedition reached the northern edge of the valley the weather turned and the guides "
    "refused to go any further until the storm had passed. We set up camp beside a frozen stream and "
    "waited for three long days, counting the remaining food and listening to the wind tearing at the "
    "canvas. On the fourth morning the sky was clear and blue, and from the ridge we could see the old "
    "monastery that had been our goal since the beginning of the journey. Nobody spoke as we climbed the "
    "last slope, because every one of us knew that the hardest part of the work was only about to begin."
)


def columnar_encrypt(codes, width, order):
    layer = TranspositionLayer(len(codes), width, "write_rows_read_cols")
    layer.key[:] = order
    low = layer.decrypt(bytes(i % 256 for i in range(len(codes))))
    high = layer.decrypt(bytes(i // 256 for i in range(len(codes))))
    out = bytearray(len(codes))
    for target, (h, l) in enumerate(zip(high, low)):
        out[h * 256 + l] = codes[target]
    return bytes(out)


def substitute(codes, seed):
    table = random.Random(seed).sample(range(26), 26)
    return codes.translate(bytes(table) + bytes(230))


class StatisticTests(unittest.TestCase):
    def test_ioc_and_column_ioc(self):
        codes = text_to_codes("AABBC")
        self.assertAlmostEqual(cp.ioc(codes), (2 + 2) / 20)
        self.assertAlmostEqual(cp.column_ioc(PLAINTEXT, 1), cp.ioc(PLAINTEXT))

    def test_adjacency_is_unchanged_by_substitution(self):
        self.assertAlmostEqual(cp.adjacency(PLAINTEXT), cp.adjacency(substitute(PLAINTEXT, 3)))

    def test_rail_fence_order_inverts_the_toolkit_decryptor(self):
        text = codes_to_text(PLAINTEXT[:61])
        for rails in range(2, 9):
            order = cp.rail_fence_order(len(text), rails)
            cipher = "".join(text[p] for p in order)
            self.assertEqual(decrypt_rail_fence(cipher, rails), text, rails)

    def test_regroup_polybius_digits(self):
        square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        plain = codes_to_text(PLAINTEXT[:80]).replace("J", "I")
        digits = "".join(f"{square.index(ch) // 5 + 1}{square.index(ch) % 5 + 1}" for ch in plain)
        prepared = cp.prepare(digits)
        self.assertTrue(prepared.regrouped)
        self.assertEqual(len(prepared.codes), len(plain))
        # The regrouped text is a simple substitution of the plaintext: same IoC.
        self.assertAlmostEqual(cp.ioc(prepared.codes), cp.ioc(text_to_codes(plain)))

    def test_attack_plan_combinations(self):
        plan = cp.AttackPlan("x", ("sub", "trans"), 1000, 1, widths=[5, 6], modes=["write_rows_read_cols"])
        self.assertEqual(plan.combos(), [[("sub", None), ("trans", (5, "write_rows_read_cols"))],
                                         [("sub", None), ("trans", (6, "write_rows_read_cols"))]])


class PathwayTests(unittest.TestCase):
    def top(self, codes):
        result = cp.profile(codes_to_text(codes))
        return result, result.pathways[0]

    def test_plaintext_is_recognised(self):
        _, top = self.top(PLAINTEXT)
        self.assertEqual(top.strength, "solved")

    def test_simple_substitution(self):
        _, top = self.top(substitute(PLAINTEXT, 11))
        self.assertTrue(top.title.startswith("Simple substitution"), top.title)

    def test_transposition_only(self):
        _, top = self.top(columnar_encrypt(PLAINTEXT, 9, [4, 0, 7, 2, 8, 1, 5, 3, 6]))
        self.assertTrue(top.title.startswith("Transposition only"), top.title)

    def test_substitution_and_transposition(self):
        _, top = self.top(columnar_encrypt(substitute(PLAINTEXT, 5), 8, [3, 7, 0, 5, 1, 6, 2, 4]))
        self.assertTrue(top.title.startswith("Substitution + transposition"), top.title)

    def test_vigenere_period_and_instant_solve(self):
        key = [10, 17, 24, 15, 19, 14, 18]
        cipher = bytes((c + key[i % 7]) % 26 for i, c in enumerate(PLAINTEXT))
        result, top = self.top(cipher)
        self.assertEqual(result.period_candidates[0], 7)
        self.assertTrue(top.title.startswith("Periodic polyalphabetic, key length 7"), top.title)
        best = cp.run_instant_attacks(result)[0]
        self.assertEqual(best.plaintext, codes_to_text(PLAINTEXT))
        self.assertEqual(cp.judge(best.fitness, result.refs), "reads as English")

    def test_rail_fence_instant_solve(self):
        order = cp.rail_fence_order(len(PLAINTEXT), 5)
        result = cp.profile(codes_to_text(bytes(PLAINTEXT[p] for p in order)))
        best = cp.run_instant_attacks(result)[0]
        self.assertEqual(best.plaintext, codes_to_text(PLAINTEXT))

    def test_too_short(self):
        self.assertIsNone(cp.profile("ABCDEFG"))


if __name__ == "__main__":
    unittest.main()
