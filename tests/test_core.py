"""Regression tests for the performance rewrites and bug fixes.

Run from the repository root:  python -m unittest discover -s tests -t .
"""
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import ngram_scoring  # noqa: E402
from attack_support import contains_all_phrases  # noqa: E402
from transposition_core import make_decryptor  # noqa: E402

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def reference_indices(length, width, mode, key):
    """Straightforward index table the fast decryptor must reproduce."""
    height = (length + width - 1) // width
    remainder = length % width or width
    column_length = lambda column: height if column < remainder else height - 1
    if mode.endswith("read_cols"):
        start, column_start = 0, {}
        for column in key:
            column_start[column] = start
            start += column_length(column)
        cells = [(column_start[c] + r, r, c) for c in range(width) for r in range(column_length(c))]
    else:
        position, row_start = 0, {}
        for row in range(height):
            for column in key:
                if row < height - 1 or column < remainder:
                    row_start[(row, column)] = position
                    position += 1
        cells = [(row_start[(r, c)], r, c) for c in range(width) for r in range(column_length(c))]
    order = (lambda cell: (cell[1], cell[2])) if mode.startswith("write_rows") else (lambda cell: (cell[2], cell[1]))
    return [cell[0] for cell in sorted(cells, key=order)]


class ScoringKernelTests(unittest.TestCase):
    def test_rolling_total_matches_naive_sum(self):
        rng = random.Random(1)
        for size in (1, 2, 3, 4):
            scores = bytes(rng.randrange(256) for _ in range(26 ** size))
            for _ in range(200):
                codes = bytes(rng.randrange(26) for _ in range(rng.randrange(0, 40)))
                naive = sum(
                    scores[sum(codes[i + j] * 26 ** (size - 1 - j) for j in range(size))]
                    for i in range(len(codes) - size + 1)
                )
                self.assertEqual(ngram_scoring.ngram_total(codes, scores, size), naive)

    def test_text_to_codes_keeps_only_ascii_letters(self):
        self.assertEqual(ngram_scoring.text_to_codes("Ab z-É!"), bytes([0, 1, 25]))
        self.assertEqual(ngram_scoring.codes_to_text(bytes([0, 1, 25])), "ABZ")


class TranspositionDecryptorTests(unittest.TestCase):
    def test_all_modes_match_reference(self):
        rng = random.Random(2)
        modes = ("write_rows_read_cols", "write_rows_read_rows", "write_cols_read_rows", "write_cols_read_cols")
        for _ in range(1500):
            length, width, mode = rng.randint(1, 80), rng.randint(2, 12), rng.choice(modes)
            key = rng.sample(range(width), width)
            text = "".join(rng.choice(ALPHABET) for _ in range(length))
            expected = "".join(text[i] for i in reference_indices(length, width, mode, key))
            self.assertEqual(make_decryptor(text, width, mode)(key).decode("latin-1"), expected, (length, width, mode, key))


class CipherFixTests(unittest.TestCase):
    def test_hill_exact_inverse_without_numpy(self):
        import hill
        key = hill.key_to_matrix("GYBNQKURP", 3, ALPHABET)
        self.assertEqual(hill.decrypt_hill("POH", key, ALPHABET), "ACT")
        rng = random.Random(3)
        for _ in range(500):
            matrix = [[rng.randrange(26) for _ in range(3)] for _ in range(3)]
            inverse = hill.modular_inverse(matrix, 26)
            self.assertEqual(inverse is not None, hill.is_valid_key_matrix(matrix, 26))
            if inverse:
                self.assertEqual(hill.multiply_mod(matrix, inverse, 26), [[1, 0, 0], [0, 1, 0], [0, 0, 1]])

    def test_gromark_spaces_and_leading_zero_primer(self):
        import Gromark_transposition as gromark
        mixed = gromark.create_keyed_alphabet("ENIGMA", ALPHABET)
        self.assertEqual(mixed, "AJRXEBKSYGFPVIDOUMHQWNCLTZ")
        self.assertEqual(gromark.generate_running_key("23452", 12), "234525797726")
        plain = "THERE ARE UP TO TEN"
        running = gromark.generate_running_key("01234", len(plain))
        cipher, k = [], 0
        for char in plain:
            if char == " ":
                cipher.append(char)
            else:
                cipher.append(mixed[(ALPHABET.index(char) + int(running[k])) % 26])
                k += 1
        self.assertEqual(gromark.decrypt_gromark("".join(cipher), mixed, running, ALPHABET), plain.lower())
        self.assertEqual(sum(len(batch) for batch in gromark.batch_primers()), 100000)

    def test_gronsfeld_ignores_spaces_for_key_position(self):
        import Gronsfeld
        cipher = "".join(
            ALPHABET[(ALPHABET.index(c) + int("31415"[i % 5])) % 26]
            for i, c in enumerate("ATTACKATDAWN")
        )
        spaced = cipher[:6] + " " + cipher[6:8] + " " + cipher[8:]
        self.assertEqual(Gronsfeld.gronsfeld_decrypt(spaced, "31415", ALPHABET), "attack at dawn")

    def test_playfair_merges_j_before_filtering(self):
        import playfair
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        self.assertEqual(playfair.create_playfair_matrix("JAM", alphabet)[0][:3], ["I", "A", "M"])
        self.assertFalse(playfair.contains_all_phrases("anything", []))

    def test_phrase_matching_ignores_spaces_in_phrase(self):
        self.assertTrue(contains_all_phrases("attack at dawn", ["ATTACK AT"]))
        self.assertFalse(contains_all_phrases("attack at dawn", []))

    def test_running_key_too_short_raises(self):
        import running_key
        with self.assertRaises(ValueError):
            running_key.decrypt_running_key("ABCDEF", "XY")


if __name__ == "__main__":
    unittest.main()
