"""Regression tests for the 2026-11-27 audit fixes and the new attacks.
Run: python -m unittest discover -s tests -t ."""
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts"), os.path.join(ROOT, "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

from ngram_scoring import codes_to_text, text_to_codes  # noqa: E402
from test_cipher_profile import PLAINTEXT, columnar_encrypt  # noqa: E402

PLAIN = codes_to_text(PLAINTEXT)


class SessionTests(unittest.TestCase):
    def test_ciphertext_prompts_are_recognised(self):
        import session
        for prompt in ("Enter ciphertext: ", "\033[38;5;245mEnter text: \033[0m", "Ciphertext: ",
                       "Enter the ciphertext to crack: ", "Enter Vigenère ciphertext: "):
            self.assertTrue(session.asks_for_ciphertext(prompt), prompt)
        for prompt in ("Solve this test ciphertext now? ([Y]/n): ", "Enter the key: ",
                       "Enter the corresponding 9 characters of ciphertext: ",
                       "Enter required plaintext words/phrases: ", "Enter file path: "):
            self.assertFalse(session.asks_for_ciphertext(prompt), prompt)


class TranspositionKeyTests(unittest.TestCase):
    def test_every_key_form_gives_the_same_order(self):
        from transposition_core import order_to_keyword, parse_column_key
        import columnar_transposition as tool20
        for text in ("[4, 2, 1, 3, 5, 0]", "4 2 1 3 5 0", "5 3 2 4 6 1", "ZEBRAS", "521304"):
            self.assertEqual(parse_column_key(text), [4, 2, 1, 3, 5, 0], text)
        for order in ([4, 2, 1, 3, 5, 0], list(range(12))[::-1]):
            self.assertEqual(tool20.key_order(order_to_keyword(order)), tuple(order))

    def test_tool20_exhaustive_finds_the_order(self):
        import columnar_transposition as tool20
        order = [3, 0, 5, 1, 4, 2]
        cipher = codes_to_text(columnar_encrypt(PLAINTEXT[:240], 6, order))
        best = min(tool20.exhaustive_results(cipher, 6, []), key=lambda r: r['bigram_score'])
        self.assertEqual(best['plaintext'], PLAIN[:240])
        self.assertEqual(best['key'], tool20.order_to_key(order))


class RailFenceTests(unittest.TestCase):
    def test_round_trips_with_offsets_and_any_symbol(self):
        from rail_fence import decrypt_rail_fence, encrypt_rail_fence
        text = "A*B*C*D*EF\nXY" * 3
        for rails in range(2, 9):
            for offset in range(2 * (rails - 1)):
                self.assertEqual(decrypt_rail_fence(encrypt_rail_fence(text, rails, offset), rails, offset), text)

    def test_ranking_finds_offset_key(self):
        import cipher_profile as cp
        from rail_fence import encrypt_rail_fence, rank_all
        cipher = encrypt_rail_fence(PLAIN[:200], 7, 3)
        best = rank_all(cipher, 10, cp.fitness_function())[0]
        self.assertEqual(best[4], PLAIN[:200])
        self.assertEqual((best[1], best[2], best[3]), (7, 3, False))


class AutokeyTests(unittest.TestCase):
    def test_textbook_example(self):
        import autoclave
        self.assertEqual(autoclave.decrypt_autokey("QNXEPVYTWTWP", "QUEENLY"), "ATTACKATDAWN")

    def test_primer_free_attack(self):
        import autoclave
        import cipher_profile as cp
        for kind, variant in (("plaintext", "vigenere"), ("plaintext", "beaufort")):
            cipher = autoclave.encrypt_codes(PLAINTEXT[:200], [10, 4, 24, 22, 14], kind, variant)
            score, found_kind, found_variant, primer, plain = autoclave.attack(cipher, 8, cp.fitness_function())[0]
            self.assertEqual((found_kind, found_variant, primer), (kind, variant, [10, 4, 24, 22, 14]))
            self.assertEqual(bytes(plain), PLAINTEXT[:200])


class HillTests(unittest.TestCase):
    KEY = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]

    def test_row_attack_3x3_ciphertext_only(self):
        import hill
        cipher = hill.encrypt_hill(PLAIN[:150], self.KEY)
        best = hill.row_attack(cipher, 3)[0]
        self.assertEqual(best['key_matrix'], self.KEY)
        self.assertEqual(best['plaintext'][:150], PLAIN[:150])

    def test_known_plaintext_unknown_position(self):
        import hill
        cipher = hill.encrypt_hill(PLAIN[:240], self.KEY)
        best = hill.known_plaintext_candidates(cipher, PLAIN[50:74], 3)[0]
        self.assertEqual((best['key_matrix'], best['position']), (self.KEY, 50))

    def test_unusable_crib_is_reported(self):
        import hill
        self.assertFalse(hill.crib_is_usable(PLAIN[50:62], 3))   # its 3x3 block matrices are all singular mod 26


class SubstitutionFixTests(unittest.TestCase):
    def test_modular_key_skips_spaces(self):
        import modular_add_sub as m
        result = m.map_to_alphabet(m.modular_operation(m.parse_input("HELLO WORLD"), "AB", "add"))
        self.assertEqual(result, "HFLMO XOSLE")

    def test_four_square_keeps_j(self):
        from four_square import decrypt_foursquare, generate_square
        tr, bl = generate_square("EXAMPLE"), generate_square("KEYWORD")
        self.assertEqual(decrypt_foursquare("ABJD", tr, bl), decrypt_foursquare("ABID", tr, bl))

    def test_gronsfeld_batch_keeps_few_and_ranks_the_key_first(self):
        import Gronsfeld as g
        from ngram_scoring import DEFAULT_NGRAM_PATH
        key = "314"
        cipher = "".join(chr((ord(c) - 65 + int(key[i % 3])) % 26 + 65) for i, c in enumerate(PLAIN[:150]))
        rows = g.process_exhaustive_batch((cipher, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 0, 1000, 3,
                                           g.load_ngram_frequencies(DEFAULT_NGRAM_PATH), []))
        self.assertLessEqual(len(rows), g.KEEP_PER_BATCH)
        self.assertEqual(min(rows, key=lambda r: r['score'])['key'], key)


class PlayfairSquareTests(unittest.TestCase):
    def test_square_round_trip(self):
        import playfair_anneal as pa
        square = pa.Square(random.Random(3).sample(range(25), 25))
        plain = bytes(pa.SQUARE_ALPHABET.index(ch) for ch in "HIDETHEGOLDINTHETREXESTUMP")
        self.assertEqual(square.decrypt(square.encrypt(plain)), plain)


class CribDragTests(unittest.TestCase):
    def test_key_fragment_variants_and_period(self):
        import crib_drag as cd
        key = "KRYPTOS"
        vig = "".join(chr((ord(c) - 65 + ord(key[i % 7]) - 65) % 26 + 65) for i, c in enumerate(PLAIN))
        position = PLAIN.index("MONASTERY")
        fragment = cd.key_fragment(vig[position:position + 9], "MONASTERY", "vigenere")
        self.assertEqual(fragment, (key * 3)[position % 7:position % 7 + 9])
        self.assertEqual(cd.self_period(fragment), 7)
        beau = "".join(chr((ord(key[i % 7]) - ord(c)) % 26 + 65) for i, c in enumerate(PLAIN))
        self.assertEqual(cd.key_fragment(beau[position:position + 9], "MONASTERY", "beaufort"), fragment)


class WordPatternTests(unittest.TestCase):
    def test_joint_solution(self):
        import pattern_isomorphism as p
        plain = "WE WILL ATTACK THE NORTHERN BRIDGE TOMORROW AT DAWN THE SOLDIERS BELIEVE THE COLONEL HAS A PLAN"
        sigma = random.Random(len(plain)).sample("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26)
        cipher = "".join(sigma[ord(c) - 65] if c.isalpha() else c for c in plain)
        share, text, _ = p.best_solutions(cipher.split(), use_annealing=False)[0]
        self.assertEqual(text, plain)
        self.assertEqual(share, 1.0)


if __name__ == "__main__":
    unittest.main()
