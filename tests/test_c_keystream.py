"""Tests for the keystream C engines: autokey primer search (keystream_autokey.c),
autokey word-list primer search (keystream_dict.c) and the Gromark screen /
alphabet hill-climb (gromark.c), plus the trimmed Gromark_transposition tool
(one-shot decryption only).

Run: python -m unittest tests.test_c_keystream
(set CCT_NATIVE_LIBRARY to test a private build)."""
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
from test_cipher_profile import PLAINTEXT  # noqa: E402

NATIVE = native.available()


# ---- test-only references (the toolkit itself runs only the C engines) ----

REF_ENGLISH = [8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61,
               6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07]


def reference_chi(letters):
    """test-only reference: autoclave's former _chi."""
    total = len(letters) or 1
    return sum((letters.count(c) - REF_ENGLISH[c] * total / 100) ** 2 / (REF_ENGLISH[c] * total / 100)
               for c in range(26))


def reference_solve_primer(cipher, length, kind, variant, fitness, rounds=6):
    """test-only reference: the former Python autoclave.solve_primer."""
    from autoclave import decrypt_codes
    n = len(cipher)
    primer = [0] * length
    for j in range(length):
        best = None
        for s in range(26):
            primer[j] = s
            score = reference_chi(decrypt_codes(cipher, primer, kind, variant)[j::length])
            if best is None or score < best[0]:
                best = (score, s)
        primer[j] = best[1]
    plain = decrypt_codes(cipher, primer, kind, variant)
    score = fitness(plain) if n > 5 else 0.0
    for _ in range(rounds):
        improved = False
        for j in range(length):
            keep = primer[j]
            for s in range(26):
                if s == keep:
                    continue
                primer[j] = s
                trial = decrypt_codes(cipher, primer, kind, variant)
                trial_score = fitness(trial)
                if trial_score > score + 1e-9:
                    score, plain, keep, improved = trial_score, trial, s, True
            primer[j] = keep
        if not improved:
            break
    return score, list(primer), plain


def reference_initial_s(cipher, digits, base, logp, sign=1):
    """test-only reference: the former Python gromark_solver.initial_s."""
    hist = [[0] * base for _ in range(26)]
    for c, d in zip(cipher, digits):
        hist[c][d] += 1
    options = []
    for c in range(26):
        for s in range(26):
            value = sum(h * logp[(s - sign * d) % 26] for d, h in enumerate(hist[c]) if h)
            options.append((value if any(hist[c]) else -1e9, c, s))
    options.sort(reverse=True)
    s_of, used = [None] * 26, set()
    for value, c, s in options:
        if s_of[c] is None and s not in used:
            s_of[c] = s
            used.add(s)
    return s_of


def reference_refine(cipher, digits, s, fitness, sign=1, rounds=30):
    """test-only reference: the former Python gromark_solver.refine."""
    def decrypt(s):
        return bytes((s[c] - sign * d) % 26 for c, d in zip(cipher, digits))
    s = list(s)
    plain = decrypt(s)
    score = fitness(plain)
    for _ in range(rounds):
        improved = False
        for a in sorted(set(cipher)):
            for b in range(26):
                if b == a:
                    continue
                s[a], s[b] = s[b], s[a]
                trial = decrypt(s)
                trial_score = fitness(trial)
                if trial_score > score + 1e-9:
                    score, plain, improved = trial_score, trial, True
                else:
                    s[a], s[b] = s[b], s[a]
        if not improved:
            break
    return score, s, plain


def reference_screen_score(cipher, digits, base, logp, sign=1):
    """test-only reference: the window score of one keystream."""
    hist = [[0] * base for _ in range(26)]
    for c, d in zip(cipher, digits):
        hist[c][d] += 1
    return sum(max(sum(h * logp[(s - sign * d) % 26] for d, h in enumerate(hist[c]) if h) for s in range(26))
               for c in range(26) if any(hist[c]))


def fitness():
    import cipher_profile as cp
    return cp.fitness_function()


# ---- autokey ----

@unittest.skipUnless(NATIVE, "native library not built")
class AutokeyTests(unittest.TestCase):
    PRIMER = [10, 4, 24, 22, 14]      # KEYWO

    def test_plaintext_autokey_recovered_both_tableaux(self):
        import autoclave
        fit = fitness()
        for variant in autoclave.VARIANTS:
            cipher = autoclave.encrypt_codes(PLAINTEXT[:200], self.PRIMER, "plaintext", variant)
            score, kind, found_variant, primer, plain = autoclave.attack(cipher, 8, fit)[0]
            self.assertEqual((kind, found_variant, primer), ("plaintext", variant, self.PRIMER))
            self.assertEqual(bytes(plain), PLAINTEXT[:200])
            self.assertAlmostEqual(score, fit(PLAINTEXT[:200]), places=9)

    def test_ciphertext_autokey_body_recovered(self):
        import autoclave
        fit = fitness()
        for variant in autoclave.VARIANTS:
            cipher = autoclave.encrypt_codes(PLAINTEXT[:200], self.PRIMER, "ciphertext", variant)
            score, kind, found_variant, primer, plain = autoclave.attack(cipher, 8, fit)[0]
            self.assertEqual((kind, found_variant, len(primer)), ("ciphertext", variant, 5))
            # every letter after the primer is fixed by the ciphertext alone
            self.assertEqual(bytes(plain[5:]), PLAINTEXT[5:200])

    def test_matches_reference_exactly(self):
        """Deterministic search: the C engine must take the same path as the
        former Python code (same primer and plaintext, same fitness)."""
        import autoclave
        fit = fitness()
        rng = random.Random(11)
        for trial in range(12):
            kind = autoclave.KINDS[trial % 2]
            variant = autoclave.VARIANTS[(trial // 2) % 2]
            n = rng.choice((40, 90, 150))
            start = rng.randrange(0, len(PLAINTEXT) - n)
            true_primer = [rng.randrange(26) for _ in range(rng.randrange(1, 9))]
            cipher = bytes(autoclave.encrypt_codes(PLAINTEXT[start:start + n], true_primer, kind, variant))
            if trial % 3 == 2:          # also random (non-English) text
                cipher = bytes(rng.randrange(26) for _ in range(n))
            for length in (1, 3, len(true_primer), 9):
                c_score, c_primer, c_plain = autoclave.solve_primer(cipher, length, kind, variant, fit)
                p_score, p_primer, p_plain = reference_solve_primer(cipher, length, kind, variant, fit)
                self.assertEqual(c_primer, p_primer, (trial, length))
                self.assertEqual(bytes(c_plain), bytes(p_plain))
                self.assertAlmostEqual(c_score, p_score, places=9)

    def test_short_and_degenerate_inputs(self):
        import autoclave
        fit = fitness()
        for cipher in (bytes([3, 7]), bytes([1, 2, 3, 4, 5]), bytes(range(26))[:12]):
            for length in (1, 4, 20):    # primer longer than the text included
                for kind in autoclave.KINDS:
                    c = autoclave.solve_primer(cipher, length, kind, "vigenere", fit)
                    p = reference_solve_primer(cipher, length, kind, "vigenere", fit)
                    self.assertEqual((c[1], bytes(c[2])), (p[1], bytes(p[2])))
                    self.assertAlmostEqual(c[0], p[0], places=9)

    def test_rejects_non_fitness_callable(self):
        import autoclave
        with self.assertRaises(TypeError):
            autoclave.solve_primer(bytes(20), 2, "plaintext", "vigenere", lambda codes: 0.0)

    def test_textbook_decrypt(self):
        import autoclave
        self.assertEqual(autoclave.decrypt_autokey("QNXEPVYTWTWP", "QUEENLY"), "ATTACKATDAWN")


def reference_dictionary(cipher, words, fitness, phrases=()):
    """test-only reference: every word as the primer for every kind and
    tableau, ranked (phrase match first, fitness descending, word order, combo order)."""
    from autoclave import KINDS, VARIANTS, decrypt_codes, to_codes, to_text
    rows = []
    for index, word in enumerate(words):
        for combo, (kind, variant) in enumerate((k, v) for k in KINDS for v in VARIANTS):
            plain = decrypt_codes(cipher, to_codes(word), kind, variant)
            match = bool(phrases) and all(p.upper().replace(" ", "") in to_text(plain) for p in phrases)
            rows.append((not match, -fitness(plain), index, combo, kind, variant, bytes(plain)))
    rows.sort(key=lambda row: row[:4])
    return rows


@unittest.skipUnless(NATIVE, "native library not built")
class AutokeyDictionaryTests(unittest.TestCase):
    def test_matches_reference_exactly(self):
        """Same top rows, same order, bit-identical fitness, as the definition."""
        import autoclave
        fit = fitness()
        words, _, _ = autoclave.read_words()
        rng = random.Random(8)
        sample = [words[rng.randrange(len(words))] for _ in range(1500)] + ["KEYWORD", "KEY", "A"]
        for kind, variant, n in (("plaintext", "vigenere", 60), ("ciphertext", "beaufort", 25),
                                 ("plaintext", "beaufort", 4)):
            cipher = autoclave.encrypt_codes(PLAINTEXT[:n], autoclave.to_codes("KEYWORD"), kind, variant)
            expected = reference_dictionary(cipher, sample, fit)[:40]
            got = autoclave.dictionary_attack(cipher, fit, words=sample, keep=40, workers=3)
            self.assertEqual([(-row[1], sample[row[2]], row[4], row[5], row[6]) for row in expected],
                             [(g[0], autoclave.to_text(g[3]), g[1], g[2], bytes(g[4])) for g in got])

    def test_phrase_flag_and_order(self):
        import autoclave
        fit = fitness()
        words = ["ALPHA", "QUEENLY", "ZEBRA", "KNIGHT", "QUEEN"]
        cipher = autoclave.encrypt_codes(autoclave.to_codes("ATTACKATDAWN"), autoclave.to_codes("QUEENLY"))
        got = autoclave.dictionary_attack(cipher, fit, words=words, phrases=["at dawn"], keep=50)
        self.assertEqual(len(got), 20)
        self.assertEqual((autoclave.to_text(got[0][3]), got[0][1], got[0][2], got[0][5]),
                         ("QUEENLY", "plaintext", "vigenere", True))
        self.assertTrue(all(not g[5] for g in got[1:]))
        expected = reference_dictionary(cipher, words, fit, ["at dawn"])
        self.assertEqual([(words[r[2]], r[4], r[5]) for r in expected],
                         [(autoclave.to_text(g[3]), g[1], g[2]) for g in got])
        # a phrase character outside A-Z never matches
        got = autoclave.dictionary_attack(cipher, fit, words=words, phrases=["AT-DAWN"], keep=5)
        self.assertTrue(all(not g[5] for g in got))

    def test_planted_short_texts(self):
        """The full word list on short planted texts (the primer-free search
        alone fails on the 32-letter one)."""
        import autoclave
        fit = fitness()
        for n, primer, kind, variant in ((32, "CAT", "plaintext", "vigenere"),
                                         (40, "MOUNTAIN", "plaintext", "beaufort")):
            cipher = autoclave.encrypt_codes(PLAINTEXT[:n], autoclave.to_codes(primer), kind, variant)
            best = autoclave.dictionary_attack(cipher, fit, keep=5)[0]
            self.assertEqual((autoclave.to_text(best[3]), best[1], best[2]), (primer, kind, variant))
            self.assertEqual(bytes(best[4]), PLAINTEXT[:n])
            self.assertEqual(best[0], fit(best[4]))

    def test_kind_filter_and_bad_input(self):
        import autoclave
        fit = fitness()
        cipher = autoclave.encrypt_codes(PLAINTEXT[:50], autoclave.to_codes("KEY"), "ciphertext", "vigenere")
        got = autoclave.dictionary_attack(cipher, fit, words=["KEY", "DOG"], kinds=("ciphertext",),
                                          variants=("vigenere",), keep=10)
        self.assertEqual([(autoclave.to_text(g[3]), g[1], g[2]) for g in got][0], ("KEY", "ciphertext", "vigenere"))
        self.assertEqual(len(got), 2)
        with self.assertRaises(ValueError):
            autoclave.dictionary_attack(bytes([3, 30]), fit, words=["KEY"])
        with self.assertRaises(ValueError):
            autoclave.dictionary_attack(cipher, fit, words=["K3Y"])
        with self.assertRaises(ValueError):
            autoclave.dictionary_attack(cipher, fit, words=["KEY"], kinds=("running",))
        with self.assertRaises(TypeError):
            autoclave.dictionary_attack(cipher, lambda codes: 0.0, words=["KEY"])


# ---- Gromark ----

@unittest.skipUnless(NATIVE, "native library not built")
class GromarkTests(unittest.TestCase):
    def planted(self, n=250, seed=4, primer=(2, 3, 4, 5, 2), sign=1):
        import gromark_solver as g
        rng = random.Random(seed)
        alphabet = "".join(rng.sample(g.ALPHABET, 26))
        return g.encrypt(PLAINTEXT[:n], list(primer), alphabet, 10, sign), alphabet

    def test_initial_s_matches_reference(self):
        import gromark_solver as g
        rng = random.Random(5)
        cipher, _ = self.planted()
        for _ in range(200):
            base = rng.choice((10, 10, 7, 26))
            sign = rng.choice((1, -1))
            primer = [rng.randrange(base) for _ in range(5)]
            digits = g.keystream(primer, len(cipher), base)
            self.assertEqual(g.initial_s(cipher, digits, base, sign),
                             reference_initial_s(cipher, digits, base, g.LOGP, sign))

    def test_refine_matches_reference(self):
        import gromark_solver as g
        fit = fitness()
        rng = random.Random(6)
        for trial in range(8):
            cipher, _ = self.planted(n=rng.choice((80, 150, 250)), seed=trial)
            sign = rng.choice((1, -1))
            primer = [2, 3, 4, 5, 2] if trial % 2 == 0 else [rng.randrange(10) for _ in range(5)]
            digits = g.keystream(primer, len(cipher))
            start = reference_initial_s(cipher, digits, 10, g.LOGP, sign)
            c_score, c_s, c_plain = g.refine(cipher, digits, start, fit, sign)
            p_score, p_s, p_plain = reference_refine(cipher, digits, start, fit, sign)
            self.assertEqual((c_s, c_plain), (p_s, p_plain), trial)
            self.assertAlmostEqual(c_score, p_score, places=9)
            self.assertAlmostEqual(c_score, fit(c_plain), places=9)

    def test_true_primer_recovers_plaintext(self):
        import gromark_solver as g
        cipher, alphabet = self.planted()
        digits = g.keystream([2, 3, 4, 5, 2], len(cipher))
        score, s, plain = g.refine(cipher, digits, g.initial_s(cipher, digits, 10), fitness())
        self.assertEqual(plain, PLAINTEXT[:250])

    def test_refine_primers_batch_equals_single_calls(self):
        import gromark_solver as g
        fit = fitness()
        cipher, _ = self.planted(n=150)
        numbers = [23452, 0, 99999, 31415, 70093]
        batch = g.refine_primers(cipher, numbers, 10, 5, -1, fit)
        for number, (score, s) in zip(numbers, batch):
            digits = g.keystream(g.primer_digits(number, 5, 10), len(cipher))
            single = g.refine(cipher, digits, g.initial_s(cipher, digits, 10, -1), fit, -1)
            self.assertEqual(s, single[1])
            self.assertEqual(score, single[0])

    def test_screen_top_equals_nlargest(self):
        import heapq
        import gromark_solver as g
        from native import fast
        cipher, _ = self.planted(n=120)
        for base, plen, sign, keep in ((10, 4, 1, 50), (7, 5, -1, 300), (10, 3, 1, 5000)):
            scores = fast.gromark_scores(cipher, base, plen, sign, g.LOGP, 0, base ** plen)
            expected = heapq.nlargest(keep, [(score, q) for q, score in enumerate(scores)])
            self.assertEqual(g.screen_primers(cipher, base, plen, sign, keep), expected)
        digits = g.keystream([3, 1, 4, 1, 5], len(cipher))
        self.assertAlmostEqual(fast.gromark_scores(cipher, 10, 5, 1, g.LOGP, 31415, 1)[0],
                               reference_screen_score(cipher, digits, 10, g.LOGP), places=6)

    def test_rejects_bad_input(self):
        """Codes above 25, digits outside the base and primers under 2 digits
        raise ValueError instead of reaching the C histograms."""
        import gromark_solver as g
        fit = fitness()
        cipher, _ = self.planted(n=120)
        bad = bytes(cipher[:-1]) + bytes([26])
        digits = g.keystream([2, 3, 4, 5, 2], len(cipher))
        for call in (lambda: g.initial_s(bad, digits, 10),
                     lambda: g.initial_s(cipher, [40] * len(cipher), 10),
                     lambda: g.initial_s(cipher, digits[:10], 10),
                     lambda: g.refine(bad, digits, list(range(26)), fit),
                     lambda: g.refine(cipher, digits, [30] * 26, fit),
                     lambda: g.screen_primers(bad, 10, 3, 1, 3),
                     lambda: g.screen_primers(cipher, 10, 1, 1, 3),
                     lambda: g.screen_primers(cipher, 10, 0, 1, 2),
                     lambda: g.screen_primers(cipher, 40, 3, 1, 2),
                     lambda: g.refine_primers(cipher, [1, 2], 10, 1, 1, fit),
                     lambda: g.refine_primers(bad, [1, 2], 10, 5, 1, fit),
                     lambda: g.solve(cipher, plen=1, workers=1)):
            with self.assertRaises(ValueError):
                call()

    def test_c_guards(self):
        """The C entry points themselves refuse bad input (no out-of-bounds writes)."""
        import ctypes
        import gromark_solver as g
        from native import fast
        cipher, _ = self.planted(n=60)
        bad = bytes(cipher[:-1]) + bytes([200])
        self.assertTrue(all(math.isinf(x) and x < 0 for x in fast.gromark_scores(bad, 10, 5, 1, g.LOGP, 0, 4)))
        self.assertTrue(all(math.isinf(x) and x < 0 for x in fast.gromark_scores(cipher, 10, 1, 1, g.LOGP, 0, 4)))
        initial = native.function("cct_gromark_initial_s", ctypes.c_int32,
                                  [ctypes.POINTER(ctypes.c_uint8), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.c_int32,
                                   ctypes.c_int32, ctypes.POINTER(ctypes.c_double), ctypes.POINTER(ctypes.c_uint8)])
        out = (ctypes.c_uint8 * 26)(*range(26))
        logp = (ctypes.c_double * 26)(*g.LOGP)
        digits = (ctypes.c_int32 * len(cipher))(*([40] * len(cipher)))
        self.assertEqual(initial(g._u8(cipher), len(cipher), digits, 10, 1, logp, out), -1)
        self.assertEqual(initial(g._u8(bad), len(bad), (ctypes.c_int32 * len(bad))(), 10, 1, logp, out), -1)
        self.assertEqual(list(out), list(range(26)))

    def test_solve_planted_both_directions(self):
        """Full ciphertext-only run (screen + refine in C, two worker processes)."""
        import gromark_solver as g
        for sign, primer in ((1, (2, 3, 4, 5, 2)), (-1, (8, 0, 6, 1, 7))):
            cipher, alphabet = self.planted(n=250, seed=9, primer=primer, sign=sign)
            best = g.solve(cipher, workers=2)[0]
            self.assertEqual(best[4], PLAINTEXT[:250])
            self.assertEqual((best[1], best[2]), ("".join(map(str, primer)), sign))
            self.assertEqual(best[3], alphabet)


class GromarkTranspositionTests(unittest.TestCase):
    """Tool 71 keeps only one-shot decryption (its search modes were removed in
    favour of tool 34, gromark_solver)."""

    def test_one_shot_helpers(self):
        import Gromark_transposition as gt
        mixed = gt.create_keyed_alphabet("ENIGMA")
        self.assertEqual(mixed, "AJRXEBKSYGFPVIDOUMHQWNCLTZ")
        self.assertEqual(gt.generate_running_key("23452", 12), "234525797726")
        plain = "THERE ARE UP TO TEN"
        running = gt.generate_running_key("01234", len(plain))
        cipher, k = [], 0
        for char in plain:
            if char == " ":
                cipher.append(char)
            else:
                cipher.append(mixed[(ord(char) - 65 + int(running[k])) % 26])
                k += 1
        self.assertEqual(gt.decrypt_gromark("".join(cipher), mixed, running), plain.lower())

    def test_search_modes_removed(self):
        import Gromark_transposition as gt
        for name in ("run_hill_climbing_attack", "run_simulated_annealing_attack", "run_genetic_algorithm_attack",
                     "run_dictionary_attack_wrapper", "run_key_length_bruteforce_wrapper", "try_decrypt_batch",
                     "can_form_word", "parallel_process_keywords"):
            self.assertFalse(hasattr(gt, name), name)

    @unittest.skipUnless(NATIVE, "native library not built")
    def test_tool19_solves_tool2_model(self):
        """Tool 71's cipher (keyword-columnar alphabet GRONSFELD, primer 32941,
        p = CA.index(c) - d) at 250 letters is solved ciphertext-only by tool 34.
        (Measured: tool 34 does NOT solve tool 71's 78-letter known-answer text;
        the true primer ranks 729th in the screen but the alphabet climb stalls.)"""
        import Gromark_transposition as gt
        import gromark_solver as g
        from ngram_scoring import codes_to_text
        mixed = gt.create_keyed_alphabet(gt.TEST_KEYWORD)
        plain = PLAINTEXT[:250]
        cipher = g.encrypt(plain, [int(d) for d in gt.TEST_PRIMER], mixed, 10, 1)
        running = gt.generate_running_key(gt.TEST_PRIMER, len(cipher))
        self.assertEqual(gt.decrypt_gromark(codes_to_text(cipher), mixed, running), codes_to_text(plain).lower())
        best = g.solve(cipher, workers=2)[0]
        self.assertEqual((best[1], best[2], best[3]), (gt.TEST_PRIMER, 1, mixed))
        self.assertEqual(best[4], plain)


if __name__ == "__main__":
    unittest.main()
