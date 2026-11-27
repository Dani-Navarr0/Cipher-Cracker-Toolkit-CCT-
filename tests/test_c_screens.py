"""C engines of the screens group: transposition families generated and scored
in C (native/screens_transposition.c), the reference statistics of the
Unknown Cipher Analyzer (native/screens_stats.c), the keyed-alphabet shift
choice (native/periodic_keyed.c) and the word-pattern beam search
(native/screens_pattern.c).
Run: python -m unittest tests.test_c_screens"""
import io
import contextlib
import os
import random
import sys
import unittest
import unittest.mock
from itertools import permutations, product

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts"), os.path.join(ROOT, "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

import cipher_profile as cp  # noqa: E402
import rail_fence  # noqa: E402
import transposition_families as tf  # noqa: E402
import transposition_screen as ts  # noqa: E402
from native import screens  # noqa: E402
from ngram_scoring import codes_to_text, text_to_codes  # noqa: E402
from test_cipher_profile import PLAINTEXT  # noqa: E402
from transposition_core import make_permuter  # noqa: E402


def reference_sources(n, items):
    """test-only reference: (info, src) from one-shot reading orders, both directions."""
    for info, order in items:
        for direction, src in tf.both_directions(order).items():
            yield dict(info, direction=direction), src


class FamilyGeneratorTests(unittest.TestCase):
    """Every C generator against the one-shot order functions of transposition_families."""
    LENGTHS = (12, 13, 31, 97)

    def test_routes(self):
        for n in self.LENGTHS:
            widths = range(2, n // 2 + 2)
            expected = reference_sources(n, (({"transposition": "route", "route": name, "width": w}, order)
                                             for w in widths for name, order in tf.route_orders(n, w).items()))
            self.assertEqual(list(tf.route_sources(n, widths)), list(expected), n)

    def test_offset_grids_drop_duplicates_within_a_width(self):
        for n in self.LENGTHS:
            expected = []
            for width in range(2, min(15, n)):
                seen = set()
                for offset in range(1, width):
                    for name, order in tf.route_orders(n, width, offset).items():
                        for direction, src in tf.both_directions(order).items():
                            if tuple(src) not in seen:
                                seen.add(tuple(src))
                                expected.append(({"transposition": "offset_grid", "route": name, "width": width,
                                                  "grid_offset": offset, "direction": direction}, src))
            self.assertEqual(list(tf.offset_grid_sources(n, range(2, min(15, n)))), expected, n)

    def test_rail_fence_and_redefence(self):
        for n in self.LENGTHS:
            rails = range(2, n)
            expected = list(reference_sources(n, (({"transposition": "rail_fence", "rails": r},
                                                   tf.rail_fence_order(n, r)) for r in rails)))
            self.assertEqual(list(tf.rail_fence_sources(n, rails)), expected)
            expected = list(reference_sources(n, (({"transposition": "redefence", "rails": r, "rail_order": list(o)},
                                                   tf.redefence_order(n, o))
                                                  for r in range(3, 7) for o in permutations(range(r))
                                                  if list(o) != sorted(o))))
            self.assertEqual(list(tf.redefence_sources(n, range(3, 7))), expected)

    def test_double_rotation(self):
        for n in self.LENGTHS:
            widths = range(2, min(12, n))
            expected = []
            for w1, w2 in product(widths, repeat=2):
                for cw1, cw2 in product((True, False), repeat=2):
                    one = tf.both_directions(tf.rotation_order(n, w1, cw1))
                    two = tf.both_directions(tf.rotation_order(n, w2, cw2))
                    for direction in ("read", "write"):
                        expected.append(({"transposition": "double_rotation", "widths": [w1, w2],
                                          "clockwise": [cw1, cw2], "direction": direction},
                                         tf.compose(one[direction], two[direction])))
            self.assertEqual(list(tf.double_rotation_sources(n, widths)), expected, n)

    def test_offset_double_rotation(self):
        n, first = 97, 31
        expected = []
        for offset in (27, 3):
            routes = tf.route_orders(n, first, offset)
            for cw1 in (True, False):
                one = tf.both_directions(routes["columns_up"] if cw1 else routes["columns_right_to_left_down"])
                for w2 in range(2, 8):
                    for cw2 in (True, False):
                        two = tf.both_directions(tf.rotation_order(n, w2, cw2))
                        for direction in ("read", "write"):
                            expected.append(({"transposition": "offset_double_rotation", "widths": [first, w2],
                                              "grid_offset": offset, "clockwise": [cw1, cw2], "direction": direction},
                                             tf.compose(one[direction], two[direction])))
        self.assertEqual(list(tf.offset_double_rotation_sources(n, first, [27, 3], range(2, 8))), expected)

    def test_keyword_sources(self):
        words = ["TOMATO", "BANANA", "BALLOON", "KRYPTOS", "AB", "ZZZ", "LIGHTHOUSE", "AARDVARK", "QUEUE",
                 "ÉTÉS", "TOMATO", "OTAMOT"]
        for n in (12, 40, 97):
            expected, seen_m, seen_a = [], set(), set()      # test-only reference of the rules
            for word in words:
                if not 3 <= len(word) < n // 2:
                    continue
                ranks = tuple(ts.keyword_ranks(word))
                if len(set(ranks)) < len(ranks) and ranks not in seen_m:
                    seen_m.add(ranks)
                    for d, src in tf.both_directions(tf.myszkowski_order(n, list(ranks))).items():
                        expected.append(({"transposition": "myszkowski", "keyword": word, "direction": d}, src))
                order = tuple(i for _, i in sorted((ch, i) for i, ch in enumerate(word)))
                if order not in seen_a:
                    seen_a.add(order)
                    for first in (1, 2):
                        for rule in ("continue", "alternate_rows"):
                            for d, src in tf.both_directions(tf.amsco_order(n, list(order), first, rule)).items():
                                expected.append(({"transposition": "amsco", "keyword": word, "first_cell": first,
                                                  "rows": rule, "direction": d}, src))
            self.assertEqual(list(ts.keyword_sources(n, words)), expected, n)

    def test_exhaustive_irregular(self):
        n = 29
        expected = []
        for width in range(2, 6):
            for order in permutations(range(width)):
                for first in (1, 2):
                    for rule in ("continue", "alternate_rows"):
                        for d, src in tf.both_directions(tf.amsco_order(n, list(order), first, rule)).items():
                            expected.append(({"transposition": "amsco", "order": list(order), "first_cell": first,
                                              "rows": rule, "direction": d}, src))
            for ranks in product(range(width), repeat=width):
                used = sorted(set(ranks))
                if used != list(range(len(used))) or len(used) == width:
                    continue
                for d, src in tf.both_directions(tf.myszkowski_order(n, list(ranks))).items():
                    expected.append(({"transposition": "myszkowski", "ranks": list(ranks), "direction": d}, src))
        self.assertEqual(list(ts.exhaustive_irregular_sources(n, 5)), expected)

    def test_columnar_identity_matches_make_permuter(self):
        rng = random.Random(1)
        for n in (20, 37, 97):
            text = bytes(rng.randrange(26) for _ in range(n))
            sources = screens.Sources(n)
            expected = []
            for width in range(2, n):
                for mode, layout in screens.LAYOUTS.items():
                    order = list(range(width)) if width > 9 else rng.sample(range(width), width)
                    sources.add(screens.COLUMNAR, (width, layout), key=order if width <= 9 else (), meta=("x",))
                    expected.append(bytes(make_permuter(n, width, mode)(text, order)))
            ids = [k << screens.ID_SHIFT for k in range(len(expected))]
            self.assertEqual(sources.plain(text, ids), expected, n)


class SourceLimitTests(unittest.TestCase):
    def test_many_offsets_in_one_record(self):
        # 3,001 offsets x 22 sources: more than the old 16-bit sub field held
        text = PLAINTEXT[:60]
        sources = tf.offset_grid_sources(60, [3], offsets=[1] * 3000 + [2])
        self.assertGreater(sources.max_sources(), 65535)
        results, tested = ts.screen(text, sources, top=50, workers=1)
        self.assertEqual(len(results), 50)
        for score, info, plain in results:
            self.assertEqual(info["transposition"], "offset_grid")
            self.assertIn(info["grid_offset"], (1, 2))
            order = tf.route_orders(60, 3, info["grid_offset"])[info["route"]]
            src = tf.both_directions(order)[info["direction"]]
            source = text[::-1] if info["text_reversed"] else text
            self.assertEqual(plain, bytes(source[i] for i in src))
        with self.assertRaises(ValueError):
            tf.offset_grid_sources(60, [3], offsets=[1] * (screens.SUB_LIMIT // screens.ROUTE_SUBS + 1))

    def test_width_zero_is_a_value_error(self):
        for build in (lambda: tf.route_sources(20, [0]), lambda: tf.double_rotation_sources(20, [0, 3]),
                      lambda: tf.offset_grid_sources(20, [0], offsets=[0]),
                      lambda: tf.offset_grid_sources(20, [4], offsets=[-1])):
            with self.assertRaises(ValueError):
                build()

    def test_c_skips_a_bad_record_without_crashing(self):
        fitness = cp.fitness_function()
        sources = screens.Sources(20)
        sources.fields.extend((screens.ROUTE, 0, 0, 0, 0, 0, 0, 1))     # width 0, built past add()
        sources.keys.append(0)
        sources.meta.append(("route", 0, [0]))
        self.assertEqual(sources.score(PLAINTEXT[:20], fitness, top=5)[0], 0)
        sources = screens.Sources(20)
        sources.fields.extend((screens.DOUBLE_ROTATION, 4, 0, 0, 0, 0, 0, 0))
        sources.meta.append(("double_rotation", 4, 0, True, True))
        self.assertEqual(sources.score(PLAINTEXT[:20], fitness, top=5)[0], 0)


class ScoringTests(unittest.TestCase):
    def test_scores_equal_the_fitness_exactly(self):
        fitness = cp.fitness_function()
        rng = random.Random(2)
        for n in (5, 40, 97):
            text = PLAINTEXT[:n] if n > 5 else bytes([1, 2, 3, 4, 5])
            sources = tf.route_sources(n, range(2, n // 2 + 2))
            tested, scored = sources.score(text, fitness, text=screens.BOTH)
            self.assertEqual(len(scored), 2 * tested)
            plains = sources.plain(text, [ident for _, ident in scored])
            for (score, ident), plain in zip(scored, plains):
                self.assertEqual(score, fitness(plain), (n, ident))
            srcs = [rng.sample(range(n), n) for _ in range(30)]
            results, _ = ts.screen(text, [({"k": k}, src) for k, src in enumerate(srcs)], top=60, chunk=7)
            for score, info, plain in results:
                source = text[::-1] if info["text_reversed"] else text
                self.assertEqual(plain, bytes(source[i] for i in srcs[info["k"]]))
                self.assertEqual(score, fitness(plain))

    def test_bad_explicit_source_is_an_error(self):
        with self.assertRaises(ValueError):
            ts.screen(PLAINTEXT[:20], [({}, [0, 1, 25])])

    def test_ties_keep_the_generation_order(self):
        text = bytes([0, 1] * 30)            # many readings give the same text
        results, _ = ts.screen(text, ts.keyless_sources(60), top=10, workers=3)
        everything = []
        for info, src in ts.keyless_sources(60):
            for reverse in (False, True):
                source = text[::-1] if reverse else text
                plain = bytes(source[i] for i in src)
                everything.append((cp.fitness_function()(plain), dict(info, text_reversed=reverse), plain))
        everything.sort(key=lambda entry: -entry[0])     # stable: generation order among ties
        self.assertEqual(results, everything[:10])


class ToolTests(unittest.TestCase):
    def test_screen_finds_planted_transpositions(self):
        plain = PLAINTEXT[:240]
        n = len(plain)
        cases = ((tf.myszkowski_order(n, ts.keyword_ranks("TOMATO")), ts.keyword_sources(n, ["BANANA", "TOMATO"])),
                 (tf.amsco_order(n, [1, 0, 4, 3, 2], 2, "alternate_rows"), ts.exhaustive_irregular_sources(n, 5)),
                 (tf.route_orders(n, 12)["diagonals_snake"], ts.keyless_sources(n, 20)),
                 (tf.redefence_order(n, [2, 0, 3, 1]), ts.keyless_sources(n, 20)))
        for order, sources in cases:
            cipher = bytes(plain[i] for i in order)
            results, tested = ts.screen(cipher, sources, top=3, workers=2)
            self.assertEqual(results[0][2], plain)
            self.assertGreater(tested, 0)

    def test_rank_all_matches_decryption(self):
        fitness = cp.fitness_function()
        text = codes_to_text(PLAINTEXT[:61]) + "*, "
        results = rail_fence.rank_all(text, 9, fitness)
        self.assertEqual(len(results), 2 * sum(2 * (r - 1) for r in range(2, 10)))
        for score, rails, offset, reverse, plain in results:
            source = text[::-1] if reverse else text
            self.assertEqual(plain, rail_fence.decrypt_rail_fence(source, rails, offset))
            self.assertEqual(score, fitness(text_to_codes(plain)))
        cipher = rail_fence.encrypt_rail_fence(codes_to_text(PLAINTEXT[:150]), 6, 4)
        self.assertEqual(rail_fence.rank_all(cipher, 12, fitness)[0][1:4], (6, 4, False))

    def test_lowercase_is_scored_and_kept(self):
        fitness = cp.fitness_function()
        mixed = "WE ARE, discovered! Flee at once 123"
        lower = rail_fence.rank_all(mixed, 6, fitness)
        upper = rail_fence.rank_all(mixed.upper(), 6, fitness)
        self.assertEqual([r[:4] for r in lower], [r[:4] for r in upper])
        for score, rails, offset, reverse, plain in lower:
            source = mixed[::-1] if reverse else mixed
            self.assertEqual(plain, rail_fence.decrypt_rail_fence(source, rails, offset))
            self.assertEqual(score, fitness(text_to_codes(plain)))
        cipher = rail_fence.encrypt_rail_fence("wearediscoveredfleeatonce", 3)
        self.assertEqual(rail_fence.rank_all(cipher, 6, fitness)[0][1:],
                         (3, 0, False, "wearediscoveredfleeatonce"))

    def test_scytale_lowercase(self):
        import Scytale
        text = codes_to_text(PLAINTEXT[:60]).lower()
        cipher = "".join(text[i] for i in tf.route_orders(60, 4)["columns_down"])
        with contextlib.redirect_stdout(io.StringIO()):
            lower = Scytale.brute_force_scytale(cipher)
            upper = Scytale.brute_force_scytale(cipher.upper())
        self.assertEqual((lower[0]['key'], lower[0]['plaintext']), (4, text))
        self.assertEqual([(r['key'], r['bigram_score']) for r in lower],
                         [(r['key'], r['bigram_score']) for r in upper])

    def test_scytale(self):
        import Scytale
        text = codes_to_text(PLAINTEXT[:97])
        for n in (20, 37, 97):
            part = text[:n - 3] + ".1 "
            with contextlib.redirect_stdout(io.StringIO()):
                results = Scytale.brute_force_scytale(part)
            self.assertEqual(sorted(r['key'] for r in results), list(range(2, n)))
            for result in results:
                self.assertEqual(result['plaintext'], Scytale.decrypt_scytale(part, result['key']))
        cipher = "".join(text[i] for i in tf.route_orders(97, 9)["columns_down"])
        with contextlib.redirect_stdout(io.StringIO()):
            best = Scytale.brute_force_scytale(cipher)[0]
        self.assertEqual((best['key'], best['plaintext']), (9, text))

    def test_attack_routes(self):
        fitness = cp.fitness_function()
        plain = PLAINTEXT[:200]
        for cipher, method in ((bytes(plain[i] for i in rail_fence.rail_order(200, 7, 5)), "Rail fence"),
                               (bytes(plain[i] for i in tf.route_orders(200, 8)["columns_down"])[::-1], "Route")):
            best = cp.attack_routes(cipher, fitness)
            self.assertEqual(best[0].plaintext, codes_to_text(plain))
            self.assertTrue(best[0].method.startswith(method), best[0])
            for candidate in best:
                self.assertEqual(candidate.fitness, fitness(text_to_codes(candidate.plaintext)))


class StatisticsTests(unittest.TestCase):
    def test_text_stats_match_the_definitions(self):
        fitness = cp.fitness_function()
        rng = random.Random(3)
        for length in (2, 3, 30, 200):
            texts = [bytes(rng.randrange(26) for _ in range(length)) for _ in range(5)] + [PLAINTEXT[:length]]
            stats = screens.text_stats(texts, length, fitness, cp.ENGLISH_FREQUENCIES)
            for k, text in enumerate(texts):
                self.assertEqual(stats['ioc'][k], cp.ioc(text))
                self.assertEqual(stats['adjacency'][k], cp.adjacency(text))
                self.assertAlmostEqual(stats['chi'][k], cp.chi_squared(text), places=9)
                self.assertAlmostEqual(stats['fitness'][k], fitness(text), places=9)

    def test_reference_samples(self):
        english = cp.english_samples(150, 20, seed=1)
        shuffled, uniform = screens.reference_samples(english, 150, seed=2)
        for a, b in zip(english, shuffled):
            self.assertEqual(sorted(a), sorted(b))
            self.assertNotEqual(a, b)
        letters = b"".join(uniform)
        self.assertTrue(all(c < 26 for c in letters))
        self.assertLess(abs(cp.ioc(letters) - 1 / 26), 0.003)
        self.assertEqual(screens.reference_samples(english, 150, seed=2), (shuffled, uniform))

    def test_periodicity_values(self):
        codes = PLAINTEXT[:300]
        english = cp.english_samples(300, 25, seed=9)
        values, rows = screens.periodicity(codes, 12, english, 7)
        for period in range(1, 13):
            chance, english_values = rows[period - 1]
            self.assertEqual(values[period - 1], cp.column_ioc(codes, period))
            self.assertEqual(english_values, [cp.column_ioc(t, period) for t in english])
            if period == 1:     # a shuffle keeps the letter counts
                self.assertEqual(chance, [cp.ioc(codes)] * 25)
            self.assertEqual(len(set(chance)) > 1, period > 1)

    def test_periodicity_finds_a_planted_period_and_none_in_random_text(self):
        key = text_to_codes("LIGHTHOUSE")
        cipher = bytes((c + key[i % 10]) % 26 for i, c in enumerate(PLAINTEXT))
        self.assertEqual(cp.likely_periods(cp.periodicity(cipher, 30))[0], 10)
        rng = random.Random(4)
        noise = bytes(rng.randrange(26) for _ in range(400))
        self.assertEqual(cp.likely_periods(cp.periodicity(noise, 30)), [])


class KeyedShiftTests(unittest.TestCase):
    @staticmethod
    def reference_solve(codes, period, alphabet, mode, variant):
        """test-only reference: the Python chi-squared choice per column."""
        import keyword_periodic as kp
        pa = alphabet if mode in (1, 3) else kp.ALPHABET
        ca = alphabet if mode in (2, 3) else kp.ALPHABET
        ct_pos = [ca.index(kp.ALPHABET[c]) for c in range(26)]
        pt = [ord(ch) - 65 for ch in pa]
        plain, key = bytearray(len(codes)), []
        for column in range(period):
            letters = codes[column::period]
            best = None
            for k in range(26):
                table = bytes(pt[(ct_pos[c] - k) % 26] if variant == 0 else pt[(k - ct_pos[c]) % 26]
                              for c in range(26)) + bytes(230)
                decrypted = letters.translate(table)
                score = kp.chi([decrypted.count(p) for p in range(26)], len(decrypted))
                if best is None or score < best[0]:
                    best = (score, k, decrypted)
            key.append(ca[best[1]])
            plain[column::period] = best[2]
        return bytes(plain), "".join(key)

    def test_solve_alphabet_matches_reference(self):
        import keyword_periodic as kp
        rng = random.Random(6)
        for word in ("KRYPTOS", "LIGHTHOUSE", "ZEBRAS"):
            alphabet = kp.keyword_alphabet(word)
            for period in (1, 3, 7):
                cipher = bytes((c + rng.randrange(26) * (i % period == 0)) % 26 for i, c in enumerate(PLAINTEXT))
                for mode in (1, 2, 3):
                    for variant in (0, 1):
                        self.assertEqual(kp.solve_alphabet(cipher, period, alphabet, mode, variant),
                                         self.reference_solve(cipher, period, alphabet, mode, variant))

    def test_long_periods_and_bad_arguments(self):
        import keyword_periodic as kp
        from native import fast
        alphabets = kp.distinct_alphabets(kp.STORY_WORDS)
        text = PLAINTEXT * 3
        for period in (129, 300, 1000):          # above the old fixed 128-column stack array
            self.assertTrue(kp.search(text, period, alphabets, keep=5))
        # C total at a long period against the Python chi-squared, column by column
        period, alphabet = 200, kp.keyword_alphabet("KRYPTOS")
        counts = kp.column_counts(text, period)
        packed = alphabet.encode().translate(kp._PACK)
        value = fast.keyed_periodic_chi(counts, period, [packed], 3, 0, kp.EXPECTED)[0]
        plain, _ = kp.solve_alphabet(text, period, alphabet, 3, 0)
        expected = sum(kp.chi([plain[c::period].count(p) for p in range(26)], len(plain[c::period]))
                       for c in range(period))
        self.assertAlmostEqual(value, expected, delta=1e-9 * expected)
        self.assertEqual(kp._best_chi(counts, period, packed, 1, [(3, 0)], 1)[0][0], value)
        with self.assertRaises(ValueError):
            kp.search(PLAINTEXT[:50], 51, alphabets)
        with self.assertRaises(ValueError):
            kp.search(PLAINTEXT[:50], 0, alphabets)
        self.assertEqual(kp.search(PLAINTEXT, 5, alphabets, keep=0), [])
        self.assertEqual(kp._best_chi(kp.column_counts(PLAINTEXT, 5), 5, packed, 1, [(3, 0)], 0), [])

    def test_run_rejects_a_key_length_above_the_text(self):
        import keyword_periodic as kp
        answers = iter([codes_to_text(PLAINTEXT[:100]), "5000", "2"])
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda prompt="": next(answers)), contextlib.redirect_stdout(out):
            kp.run()
        self.assertIn("Key lengths must be 1-100", out.getvalue())

    def test_keyed_periodic_attack(self):
        alphabet, key = cp.KEYED_ALPHABETS["KRYPTOS"], "ABSCISSA"
        cipher = bytes(ord(alphabet[(alphabet.index(chr(65 + p)) + alphabet.index(key[i % 8])) % 26]) - 65
                       for i, p in enumerate(PLAINTEXT))
        best = cp.attack_periodic_keyed(cipher, cp.fitness_function(), [7, 8])[0]
        self.assertEqual((best.method, best.key, best.plaintext),
                         ("Vigenere (KRYPTOS alphabet)", "period 8, key ABSCISSA", codes_to_text(PLAINTEXT)))


class WordPatternTests(unittest.TestCase):
    """native/screens_pattern.c against a test-only reference of the beam search."""

    @classmethod
    def setUpClass(cls):
        import pattern_isomorphism as pi
        cls.pi = pi
        cls.dictionary = pi.load_dictionary()
        cls.scores = list(cls.dictionary.scores)

    def matching(self, word):
        pattern, words = self.pi.get_word_pattern(word), self.dictionary.words
        return [i for i, d in enumerate(words) if len(d) == len(word) and self.pi.get_word_pattern(d) == pattern]

    def reference_solve(self, cipher_words, beam, per_word):
        """test-only reference: pattern_isomorphism.solve as it was in Python, on the
        same word list, candidates in ranked order (ties: dictionary order)."""
        words, scores = self.dictionary.words, self.scores
        distinct = list(dict.fromkeys(w for w in cipher_words if w))
        ranked = {w: sorted(self.matching(w), key=lambda i: -scores[i]) for w in distinct}
        order = sorted((w for w in distinct if ranked[w]), key=lambda w: (min(len(ranked[w]), per_word), -len(w)))
        beams = [(0.0, {}, {})]
        for word in order:
            expanded = []
            for score, forward, backward in beams:
                known = [forward.get(c) for c in word]
                cands = [i for i in ranked[word]
                         if all(k is None or k == words[i][j] for j, k in enumerate(known))][:per_word]
                for i in cands:
                    f, b, ok = dict(forward), dict(backward), True
                    for c, p in zip(word, words[i]):
                        if c in f:
                            ok = f[c] == p
                        elif b.get(p, c) != c:
                            ok = False
                        else:
                            f[c], b[p] = p, c
                        if not ok:
                            break
                    if ok:
                        expanded.append((score + scores[i] * len(word), f, b))
            if expanded:
                expanded.sort(key=lambda entry: -entry[0])
                beams = expanded[:beam]
        return [(score, forward) for score, forward, _ in beams]

    @staticmethod
    def planted(plain):
        sigma = random.Random(len(plain)).sample("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26)
        return "".join(sigma[ord(c) - 65] if c.isalpha() else c for c in plain).split()

    def test_word_scores_match_the_definition(self):
        from ngram_scoring import load_ngram_scores, ngram_total, resolve_ngram_path
        model = load_ngram_scores(resolve_ngram_path(3))
        rng = random.Random(5)
        words = self.dictionary.words
        picks = rng.sample(range(len(words)), 3000) + [i for i, w in enumerate(words) if len(w) <= 2]
        for i in picks:
            word = words[i]
            if len(word) < 3:
                expected = 120.0 if word in self.pi.SHORT_COMMON else 60.0
            else:
                expected = ngram_total(text_to_codes(word), model.scores, 3) / (len(word) - 2)
            self.assertEqual(self.scores[i], expected, word)

    def test_dictionary_holds_only_a_to_z_words_once(self):
        words = self.dictionary.words
        self.assertEqual(len(words), len(set(words)))
        self.assertTrue(all(w.isascii() and w.isalpha() and w.isupper() for w in words))
        self.assertEqual({w for w in words if len(w) == 1}, {"A", "I"})

    def test_matches(self):
        words = self.dictionary.words
        for word in ("ATTACK", "XQZ", "BOOKKEEPER", "A", "QQ"):
            found = self.matching(word)
            ranked = [words[i] for i in sorted(found, key=lambda i: -self.scores[i])]
            self.assertEqual(self.pi.candidates_for(word, 10), (len(found), ranked[:10]), word)

    def test_solve_matches_the_reference(self):
        sentences = ("WE WILL ATTACK THE NORTHERN BRIDGE TOMORROW AT DAWN THE SOLDIERS BELIEVE THE COLONEL HAS A PLAN",
                     "MEET ME AT THE OLD CHURCH AFTER MIDNIGHT BRING THE DOCUMENTS AND COME ALONE",
                     "SHE SELLS SEA SHELLS BY THE SEA SHORE")
        for plain in sentences:
            cipher = self.planted(plain)
            for beam, per_word in ((300, 400), (40, 25)):
                self.assertEqual(self.pi.solve(cipher, beam, per_word), self.reference_solve(cipher, beam, per_word),
                                 (plain, beam))

    def test_joint_solution_and_bad_words(self):
        plain = "WE WILL ATTACK THE NORTHERN BRIDGE TOMORROW AT DAWN THE SOLDIERS BELIEVE THE COLONEL HAS A PLAN"
        share, text, _ = self.pi.best_solutions(self.planted(plain), use_annealing=False)[0]
        self.assertEqual((share, text), (1.0, plain))
        with self.assertRaises(ValueError):
            self.pi.solve(["AB1", "CD"])
        self.assertEqual(self.pi.solve(["QXQXQXQXQXQXQXQXQ", "ZZZZZZZZZZZZZZZZZZZZ"]), [(0.0, {})])


if __name__ == "__main__":
    unittest.main()
