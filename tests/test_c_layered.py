"""Tests for the layered group's C engines: native/layered_engine.c (the
multi-layer annealer behind layered.LayeredSolver, two_layer.solve_job, tool 13
and tool 45's annealing) and native/layered_columnar.c (tool 45's exhaustive,
dictionary and double-exhaustive searches), plus tool 44 (both move sets) end to end.
Run: python -m unittest tests.test_c_layered"""
import itertools
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import native  # noqa: E402
import ngram_scoring as ns  # noqa: E402
from annealing import Fitness, Schedule  # noqa: E402
from layered import (LayeredSolver, PeriodicLayer, SubstitutionLayer, TRANSPOSITION_MODES,  # noqa: E402
                     TranspositionLayer)

MODES = list(TRANSPOSITION_MODES)
PLAINTEXT = (
    "THEREWEREMANYTHINGSTHATCOULDHAVEGONEWRONGWITHTHEPLANBUTTHEMOSTIMPORTANT"
    "THINGWASTHATNOBODYKNEWWHEREWEHADHIDDENTHEGOLDANDSOWEWAITEDFORTHENIGHT"
    "TOCOMEANDTHENWEWALKEDSLOWLYDOWNTOTHERIVERWHERETHEBOATWASWAITINGFORUS"
    "ANDWHENWEREACHEDTHEOTHERSIDEWEFOUNDTHATTHEMENWHOHADPROMISEDTOHELPUS"
    "WERENOWHERETOBESEENSOWESATDOWNONTHEBANKANDWAITEDUNTILTHESUNCAMEUP"
)


def codes(text):
    return ns.text_to_codes(text)


def model(size=4):
    return ns.load_ngram_scores(ns.resolve_ngram_path(size))


def encrypt_transposition(plain, width, order, mode="write_rows_read_cols"):
    """Inverse of the layer's decryption (test-only reference)."""
    layer = TranspositionLayer(len(plain), width, mode)
    layer.key[:] = order
    low = layer.decrypt(bytes(i % 256 for i in range(len(plain))))
    high = layer.decrypt(bytes(i // 256 for i in range(len(plain))))
    out = bytearray(len(plain))
    for target, (h, l) in enumerate(zip(high, low)):
        out[h * 256 + l] = plain[target]
    return bytes(out)


def python_stack_decrypt(cipher, layers):
    """Test-only reference: the stack decrypted with the Python layer classes."""
    text = bytes(cipher)
    for layer in layers:
        text = bytes(layer.decrypt(text))
    return text


def random_layers(rng, length, kinds):
    layers = []
    for kind in kinds:
        if kind == "sub":
            layer = SubstitutionLayer()
        elif kind == "trans":
            layer = TranspositionLayer(length, rng.randint(2, 12), rng.choice(MODES))
        else:
            layer = PeriodicLayer(rng.randint(1, 9), rng.choice(["vigenere", "beaufort", "variant"]))
        layers.append(layer)
    return layers


@unittest.skipUnless(native.available(), "C library not built")
class LayeredEngineTests(unittest.TestCase):
    def test_c_decryption_and_fitness_match_python_layers(self):
        random.seed(11)
        rng = random.Random(11)
        m = model()
        cipher = codes(PLAINTEXT)
        for _ in range(60):
            kinds = [rng.choice(["sub", "trans", "periodic"]) for _ in range(rng.randint(1, 3))]
            length = rng.randint(30, len(cipher))
            text = cipher[:length]
            layers = random_layers(rng, length, kinds)
            counts_kept = all(layer.preserves_counts for layer in layers)
            fitness = Fitness(m, 0.5, fixed_letters=text if counts_kept else None)
            solver = LayeredSolver(text, layers, fitness)
            expected = python_stack_decrypt(text, layers)
            self.assertEqual(solver.plaintext(), expected, kinds)
            if counts_kept:     # same arithmetic: exact
                self.assertEqual(solver.score(), fitness(expected), kinds)
            else:               # entropy recomputed in C (log2/pow of the C library)
                self.assertAlmostEqual(solver.score(), fitness(expected), places=9, msg=kinds)
            # random moves (incremental window scoring in C), some undone: the
            # score stays the fitness of the plaintext
            for step in range(200):
                score = solver.propose()
                if step % 3 == 0:
                    solver.undo()
                    score = solver.score()
                plain = solver.plaintext()
                if counts_kept:
                    self.assertEqual(score, fitness(plain), kinds)
                else:
                    self.assertAlmostEqual(score, fitness(plain), places=9, msg=kinds)
            # the keys written back to the layer objects decrypt to the same text
            solver.restore(solver.snapshot())
            self.assertEqual(solver.plaintext(), python_stack_decrypt(text, layers), kinds)

    def test_moves_keep_keys_valid(self):
        random.seed(12)
        m = model()
        cipher = codes(PLAINTEXT)
        layers = [TranspositionLayer(len(cipher), 9, "write_cols_read_rows"), SubstitutionLayer(),
                  PeriodicLayer(7, "beaufort")]
        solver = LayeredSolver(cipher, layers, Fitness(m))
        for _ in range(3000):
            solver.propose()
            if random.random() < 0.5:
                solver.undo()
        trans, sub, periodic = solver.snapshot()
        self.assertEqual(sorted(trans), list(range(9)))
        self.assertEqual(sorted(sub), list(range(26)))
        self.assertTrue(all(0 <= k < 26 for k in periodic) and len(periodic) == 7)

    def test_polish_ends_at_a_local_optimum(self):
        """After polish no single move of any layer improves the fitness
        (checked by enumerating the moves in Python, test-only reference)."""
        random.seed(13)
        m = model()
        cipher = codes(PLAINTEXT[:150])
        layers = [PeriodicLayer(3), TranspositionLayer(len(cipher), 5, "write_rows_read_cols")]
        fitness = Fitness(m)
        solver = LayeredSolver(cipher, layers, fitness)
        score = solver.polish()
        base = solver.snapshot()
        self.assertEqual(score, fitness(solver.plaintext()))
        periodic, order = list(base[0]), list(base[1])
        candidates = []
        for column in range(3):
            for shift in range(26):
                key = periodic[:]
                key[column] = shift
                candidates.append((tuple(key), tuple(order)))
        for i in range(5):
            for j in range(5):
                if i < j:
                    key = order[:]
                    key[i], key[j] = key[j], key[i]
                    candidates.append((tuple(periodic), tuple(key)))
                if abs(i - j) > 1:
                    key = order[:]
                    key.insert(j, key.pop(i))
                    candidates.append((tuple(periodic), tuple(key)))
        for state in candidates:
            solver.restore(state)
            self.assertLessEqual(solver.score(), score + 1e-9, state)

    def test_anneal_returns_its_best_state(self):
        random.seed(14)
        m = model()
        cipher = codes(PLAINTEXT)
        fitness = Fitness(m, fixed_letters=cipher)
        solver = LayeredSolver(cipher, [SubstitutionLayer()], fitness)
        seen = []
        score = solver.anneal(Schedule(150_000), report=lambda *args: seen.append(args), report_seconds=0)
        self.assertEqual(score, solver.score())
        self.assertEqual(score, fitness(solver.plaintext()))
        self.assertEqual(solver.plaintext(), python_stack_decrypt(cipher, solver.layers))
        self.assertTrue(seen)              # progress reports between C calls

    def test_two_layer_solve_job_recovers_planted_stacks(self):
        import cipher_profile as cp
        import two_layer
        plain = codes(PLAINTEXT)
        rng = random.Random(15)
        order = rng.sample(range(7), 7)
        key = [rng.randrange(26) for _ in range(5)]
        middle = encrypt_transposition(plain, 7, order)
        cipher = bytes((v + key[i % 5]) % 26 for i, v in enumerate(middle))
        sigma = rng.sample(range(26), 26)
        # 330 letters fill the width-6 grid: with a short last row this text has a
        # one-letter-shifted decryption that scores higher than the true one
        cipher2 = encrypt_transposition(plain[:330].translate(bytes(sigma) + bytes(230)), 6, rng.sample(range(6), 6))
        for encryption, text, iterations, expected in (
                ([("trans", (7, "write_rows_read_cols")), ("periodic", (5, "vigenere"))], cipher, 300_000, plain),
                ([("sub", None), ("trans", (6, "write_rows_read_cols"))], cipher2, 400_000, plain[:330])):
            best = max((two_layer.solve_job({
                'cipher': text, 'encryption': encryption, 'iterations': iterations,
                'ngram_path': str(ns.DEFAULT_NGRAM_PATH), 'entropy_weight': 0.5, 'seed': seed, 'label': 'test'})
                for seed in range(3)), key=lambda result: result['score'])
            self.assertEqual(best['plaintext'], ns.codes_to_text(expected), encryption)
            self.assertEqual(best['score'], cp.fitness_function()(expected))
            self.assertEqual(len(best['keys']), len(encryption))

    def test_measure_step_time_is_positive(self):
        import two_layer
        job = {'cipher': codes(PLAINTEXT), 'encryption': [("sub", None), ("trans", (8, "write_rows_read_cols"))],
               'iterations': 1000, 'ngram_path': str(ns.DEFAULT_NGRAM_PATH), 'entropy_weight': 0.5, 'seed': 1,
               'label': 'x'}
        seconds = two_layer.measure_step_time(job)
        self.assertTrue(0 < seconds < 1e-3)

    def test_engine_limits_are_checked(self):
        cipher = codes(PLAINTEXT)
        with self.assertRaises(ValueError):
            LayeredSolver(cipher, [TranspositionLayer(len(cipher), 65, "write_rows_read_cols")], Fitness(model()))
        with self.assertRaises(ValueError):
            LayeredSolver(cipher, [PeriodicLayer(129)], Fitness(model()))


@unittest.skipUnless(native.available(), "C library not built")
class Tool31Tests(unittest.TestCase):
    def test_substitution_is_solved(self):
        import contextlib
        import io
        import simulated_annealing as tool31
        rng = random.Random(21)
        random.seed(21)
        sigma = rng.sample(range(26), 26)
        cipher = ns.codes_to_text(codes(PLAINTEXT).translate(bytes(sigma) + bytes(230)))
        m = ns.load_ngram_scores(ns.DEFAULT_NGRAM_PATH)
        results = []
        with contextlib.redirect_stdout(io.StringIO()):
            for mode in ("1", "3"):
                results.append(tool31.run_simulated_annealing(cipher, m, 20.0, 0.99, 500, 0.5, mode, 0.060, 0.070))
        for key, score, ioc, text in results:
            self.assertEqual(text, PLAINTEXT)
            # key[p] = cipher letter of plaintext letter p, for the letters that occur
            for p in set(codes(PLAINTEXT)):
                self.assertEqual(key[p], chr(65 + sigma[p]))
        cipher_codes = codes(cipher)
        self.assertEqual(results[0][1], Fitness(m, 0.5, fixed_letters=cipher_codes)(codes(PLAINTEXT)))


def reference_topk(cipher_codes, width, m, k, required=()):
    """Test-only reference: every order (itertools), best k by total, ties
    lexicographic; plus the orders whose plaintext contains every word."""
    decrypt = TranspositionLayer(len(cipher_codes), width, "write_rows_read_cols").permute
    scored, matches = [], set()
    for order in itertools.permutations(range(width)):
        plain = bytes(decrypt(cipher_codes, list(order)))
        total = ns.ngram_total(plain, m.scores, m.size)
        scored.append((-total, order))
        if required and all(word in plain for word in required):
            matches.add(order)
    scored.sort()
    return [order for _, order in scored[:k]], matches


@unittest.skipUnless(native.available(), "C library not built")
class Tool20Tests(unittest.TestCase):
    def setUp(self):
        import columnar_transposition as tool20
        self.tool20 = tool20
        self.model = tool20.load_bigram_frequencies(tool20.ngram_path)

    def test_exhaustive_matches_reference_ranking(self):
        import contextlib
        import io
        tool20 = self.tool20
        rng = random.Random(31)
        for width in (5, 6, 8):
            order = rng.sample(range(width), width)
            cipher_codes = encrypt_transposition(codes(PLAINTEXT[:200]), width, order)
            with contextlib.redirect_stdout(io.StringIO()):
                results = tool20.exhaustive_results(ns.codes_to_text(cipher_codes), width, ["RIVER", "GOLD"])
            expected, matches = reference_topk(cipher_codes, width, self.model, tool20.KEEP_PER_BATCH,
                                               [codes("RIVER"), codes("GOLD")])
            self.assertEqual(results[0]['plaintext'], PLAINTEXT[:200])
            self.assertEqual(results[0]['key'], tool20.order_to_key(order))
            got = [tool20.key_order(result['key']) for result in results]
            self.assertEqual(set(got), set(expected) | matches, width)
            self.assertEqual([o for o in got if o in set(expected)], expected, width)
            costs = [result['bigram_score'] for result in results]
            self.assertEqual(costs, sorted(costs))
            for result in results[:5]:
                self.assertEqual(result['bigram_score'], ns.score_text(result['plaintext'], self.model))

    def test_dictionary_batch_ranks_the_planted_keyword_first(self):
        tool20 = self.tool20
        keyword = "COLUMN"
        order = tool20.key_order(keyword)
        cipher = ns.codes_to_text(encrypt_transposition(codes(PLAINTEXT[:200]), 6, list(order)))
        words = ["ZEBRAS", "CIPHER", keyword, "KEY", "ATTACK", "SECRET", "GARDEN", "CUBE"]
        results = tool20.process_key_batch((words, cipher, self.model, ["RIVER"]))
        results.sort(key=lambda r: r['bigram_score'])
        self.assertEqual(results[0]['key'], keyword)
        self.assertEqual(results[0]['plaintext'], PLAINTEXT[:200])
        for result in results:      # cost = score_text of the plaintext
            self.assertEqual(result['bigram_score'], ns.score_text(result['plaintext'], self.model))

    def test_double_exhaustive_matches_reference_loop(self):
        import contextlib
        import io
        tool20 = self.tool20
        plain = PLAINTEXT[:120]
        key1, key2 = "201", "3102"
        cipher = ns.codes_to_text(encrypt_transposition(
            encrypt_transposition(codes(plain), 3, list(tool20.key_order(key1))), 4, list(tool20.key_order(key2))))
        with contextlib.redirect_stdout(io.StringIO()):
            found = tool20.double_exhaustive_results(cipher, 3, 4)
        # test-only reference: the loop this replaced (key1-major tie rule)
        best = None
        keys1 = ["".join(p) for p in itertools.permutations("012")]
        keys2 = ["".join(p) for p in itertools.permutations("0123")]
        for j, k2 in enumerate(keys2):
            middle = tool20.decrypt_columnar_transposition(cipher, k2)
            for i, k1 in enumerate(keys1):
                cost = ns.score_text(tool20.decrypt_columnar_transposition(middle, k1), self.model)
                if best is None or cost < best[0] or (cost == best[0] and (i, j) < best[1]):
                    best = (cost, (i, j), k1, k2)
        self.assertEqual((found['key1'], found['key2']), (best[2], best[3]))
        self.assertEqual(found['bigram_score'], best[0])
        self.assertEqual(found['plaintext'], plain)

    def test_anneal_columnar_single_and_double(self):
        import contextlib
        import io
        tool20 = self.tool20
        random.seed(33)
        order = random.sample(range(10), 10)
        cipher = ns.codes_to_text(encrypt_transposition(codes(PLAINTEXT), 10, order))
        with contextlib.redirect_stdout(io.StringIO()):
            keys, plaintext, cost = tool20.anneal_columnar(cipher, [10], 200_000, 3)
        self.assertEqual(plaintext, PLAINTEXT)
        self.assertEqual(keys[0], tool20.order_to_key(order))
        o1, o2 = random.sample(range(5), 5), random.sample(range(7), 7)
        cipher = ns.codes_to_text(encrypt_transposition(encrypt_transposition(codes(PLAINTEXT), 5, o1), 7, o2))
        with contextlib.redirect_stdout(io.StringIO()):
            keys, plaintext, cost = tool20.anneal_columnar(cipher, [5, 7], 400_000, 4)
        self.assertEqual(plaintext, PLAINTEXT)


@unittest.skipUnless(native.available(), "C library not built")
class Tool44Tests(unittest.TestCase):
    def test_annealing_passes_and_brute_force_recover_planted_orders(self):
        import contextlib
        import io
        import cipher_profile as cp
        import permutation_solver as tool44
        m = ns.load_ngram_scores(ns.DEFAULT_NGRAM_PATH)
        random.seed(41)
        order = random.sample(range(11), 11)
        plain = codes(PLAINTEXT)
        cipher = ns.codes_to_text(encrypt_transposition(plain, 11, order))
        with contextlib.redirect_stdout(io.StringIO()):
            # moves 1: swap or reverse (was tool 23); moves 0: swap only (was tool 32)
            r23 = max((tool44.run_simulated_annealing_pass(cipher, 11, "write_rows_read_cols", m, 20, 0.99, 500, 0.5)
                       for _ in range(2)), key=lambda r: r[1])
            r32 = max((tool44.run_simulated_annealing_pass(cipher, 11, "write_rows_read_cols", m, 20, 0.99, 500, 0.5, 0)
                       for _ in range(2)), key=lambda r: r[1])
            brute = tool44.run_brute_force_for_width(
                ns.codes_to_text(encrypt_transposition(plain, 7, [3, 1, 6, 0, 5, 2, 4])), 7, "write_rows_read_cols",
                m, 0.5)
        for result in (r23, r32, brute):
            self.assertEqual(result[2], PLAINTEXT)
            self.assertEqual(result[1], cp.fitness_function()(plain))
        self.assertEqual(r23[0], order)
        self.assertEqual(r32[0], order)


if __name__ == "__main__":
    unittest.main()
