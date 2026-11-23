"""Tests for the shared annealing engine, layered (two-layer) model and the
periodic-key solver.  Run: python -m unittest discover -s tests -t ."""
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

from annealing import Fitness, Schedule  # noqa: E402
from layered import LayeredSolver, PeriodicLayer, SubstitutionLayer, TranspositionLayer  # noqa: E402
import ngram_scoring  # noqa: E402

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PLAINTEXT = (
    "THEREWEREMANYTHINGSTHATCOULDHAVEGONEWRONGWITHTHEPLANBUTTHEMOSTIMPORTANT"
    "THINGWASTHATNOBODYKNEWWHEREWEHADHIDDENTHEGOLDANDSOWEWAITEDFORTHENIGHT"
    "TOCOMEANDTHENWEWALKEDSLOWLYDOWNTOTHERIVERWHERETHEBOATWASWAITINGFORUS"
)


def codes(text):
    return ngram_scoring.text_to_codes(text)


def encrypt_transposition(plain, layer):
    """Inverse of layer.decrypt for the layer's current key."""
    n = len(plain)
    low = layer.decrypt(bytes(i % 256 for i in range(n)))
    high = layer.decrypt(bytes(i // 256 for i in range(n)))
    out = bytearray(n)
    for target, (h, l) in enumerate(zip(high, low)):
        out[h * 256 + l] = plain[target]
    return bytes(out)


class LayerRoundTripTests(unittest.TestCase):
    def test_each_layer_inverts_its_encryption(self):
        rng = random.Random(5)
        random.seed(5)
        plain = codes(PLAINTEXT)
        sigma = rng.sample(range(26), 26)
        substitution = SubstitutionLayer()
        inverse = [0] * 26
        for p, c in enumerate(sigma):
            inverse[c] = p
        substitution.table[:26] = bytes(inverse)
        self.assertEqual(substitution.decrypt(plain.translate(bytes(sigma) + bytes(230))), plain)

        for variant, encrypt in (("vigenere", lambda p, k: (p + k) % 26),
                                 ("beaufort", lambda p, k: (k - p) % 26),
                                 ("variant", lambda p, k: (p - k) % 26)):
            layer = PeriodicLayer(7, variant)
            cipher = bytes(encrypt(p, layer.key[i % 7]) for i, p in enumerate(plain))
            self.assertEqual(layer.decrypt(cipher), plain, variant)

        for mode in ("write_rows_read_cols", "write_rows_read_rows", "write_cols_read_rows", "write_cols_read_cols"):
            layer = TranspositionLayer(len(plain), 9, mode)
            self.assertEqual(layer.decrypt(encrypt_transposition(plain, layer)), plain, mode)

    def test_two_layer_stack_decrypts_with_true_keys(self):
        random.seed(6)
        plain = codes(PLAINTEXT)
        transposition = TranspositionLayer(len(plain), 8, "write_rows_read_cols")
        vigenere = PeriodicLayer(5)
        middle = encrypt_transposition(plain, transposition)                         # transposition first
        cipher = bytes((v + vigenere.key[i % 5]) % 26 for i, v in enumerate(middle))  # then Vigenere
        model = ngram_scoring.load_ngram_scores(ngram_scoring.resolve_ngram_path(4))
        solver = LayeredSolver(cipher, [vigenere, transposition], Fitness(model))
        self.assertEqual(solver.plaintext(), plain)

    def test_moves_undo_exactly(self):
        random.seed(7)
        plain = codes(PLAINTEXT)
        model = ngram_scoring.load_ngram_scores(ngram_scoring.resolve_ngram_path(4))
        solver = LayeredSolver(plain, [TranspositionLayer(len(plain), 7, "write_rows_read_rows"),
                                       SubstitutionLayer(), PeriodicLayer(3)], Fitness(model))
        before_state, before_text = solver.snapshot(), solver.plaintext()
        for _ in range(500):
            solver.propose()
            solver.undo()
        self.assertEqual(solver.snapshot(), before_state)
        self.assertEqual(solver.plaintext(), before_text)


class SolverTests(unittest.TestCase):
    def test_substitution_plus_transposition_is_solved(self):
        rng = random.Random(8)
        random.seed(8)
        plain = codes(PLAINTEXT)
        transposition = TranspositionLayer(len(plain), 5, "write_rows_read_cols")
        cipher = encrypt_transposition(plain.translate(bytes(rng.sample(range(26), 26)) + bytes(230)), transposition)
        model = ngram_scoring.load_ngram_scores(ngram_scoring.resolve_ngram_path(4))
        best = None
        for _ in range(3):
            solver = LayeredSolver(cipher, [TranspositionLayer(len(plain), 5, "write_rows_read_cols"),
                                            SubstitutionLayer()], Fitness(model, fixed_letters=cipher))
            solver.anneal(Schedule(120_000))
            score = solver.polish()
            if best is None or score > best[0]:
                best = (score, solver.plaintext())
        correct = sum(a == b for a, b in zip(best[1], plain)) / len(plain)
        self.assertGreater(correct, 0.9)

    def test_periodic_rules_match_cipher_modules(self):
        import beaufort
        import porta
        import vigenere
        rng = random.Random(9)
        for _ in range(50):
            key = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 8)))
            text = "".join(rng.choice(ALPHABET) for _ in range(40))
            for module, decrypt, rule in (
                (vigenere, vigenere.decrypt_vigenere, lambda c, k, m: (c - k) % m),
                (beaufort, beaufort.decrypt_beaufort, lambda c, k, m: (k - c) % m),
                (porta, porta.decrypt_porta, porta.porta_rule),
            ):
                expected = decrypt(text, key, ALPHABET).upper()
                got = "".join(
                    ALPHABET[rule(ALPHABET.index(c), ALPHABET.index(key[i % len(key)]), 26)]
                    for i, c in enumerate(text)
                )
                self.assertEqual(got, expected, module.__name__)

    def test_periodic_solver_recovers_vigenere_key(self):
        from periodic_solver import solve_periodic
        random.seed(10)
        cipher = "".join(ALPHABET[(ALPHABET.index(c) + ALPHABET.index("LEMON"[i % 5])) % 26]
                         for i, c in enumerate(PLAINTEXT))
        model = ngram_scoring.load_ngram_scores(ngram_scoring.resolve_ngram_path(4))
        results = solve_periodic(cipher, ALPHABET, ALPHABET, 5, lambda c, k, m: (c - k) % m,
                                 model, Schedule(30_000), restarts=2)
        self.assertEqual(results[0][0], "LEMON")
        self.assertEqual(results[0][2], PLAINTEXT)


if __name__ == "__main__":
    unittest.main()
