"""Multi-layer cipher model: each layer is one classical cipher with a key, and
a stack of layers is decrypted in sequence. The search over the keys (joint
simulated annealing and the final hill climb) runs in C
(native/layered_engine.c); the layer classes here hold the keys and decrypt
once (encryption in tests and test-cipher makers, display).

Layers operate on bytes of letter codes 0-25. A stack is given in DECRYPTION
order: ``layers[0]`` is applied to the ciphertext first (it is the layer that
was applied LAST during encryption).
"""
import random
import time

from annealing import Fitness, Schedule
from transposition_core import make_permuter

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
# English letter frequencies (%), used to seed keys from letter counts.
ENGLISH_FREQUENCIES = [
    8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61,
    6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07,
]
TRANSPOSITION_MODES = {
    'write_rows_read_cols': 'Write Rows, Read Columns (Standard Columnar)',
    'write_rows_read_rows': 'Write Rows, Read Rows',
    'write_cols_read_rows': 'Write Columns, Read Rows',
    'write_cols_read_cols': 'Write Columns, Read Columns',
}
# Annealing steps per C call: Ctrl+C and progress reports are handled between calls.
CHUNK_STEPS = 100_000


class SubstitutionLayer:
    """Simple (monoalphabetic) substitution. ``table[c]`` = plaintext of cipher letter c."""
    name = "Substitution"
    kind = "sub"
    preserves_counts = True

    def __init__(self):
        self.table = bytearray(range(256))
        self.randomize()

    def randomize(self):
        self.table[:26] = bytes(random.sample(range(26), 26))

    def seed(self, source):
        """Map cipher letters to plaintext letters by frequency rank."""
        cipher_order = sorted(range(26), key=lambda code: -source.count(code))
        english_order = sorted(range(26), key=lambda code: -ENGLISH_FREQUENCIES[code])
        for cipher, plain in zip(cipher_order, english_order):
            self.table[cipher] = plain

    def decrypt(self, source):
        return source.translate(self.table)

    def spec(self):
        """(kind, key length, variant, layout) for the C engine."""
        return ("sub", 26, None, None)

    def key_codes(self):
        return list(self.table[:26])

    def snapshot(self):
        return bytes(self.table[:26])

    def restore(self, snapshot):
        self.table[:26] = bytes(snapshot)

    @staticmethod
    def describe(snapshot):
        cipher_for_plain = ["?"] * 26
        for cipher, plain in enumerate(snapshot):
            cipher_for_plain[plain] = ALPHABET[cipher]
        return f"plain {ALPHABET} -> cipher {''.join(cipher_for_plain)}"


class TranspositionLayer:
    """Columnar-style transposition of a fixed width in one of four layouts."""
    kind = "trans"
    preserves_counts = True

    def __init__(self, length: int, width: int, mode: str):
        self.width = width
        self.mode = mode
        self.name = f"Transposition (width {width}, {TRANSPOSITION_MODES[mode]})"
        self.permute = make_permuter(length, width, mode)
        self.key = list(range(width))
        self.randomize()

    def randomize(self):
        random.shuffle(self.key)

    def seed(self, source):
        self.randomize()

    def decrypt(self, source):
        return self.permute(source, self.key)

    def spec(self):
        return ("trans", self.width, None, self.mode)

    def key_codes(self):
        return list(self.key)

    def snapshot(self):
        return tuple(self.key)

    def restore(self, snapshot):
        self.key[:] = snapshot

    @staticmethod
    def describe(snapshot):
        return f"column order {list(snapshot)}"


class PeriodicLayer:
    """Periodic polyalphabetic layer (Vigenere, Beaufort, Variant Beaufort)."""
    kind = "periodic"
    preserves_counts = False
    VARIANTS = {
        'vigenere': lambda c, k: (c - k) % 26,
        'beaufort': lambda c, k: (k - c) % 26,
        'variant': lambda c, k: (c + k) % 26,
    }

    def __init__(self, period: int, variant: str = 'vigenere'):
        self.period = period
        self.variant = variant
        self.name = f"{variant.title()} (period {period})"
        rule = self.VARIANTS[variant]
        self.tables = [bytes(rule(c, k) for c in range(26)) + bytes(230) for k in range(26)]
        self.key = [0] * period
        self.randomize()

    def randomize(self):
        self.key = [random.randrange(26) for _ in range(self.period)]

    def seed(self, source):
        """Per column, the shift whose decryption best matches English letter frequencies.

        Exact for a layer whose inner layers only reorder letters (transposition);
        a reasonable start otherwise.
        """
        for column in range(self.period):
            letters = source[column::self.period]
            total = max(1, len(letters))
            best_shift, best_chi = 0, float("inf")
            for shift in range(26):
                plain = letters.translate(self.tables[shift])
                chi = 0.0
                for code in range(26):
                    expected = ENGLISH_FREQUENCIES[code] * total / 100
                    chi += (plain.count(code) - expected) ** 2 / expected
                if chi < best_chi:
                    best_shift, best_chi = shift, chi
            self.key[column] = best_shift

    def decrypt(self, source):
        output = bytearray(len(source))
        period, tables, key = self.period, self.tables, self.key
        for column in range(period):
            output[column::period] = source[column::period].translate(tables[key[column]])
        return output

    def spec(self):
        return ("periodic", self.period, self.variant, None)

    def key_codes(self):
        return list(self.key)

    def snapshot(self):
        return tuple(self.key)

    def restore(self, snapshot):
        self.key = list(snapshot)

    def describe(self, snapshot):
        return f"key {''.join(ALPHABET[k] for k in snapshot)}"


class LayeredSolver:
    """Joint annealing over every layer's key, scoring the fully decrypted text.

    The search runs in C (native/layered_engine.c; 1-4 layers, transposition
    width <= 64, period <= 128). The layers' current keys are the starting
    point (random from the constructors, or set with seed()); after anneal(),
    polish() and restore() the keys found are written back to the layer objects.
    Raises native.NativeUnavailable when the C library is not built.
    """

    def __init__(self, cipher_codes: bytes, layers, fitness: Fitness, weights=None, seed=None):
        from native.layered_engine import Stack
        self.cipher = bytes(cipher_codes)
        self.layers = layers
        self.fitness = fitness
        self.stack = Stack(self.cipher, [layer.spec() for layer in layers], weights or [1.0] * len(layers),
                           fitness.scores, fitness.size, fitness.entropy_weight, fitness.fixed_factor,
                           random.getrandbits(64) if seed is None else seed)
        for index, layer in enumerate(layers):
            self.stack.set_key(index, layer.key_codes())

    def plaintext(self) -> bytes:
        return self.stack.plaintext()

    def score(self) -> float:
        return self.stack.score()

    def propose(self) -> float:
        """One random move in C (a layer chosen by weight); undo() reverts it."""
        return self.stack.propose()

    def undo(self):
        self.stack.undo()

    def _layer_snapshot(self, index, best=False):
        key = self.stack.get_key(index, best)
        return bytes(key) if self.layers[index].kind == "sub" else tuple(key)

    def snapshot(self):
        return tuple(self._layer_snapshot(index) for index in range(len(self.layers)))

    def restore(self, snapshot):
        for index, state in enumerate(snapshot):
            self.stack.set_key(index, list(state))
        self._sync()

    def _sync(self):
        """Write the C engine's current keys back to the layer objects."""
        for index, layer in enumerate(self.layers):
            layer.restore(self._layer_snapshot(index))

    def anneal(self, schedule: Schedule, report=None, report_seconds: float = 0.5):
        """Simulated annealing in C, CHUNK_STEPS steps per call. ``report(step,
        temperature, best score, best state)`` is called about every
        report_seconds. Ctrl+C stops early and keeps the best so far. Leaves the
        best state current and returns its score."""
        stack = self.stack
        stack.schedule(schedule.iterations, schedule.t_start, schedule.t_end)
        next_report = time.time() + report_seconds
        try:
            while stack.anneal(CHUNK_STEPS):
                if report is not None and time.time() >= next_report:
                    step, _, best, temperature = stack.status()
                    report(step, temperature, best,
                           tuple(self._layer_snapshot(i, best=True) for i in range(len(self.layers))))
                    next_report = time.time() + report_seconds
        except KeyboardInterrupt:
            print("\nPass interrupted; keeping the best result so far.")
        score = stack.restore_best()
        self._sync()
        return score

    def polish(self, max_rounds: int = 20) -> float:
        """Hill-climb every single move of every layer (in C) until nothing improves."""
        score = self.stack.polish(max_rounds)
        self._sync()
        return score

    def seconds_per_step(self, steps: int = 20_000) -> float:
        """Measured time of one annealing step on this machine (keys are restored after)."""
        saved = self.snapshot()
        self.stack.schedule(steps, 20.0, 0.1)
        started = time.perf_counter()
        self.stack.anneal(steps)
        elapsed = time.perf_counter() - started
        self.restore(saved)
        return elapsed / max(1, steps)

    def describe(self, snapshot=None):
        snapshot = snapshot or self.snapshot()
        return [f"{layer.name}: {layer.describe(state)}" for layer, state in zip(self.layers, snapshot)]
