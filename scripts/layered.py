"""Multi-layer cipher model: each layer is one classical cipher with a key that
annealing can modify, and a stack of layers is decrypted in sequence.

Layers operate on bytes of letter codes 0-25. A stack is given in DECRYPTION
order: ``layers[0]`` is applied to the ciphertext first (it is the layer that
was applied LAST during encryption).
"""
import random

from annealing import Fitness, Schedule, anneal, hill_climb
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


class SubstitutionLayer:
    """Simple (monoalphabetic) substitution. ``table[c]`` = plaintext of cipher letter c."""
    name = "Substitution"
    preserves_counts = True

    def __init__(self):
        self.table = bytearray(range(256))
        self.present = list(range(26))
        self.randomize()

    def prepare(self, source):
        """Restrict moves to cipher letters that actually occur in this layer's input."""
        present = sorted(set(source))
        self.present = present if len(present) >= 2 else list(range(26))

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

    def move(self):
        a = random.choice(self.present)
        b = random.randrange(25)
        b += b >= a
        table = self.table
        table[a], table[b] = table[b], table[a]
        self._last = (a, b)

    def undo(self):
        a, b = self._last
        table = self.table
        table[a], table[b] = table[b], table[a]

    def all_moves(self):
        return [(a, b) for a in self.present for b in range(26) if b != a and (b not in self.present or b > a)]

    def apply(self, move):
        a, b = move
        table = self.table
        table[a], table[b] = table[b], table[a]
        self._last = move

    def snapshot(self):
        return bytes(self.table[:26])

    def restore(self, snapshot):
        self.table[:26] = snapshot

    @staticmethod
    def describe(snapshot):
        cipher_for_plain = ["?"] * 26
        for cipher, plain in enumerate(snapshot):
            cipher_for_plain[plain] = ALPHABET[cipher]
        return f"plain {ALPHABET} -> cipher {''.join(cipher_for_plain)}"


class TranspositionLayer:
    """Columnar-style transposition of a fixed width in one of four layouts."""
    preserves_counts = True

    def __init__(self, length: int, width: int, mode: str):
        self.width = width
        self.mode = mode
        self.name = f"Transposition (width {width}, {TRANSPOSITION_MODES[mode]})"
        self.permute = make_permuter(length, width, mode)
        self.key = list(range(width))
        self.randomize()

    def prepare(self, source):
        pass

    def randomize(self):
        random.shuffle(self.key)

    def seed(self, source):
        self.randomize()

    def decrypt(self, source):
        return self.permute(source, self.key)

    def move(self):
        key = self.key
        self._last = key[:]
        width = self.width
        roll = random.random()
        i, j = random.sample(range(width), 2)
        if roll < 0.6:      # swap two columns
            key[i], key[j] = key[j], key[i]
        elif roll < 0.8:    # reverse a block of columns
            if i > j:
                i, j = j, i
            key[i:j + 1] = key[i:j + 1][::-1]
        else:               # move one column to another position
            key.insert(j, key.pop(i))

    def undo(self):
        self.key[:] = self._last

    def all_moves(self):
        swaps = [("swap", i, j) for i in range(self.width) for j in range(i + 1, self.width)]
        shifts = [("move", i, j) for i in range(self.width) for j in range(self.width) if abs(i - j) > 1]
        return swaps + shifts

    def apply(self, move):
        kind, i, j = move
        self._last = self.key[:]
        if kind == "swap":
            self.key[i], self.key[j] = self.key[j], self.key[i]
        else:
            self.key.insert(j, self.key.pop(i))

    def snapshot(self):
        return tuple(self.key)

    def restore(self, snapshot):
        self.key[:] = snapshot

    @staticmethod
    def describe(snapshot):
        return f"column order {list(snapshot)}"


class PeriodicLayer:
    """Periodic polyalphabetic layer (Vigenere, Beaufort, Variant Beaufort)."""
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

    def prepare(self, source):
        pass

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

    def move(self):
        column = random.randrange(self.period)
        old = self.key[column]
        new = random.randrange(25)
        self.key[column] = new + (new >= old)
        self._last = (column, old)

    def undo(self):
        column, old = self._last
        self.key[column] = old

    def all_moves(self):
        return [(column, shift) for column in range(self.period) for shift in range(26)]

    def apply(self, move):
        column, shift = move
        self._last = (column, self.key[column])
        self.key[column] = shift

    def snapshot(self):
        return tuple(self.key)

    def restore(self, snapshot):
        self.key = list(snapshot)

    def describe(self, snapshot):
        return f"key {''.join(ALPHABET[k] for k in snapshot)}"


class LayeredSolver:
    """Joint annealing over every layer's key, scoring the fully decrypted text.

    Intermediate results are cached per layer, so a move in a later layer (in
    decryption order) only re-runs that layer and the ones after it.
    """

    def __init__(self, cipher_codes: bytes, layers, fitness: Fitness, weights=None):
        self.cipher = bytes(cipher_codes)
        self.layers = layers
        self.fitness = fitness
        weights = weights or [1.0] * len(layers)
        total = sum(weights)
        cumulative, running = [], 0.0
        for weight in weights:
            running += weight / total
            cumulative.append(running)
        self.cumulative = cumulative
        self.outputs = [None] * len(layers)
        self._recompute(0)
        for index, layer in enumerate(layers):
            layer.prepare(self.cipher if index == 0 else self.outputs[index - 1])
        self.current = self.fitness(self.outputs[-1])

    def _recompute(self, start):
        text = self.cipher if start == 0 else self.outputs[start - 1]
        for index in range(start, len(self.layers)):
            text = self.layers[index].decrypt(text)
            self.outputs[index] = text
        return text

    def plaintext(self) -> bytes:
        return bytes(self.outputs[-1])

    def score(self) -> float:
        return self.fitness(self.outputs[-1])

    def _choose_layer(self):
        roll = random.random()
        for index, bound in enumerate(self.cumulative):
            if roll < bound:
                return index
        return len(self.layers) - 1

    def propose(self) -> float:
        index = self._choose_layer()
        self._saved = (index, self.outputs[index:])
        self.layers[index].move()
        return self.fitness(self._recompute(index))

    def undo(self):
        index, saved = self._saved
        self.layers[index].undo()
        self.outputs[index:] = saved

    def snapshot(self):
        return tuple(layer.snapshot() for layer in self.layers)

    def restore(self, snapshot):
        for layer, state in zip(self.layers, snapshot):
            layer.restore(state)
        self._recompute(0)

    def anneal(self, schedule: Schedule, report=None):
        best_state, best_score = anneal(self.score(), self.propose, self.undo, self.snapshot, schedule, report)
        self.restore(best_state)
        return best_score

    def polish(self, max_rounds: int = 20) -> float:
        """Hill-climb every single move of every layer until nothing improves."""
        score = self.score()
        for _ in range(max_rounds):
            before = score
            for index, layer in enumerate(self.layers):
                def apply_move(move, index=index, layer=layer):
                    self._saved = (index, self.outputs[index:])
                    layer.apply(move)
                    return self.fitness(self._recompute(index))
                score = hill_climb(score, layer.all_moves(), apply_move, self.undo, max_rounds=1)
            if score <= before + 1e-12:
                break
        return score

    def describe(self, snapshot=None):
        snapshot = snapshot or self.snapshot()
        return [f"{layer.name}: {layer.describe(state)}" for layer, state in zip(self.layers, snapshot)]
