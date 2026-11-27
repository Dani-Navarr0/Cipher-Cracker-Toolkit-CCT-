"""Shared fitness and schedule definitions for the toolkit's annealing solvers.

The annealing itself runs in the C engines (scripts/native/*.c); this module
defines what they must compute, and the tests check them against it.

Every solver maximises the same fitness: the mean n-gram log score of the
candidate plaintext (bytes 0-255 from the AZdecrypt tables) multiplied by
``entropy ** entropy_weight``. Because the fitness is a *mean*, its scale does
not depend on the text length, so one temperature range suits every solver.

Measured on English text (5-grams): a single key change moves the fitness by
a median of roughly 0.5-2 points from a random key and 25-40 points next to
the correct key. A schedule that cools geometrically from about 20 to 0.1
therefore starts by accepting almost any move and ends as a pure hill climb.
"""
import math
from dataclasses import dataclass

from ngram_scoring import ngram_total

DEFAULT_T_START = 20.0
DEFAULT_T_END = 0.1


@dataclass
class Schedule:
    """Geometric cooling from ``t_start`` to ``t_end`` over ``iterations`` moves."""
    iterations: int = 100_000
    t_start: float = DEFAULT_T_START
    t_end: float = DEFAULT_T_END


class Fitness:
    """Mean n-gram score x entropy factor for 0-25 letter codes.

    ``entropy_factor`` may be fixed in advance when the cipher cannot change
    letter counts (substitution, transposition); otherwise it is recomputed.
    """

    def __init__(self, ngram_model, entropy_weight: float = 0.5, fixed_letters=None):
        self.scores = ngram_model.scores
        self.size = ngram_model.size
        self.entropy_weight = entropy_weight
        self.fixed_factor = None
        if fixed_letters is not None:
            self.fixed_factor = letter_entropy(fixed_letters) ** entropy_weight

    def __call__(self, codes) -> float:
        count = len(codes) - self.size + 1
        if count <= 0:
            return -9999.0
        factor = self.fixed_factor
        if factor is None:
            factor = letter_entropy(codes) ** self.entropy_weight
        return (ngram_total(codes, self.scores, self.size) / count) * factor


def letter_entropy(letters) -> float:
    total = len(letters)
    if not total:
        return 0.0
    entropy = 0.0
    for code in range(26):  # letters are 0-25 codes; bytes.count runs in C
        count = letters.count(code)
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy
