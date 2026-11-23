"""Shared simulated-annealing engine used by every key-search solver.

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
import random
import time
from dataclasses import dataclass
from typing import Callable, Optional

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


def anneal(
    initial_score: float,
    propose: Callable[[], float],
    undo: Callable[[], None],
    snapshot: Callable[[], object],
    schedule: Schedule,
    report: Optional[Callable[[int, float, float, object], None]] = None,
    report_seconds: float = 0.5,
):
    """Maximise a score by simulated annealing.

    ``propose()`` applies a random change to the solver's current state and
    returns the new score; ``undo()`` reverts the last change; ``snapshot()``
    returns a copy of the current state (called only on a new best).
    Returns ``(best_state, best_score)``. Ctrl+C stops early and returns the
    best found so far.
    """
    current = best = initial_score
    best_state = snapshot()
    iterations = max(1, int(schedule.iterations))
    temperature = schedule.t_start
    ratio = (schedule.t_end / schedule.t_start) ** (1.0 / iterations)
    rand, exp = random.random, math.exp
    next_report = time.time() + report_seconds
    try:
        for step in range(iterations):
            score = propose()
            difference = score - current
            if difference >= 0 or rand() < exp(difference / temperature):
                current = score
                if score > best:
                    best = score
                    best_state = snapshot()
            else:
                undo()
            temperature *= ratio
            if report is not None and not step & 1023 and time.time() >= next_report:
                report(step, temperature, best, best_state)
                next_report = time.time() + report_seconds
    except KeyboardInterrupt:
        print("\nPass interrupted; keeping the best result so far.")
    return best_state, best


def hill_climb(score: float, moves, apply_move, undo, max_rounds: int = 50) -> float:
    """Deterministic polish: try every move, keep improvements, until none help.

    ``moves`` is a list of move descriptions; ``apply_move(move)`` applies one
    and returns the new score; ``undo()`` reverts it.
    """
    for _ in range(max_rounds):
        improved = False
        for move in moves:
            new_score = apply_move(move)
            if new_score > score + 1e-12:
                score = new_score
                improved = True
            else:
                undo()
        if not improved:
            break
    return score
