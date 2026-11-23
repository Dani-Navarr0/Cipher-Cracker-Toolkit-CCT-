"""Shared annealing solver for periodic-key ciphers (Vigenere family).

Vigenere, Beaufort, Porta and Gronsfeld differ only in how one key symbol
decrypts one cipher letter, so one solver serves them all: each key symbol is
turned into a 256-byte translation table and only the key column that changed
is re-decrypted on each step (a C-level ``translate`` plus slice assignment).
"""
import random

from annealing import Fitness, Schedule, anneal, hill_climb
from ngram_scoring import codes_to_text, text_to_codes

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def ioc_of_codes(codes) -> float:
    total = len(codes)
    if total < 2:
        return 0.0
    return sum(codes.count(code) * (codes.count(code) - 1) for code in range(26)) / (total * (total - 1))


def solve_periodic(
    ciphertext: str,
    alphabet_str: str,
    key_symbols: str,
    key_length: int,
    rule,
    ngram_model,
    schedule: Schedule = None,
    restarts: int = 1,
    entropy_weight: float = 0.5,
    ioc_range=None,
    scoring_mode: str = '1',
    report=None,
):
    """Anneal a periodic key.

    ``rule(cipher_index, key_symbol_index, m) -> plaintext_index`` gives the
    cipher's decryption for alphabet indices (m = alphabet length).
    ``scoring_mode``: '1' n-grams, '2' IoC target only, '3' n-grams weighted by
    the IoC target (``ioc_range`` = (min, max)).
    Returns a list of ``(key, fitness, plaintext)`` per restart, best first,
    or None if the alphabet is not a permutation of A-Z (no fast path).
    """
    schedule = schedule or Schedule()
    alphabet = alphabet_str.upper()
    if sorted(alphabet) != list(ALPHABET):
        return None
    index_of = {char: i for i, char in enumerate(alphabet)}
    symbols = []
    for char in ciphertext:
        upper = char.upper()
        if upper in index_of:
            symbols.append(index_of[upper])
        elif text_to_codes(char):
            return None
    symbols = bytes(symbols)
    if not symbols or key_length < 1:
        return None
    columns = [symbols[j::key_length] for j in range(key_length)]
    plain_codes = [ord(char) - 65 for char in alphabet]
    tables = [
        bytes(plain_codes[rule(index, k, 26)] for index in range(26)) + bytes(230)
        for k in range(len(key_symbols))
    ]

    base = Fitness(ngram_model, entropy_weight)
    min_ioc, max_ioc = ioc_range or (0.060, 0.070)

    def penalty(codes):
        ioc = ioc_of_codes(codes)
        return 0.0 if min_ioc <= ioc <= max_ioc else min(abs(ioc - min_ioc), abs(ioc - max_ioc))

    if scoring_mode == '2':
        def fitness(codes):
            return -penalty(codes) * 1000.0
    elif scoring_mode == '3':
        def fitness(codes):
            return base(codes) * max(0.05, 1.0 - penalty(codes) * 20.0)
    else:
        fitness = base

    plain = bytearray(len(symbols))
    key = [0] * key_length
    last = []

    def set_column(column, symbol):
        key[column] = symbol
        plain[column::key_length] = columns[column].translate(tables[symbol])

    def propose():
        column = random.randrange(key_length)
        old = key[column]
        new = random.randrange(len(tables) - 1)
        new += new >= old
        last[:] = [column, old]
        set_column(column, new)
        return fitness(plain)

    def undo():
        set_column(*last)

    def snapshot():
        return tuple(key)

    results = []
    for _ in range(max(1, restarts)):
        for column in range(key_length):
            set_column(column, random.randrange(len(tables)))
        best_key, _ = anneal(fitness(plain), propose, undo, snapshot, schedule, report)
        for column, symbol in enumerate(best_key):
            set_column(column, symbol)

        def apply_move(move):
            column, symbol = move
            last[:] = [column, key[column]]
            set_column(column, symbol)
            return fitness(plain)

        moves = [(column, symbol) for column in range(key_length) for symbol in range(len(tables))]
        score = hill_climb(fitness(plain), moves, apply_move, undo)
        results.append(("".join(key_symbols[k] for k in key), score, codes_to_text(plain)))
    results.sort(key=lambda result: -result[1])
    return results
