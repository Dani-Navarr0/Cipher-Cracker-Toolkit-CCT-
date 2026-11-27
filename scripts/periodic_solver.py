"""Shared annealing solver for periodic-key ciphers (Vigenere family).

Vigenere, Beaufort, Variant, Porta and Gronsfeld differ only in how one key
symbol decrypts one cipher letter, so one solver serves them all: Python turns
the cipher's rule into one table row per key symbol, and the C engine
(scripts/native/periodic_engine.c) runs every restart: random key, simulated
annealing in C (one key column changes per move; geometric cooling,
annealing.Schedule), then a hill-climb polish over every single-symbol change.

Alphabets: any alphabet of 1 to 256 characters (A-Z, a keyed alphabet such as
KRYPTOSABCDEFGHIJLMNQUVWXZ, a 25-letter I/J-merged alphabet, one with digits).
The text scored is the text the tools show: each character whose upper case is
in the alphabet is decrypted and shown as alphabet[p].lower(); every other
character passes through as char.lower(). Its A-Z letters (after upper()) are
the plaintext codes the fitness is computed on, so letters that are not in the
alphabet (the J of an I/J-merged alphabet) are scored where they stand.
"""
import random

from annealing import Schedule
from ngram_scoring import codes_to_text, text_to_codes

from native import periodic_engine

MAX_ALPHABET = 256
CANNOT_START = ("Annealing needs at least one ciphertext character that is in the alphabet, a key length of at "
                "least 1, and an alphabet of 1 to 256 characters.")


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
    cipher's decryption for alphabet indices (m = alphabet length). A key
    symbol that occurs more than once in ``key_symbols`` is used at its last
    position, as the tools' {char: index} alphabet dictionaries do.
    ``scoring_mode``: '1' n-grams (annealing.Fitness), '2' IoC target only,
    '3' n-grams weighted by the IoC target (``ioc_range`` = (min, max)).
    ``report(step, temperature, best score, best key tuple)`` is called about
    twice a second during each restart (key = indices into key_symbols).
    Returns a list of ``(key, fitness, plaintext)`` per restart, best first,
    where plaintext is the A-Z letters of the shown text and fitness is
    annealing.Fitness of them (mode '1'); or None if the alphabet is empty or
    longer than 256 characters, no ciphertext character is in the alphabet, or
    there is no key symbol or key column.
    """
    schedule = schedule or Schedule()
    alphabet = alphabet_str.upper()
    m = len(alphabet)
    if not 1 <= m <= MAX_ALPHABET:
        return None
    index_of = {char: i for i, char in enumerate(alphabet)}
    symbols, layout = [], []
    for char in ciphertext:
        index = index_of.get(char.upper())
        if index is not None:
            layout.append(len(symbols))
            symbols.append(index)
        else:
            layout.extend(-(code + 1) for code in text_to_codes(char.lower()))
    if not symbols or key_length < 1 or not key_symbols:
        return None
    key_indices = [k for k, char in enumerate(key_symbols) if key_symbols.rfind(char) == k]
    symbol_codes = [text_to_codes(char.lower()) for char in alphabet]
    try:
        rows = [[rule(c, k, m) for c in range(m)] for k in key_indices]
    except ZeroDivisionError:        # e.g. Porta on a one-letter alphabet (its decrypt fails the same way)
        return None
    if any(not 0 <= p < m for row in rows for p in row):
        raise ValueError("the cipher rule gave a plaintext index outside the alphabet")
    if all(len(codes) == 1 for codes in symbol_codes) and all(item >= 0 for item in layout):
        # one scored letter per cipher symbol: the tables give letter codes directly
        tables = b"".join(bytes(symbol_codes[p][0] for p in row) for row in rows)
        built, keep = periodic_engine.problem(symbols, key_length, tables, len(key_indices), ngram_model,
                                              entropy_weight, scoring_mode, ioc_range or (0.060, 0.070), m)
    else:
        tables = b"".join(bytes(row) for row in rows)
        built, keep = periodic_engine.problem(symbols, key_length, tables, len(key_indices), ngram_model,
                                              entropy_weight, scoring_mode, ioc_range or (0.060, 0.070), m,
                                              layout, symbol_codes)
    progress = None
    if report is not None:
        def progress(step, temperature, best, best_key):
            report(step, temperature, best, tuple(key_indices[k] for k in best_key))
    results = []
    for _ in range(max(1, restarts)):
        key, score, plain = periodic_engine.anneal(built, schedule.iterations, schedule.t_start, schedule.t_end,
                                                   random.getrandbits(64), progress)
        results.append(("".join(key_symbols[key_indices[k]] for k in key), score, codes_to_text(plain)))
    results.sort(key=lambda result: -result[1])
    return results
