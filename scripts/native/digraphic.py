"""Python wrappers for the square-key engines (digraphic.c, digraphic_hill.c):
Playfair / Four-square / Bifid-Trifid annealing, the Playfair keyword scorer
and the Hill row attack. Every function raises native.NativeUnavailable when
the C library is not built (there is no Python fallback).

Annealing runs in chunks of CHUNK moves so that progress can be shown and
Ctrl+C stops the run (keeping the best key so far) between chunks."""
import ctypes
import itertools
import random

import native
from native.fast import _scores_pointer

PLAYFAIR, FOURSQUARE, FRACTION = 0, 1, 2
MAXSYM = 36
CHUNK = 100_000

_i32, _i64, _f64, _u8 = ctypes.c_int32, ctypes.c_int64, ctypes.c_double, ctypes.c_uint8
_P8, _P32, _PF = ctypes.POINTER(_u8), ctypes.POINTER(_i32), ctypes.POINTER(_f64)
_p, _v = ctypes.c_char_p, ctypes.c_void_p


class Cipher(ctypes.Structure):
    _fields_ = [("kind", _i32), ("n", _i32), ("cipher", _p), ("period", _i32), ("dims", _i32), ("side", _i32),
                ("nsym", _i32), ("to_az", _p), ("scores", _v), ("size", _i32), ("weight", _f64)]


class State(ctypes.Structure):
    _fields_ = [("current", (_u8 * MAXSYM) * 2), ("best", (_u8 * MAXSYM) * 2), ("current_score", _f64),
                ("best_score", _f64), ("temp", _f64), ("ratio", _f64), ("step", _i64), ("iterations", _i64),
                ("rng", ctypes.c_uint64 * 4), ("started", _i32)]


def _fn(name, restype, argtypes):
    return native.function(name, restype, argtypes)


def make_cipher(kind, symbols, nsym, to_az, ngram_model, weight=0.5, period=0, dims=0, side=0):
    """A Cipher struct plus the objects it points to (keep them alive together)."""
    symbols = bytes(symbols)
    to_az = bytes(to_az) + bytes(max(0, 256 - len(to_az)))
    cipher = Cipher(kind, len(symbols), symbols, period, dims, side, nsym, to_az,
                    _scores_pointer(ngram_model.scores), ngram_model.size, weight)
    cipher._keep = (symbols, to_az)
    return cipher


def anneal(cipher, start_keys, iterations, t_start, t_end=0.1, seed=None, polish_rounds=10, report=None,
           chunk=CHUNK):
    """One whole annealing run in C, then the swap polish.
    ``start_keys``: one or two lists (cell -> symbol). ``seed``: 64-bit seed for
    the C generator (None = random.getrandbits(64)).
    ``report(step, temperature, best_score, best_keys)`` is called after every chunk.
    Returns (final fitness, list of best keys)."""
    native.require()
    init = _fn("cct_dg_init", None, [ctypes.POINTER(State), ctypes.c_uint64, _i64, _f64, _f64])
    step = _fn("cct_dg_anneal", _i64, [ctypes.POINTER(Cipher), _i64, ctypes.POINTER(State)])
    polish = _fn("cct_dg_polish", _f64, [ctypes.POINTER(Cipher), _i32, ctypes.POINTER(State)])
    state = State()
    init(ctypes.byref(state), random.getrandbits(64) if seed is None else seed, max(1, int(iterations)),
         t_start, t_end)
    for k, key in enumerate(start_keys):
        for cell, symbol in enumerate(key):
            state.current[k][cell] = symbol
    nsym, nkeys = cipher.nsym, len(start_keys)

    def best_keys():
        return [list(state.best[k][:nsym]) for k in range(nkeys)]
    try:
        while True:
            done = step(ctypes.byref(cipher), chunk, ctypes.byref(state))
            if done < 0:
                raise MemoryError("the C annealer could not allocate its buffers")
            if report is not None and done:
                report(state.step, state.temp, state.best_score, best_keys())
            if done < chunk:
                break
    except KeyboardInterrupt:
        print("\nPass interrupted; keeping the best result so far.")
        if not state.started:
            for k in range(nkeys):
                state.best[k][:] = state.current[k][:]
    final = polish(ctypes.byref(cipher), polish_rounds, ctypes.byref(state))
    return final, best_keys()


def score(cipher, keys):
    """(fitness, plaintext symbols) of one key set (one-shot, C)."""
    native.require()
    fn = _fn("cct_dg_score", _f64, [ctypes.POINTER(Cipher), _p, _p, _p])
    out = ctypes.create_string_buffer(max(1, cipher.n))
    second = bytes(keys[1]) if len(keys) > 1 else None
    value = fn(ctypes.byref(cipher), bytes(keys[0]), second, out)
    return value, out.raw[:cipher.n]


def playfair_keywords(cipher, dim, to_az, words, ngram_model, cribs=(), weight=0.5):
    """Score the keyword square of every word (a list of bytes of symbol indices).
    ``cribs``: symbol-index sequences that must all occur (255 = impossible).
    Returns (fitness list, IoC list, crib-hit list)."""
    native.require()
    fn = _fn("cct_playfair_keywords", None,
             [_p, _i32, _i32, _p, _p, _P32, _i32, _v, _i32, _f64, _p, _P32, _i32, _PF, _PF, _P8])
    cipher = bytes(cipher)
    to_az = bytes(to_az) + bytes(max(0, 256 - len(to_az)))
    flat = b"".join(words)
    offsets = list(itertools.accumulate(map(len, words), initial=0))
    crib_flat = b"".join(bytes(c) for c in cribs)
    crib_offsets = [0]
    for c in cribs:
        crib_offsets.append(crib_offsets[-1] + len(c))
    m = len(words)
    fitness, ioc, hits = (_f64 * max(1, m))(), (_f64 * max(1, m))(), (_u8 * max(1, m))()
    fn(cipher, len(cipher), dim, to_az, flat or b"\0", native.i32(offsets), m, _scores_pointer(ngram_model.scores),
       ngram_model.size, weight, crib_flat or b"\0", native.i32(crib_offsets), len(cribs), fitness, ioc, hits)
    return list(fitness[:m]), list(ioc[:m]), list(hits[:m])


def hill_best_rows(cipher, size, expected_pct, keep):
    """Stage 1 of the Hill row attack: (rows scored, [(chi, row tuple)] best first)."""
    native.require()
    fn = _fn("cct_hill_best_rows", _i64, [_p, _i32, _i32, _PF, _i32, _P8, _PF, _P32])
    cipher = bytes(cipher)
    rows, chis, kept = (_u8 * (keep * size))(), (_f64 * keep)(), _i32(0)
    scored = fn(cipher, len(cipher), size, (_f64 * 26)(*expected_pct), keep, rows, chis, ctypes.byref(kept))
    return scored, [(chis[i], tuple(rows[i * size:(i + 1) * size])) for i in range(kept.value)]


def hill_combine(cipher, size, rows, ngram_model, top, weight=0.5):
    """Stage 2: [(fitness, combination of row indices)] best first."""
    native.require()
    fn = _fn("cct_hill_combine", _i32, [_p, _i32, _i32, _p, _i32, _v, _i32, _f64, _i32, _P32, _PF])
    cipher = bytes(cipher)
    flat = bytes(value for row in rows for value in row)
    combos, fits = (_i32 * (top * size))(), (_f64 * top)()
    found = fn(cipher, len(cipher), size, flat or b"\0", len(rows), _scores_pointer(ngram_model.scores),
               ngram_model.size, weight, top, combos, fits)
    return [(fits[i], tuple(combos[i * size:(i + 1) * size])) for i in range(found)]
