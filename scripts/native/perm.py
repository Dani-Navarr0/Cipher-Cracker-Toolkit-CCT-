"""Native column-order search for the transposition solvers.

* best_order: exhaustive search (permutation_solver brute force). Returns the
  first column order, in lexicographic order, with the highest n-gram total,
  which is exactly the order the Python loop keeps (a transposition only
  reorders letters, so the entropy factor is the same for every order and the
  fitness ranks orders by their n-gram total). On the GPU when enabled.
* anneal: the solvers' simulated annealing (same moves, schedule, acceptance
  rule, progress output), with the C engine's own random number generator
  seeded from Python's `random`.
Both return None when the native engine cannot be used, and the caller then
runs its Python code.
"""
import ctypes
import random

from ngram_scoring import text_to_codes

import native


def _usable(codes, width, ngram_model):
    return (native.available() and 2 <= width <= native.MAXW and len(codes) >= ngram_model.size
            and len(codes) >= width)


def best_order(ciphertext, width, mode, ngram_model):
    """The column order the Python brute force would keep, or None."""
    codes = text_to_codes(ciphertext)
    if not _usable(codes, width, ngram_model):
        return None
    from native import gpu
    if gpu.enabled() and width >= gpu.MIN_WIDTH:
        return gpu.best_order(codes, width, mode, ngram_model)
    lib = native.library()
    layout, keep = native.layout_struct(codes, width, mode)
    scores = native.u8(ngram_model.scores)
    key = native.u8(list(range(width)))
    best_key = (ctypes.c_uint8 * width)()
    best_total, done = ctypes.c_int64(-1), ctypes.c_int32(0)
    while not done.value:
        lib.cct_perm_bruteforce(ctypes.byref(layout), scores, ngram_model.size, 0, key, 1 << 62,
                                ctypes.byref(best_total), best_key, ctypes.byref(done))
    return list(best_key)


def order_total(codes, width, mode, ngram_model, order):
    lib = native.library()
    layout, keep = native.layout_struct(codes, width, mode)
    return lib.cct_order_total(ctypes.byref(layout), native.u8(list(order)), native.u8(ngram_model.scores),
                               ngram_model.size)


def anneal(ciphertext, width, mode, ngram_model, factor, start_perm, starting_temp, cooling_rate, steps_per_temp,
           moves, progress=None):
    """Simulated annealing over column orders; returns (best order, best score) or None.
    ``factor`` is the solver's entropy factor; moves 0 = swap only, 1 = swap/reverse.
    ``progress(best order, best score, temperature)`` is called every 10 levels."""
    codes = text_to_codes(ciphertext)
    count = len(codes) - ngram_model.size + 1
    if not _usable(codes, width, ngram_model) or count <= 0:
        return None
    lib = native.library()
    layout, keep = native.layout_struct(codes, width, mode)
    scores = native.u8(ngram_model.scores)
    state = native.AnnealState()
    for i, column in enumerate(start_perm):
        state.current[i] = state.best[i] = column
    total = lib.cct_order_total(ctypes.byref(layout), native.u8(list(start_perm)), scores, ngram_model.size)
    state.current_score = state.best_score = (total / count) * factor
    state.temp = starting_temp
    for i in range(4):
        state.rng[i] = random.getrandbits(64) or 1
    while state.temp > 0.1:
        ran = lib.cct_perm_anneal(ctypes.byref(layout), scores, ngram_model.size, float(count), factor, moves,
                                  steps_per_temp, cooling_rate, 10, ctypes.byref(state))
        if progress is not None:
            progress(list(state.best[:width]), state.best_score, state.temp)
        if ran == 0:
            break
    return list(state.best[:width]), state.best_score
