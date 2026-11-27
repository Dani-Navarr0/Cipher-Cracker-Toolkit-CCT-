"""Python wrappers for layered_engine.c (the multi-layer annealer behind
layered.LayeredSolver) and layered_columnar.c (tool 45's column-order
searches). Every function raises native.NativeUnavailable when the C library
is not built."""
import ctypes

import native
from native import fast

_i32, _i64, _f64, _u64 = ctypes.c_int32, ctypes.c_int64, ctypes.c_double, ctypes.c_uint64
_P8, _P32, _P64, _PF = (ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(_i32), ctypes.POINTER(_i64),
                        ctypes.POINTER(_f64))
_H = ctypes.c_void_p
_LP = ctypes.POINTER(native.Layout)
MAXW = 64          # transposition width limit of the C engines
MAXP = 128         # periodic period limit
MAXLAYERS = 4
KINDS = {"sub": 0, "trans": 1, "periodic": 2}
VARIANTS = {"vigenere": 0, "beaufort": 1, "variant": 2}

_SIGNATURES = {
    "cct_layered_new": (_H, [ctypes.c_char_p, _i32, _i32, _P32, _P32, _P32, _LP, _PF, _H, _i32, _f64, _f64, _u64]),
    "cct_layered_free": (None, [_H]),
    "cct_layered_get_key": (_i32, [_H, _i32, _i32, _P8]),
    "cct_layered_set_key": (_f64, [_H, _i32, ctypes.c_char_p]),
    "cct_layered_randomize": (_f64, [_H]),
    "cct_layered_plaintext": (None, [_H, _P8]),
    "cct_layered_score": (_f64, [_H]),
    "cct_layered_propose": (_f64, [_H]),
    "cct_layered_undo": (None, [_H]),
    "cct_layered_schedule": (None, [_H, _i64, _f64, _f64]),
    "cct_layered_anneal": (_i64, [_H, _i64]),
    "cct_layered_status": (_i64, [_H, _PF]),
    "cct_layered_restore_best": (_f64, [_H]),
    "cct_layered_polish": (_f64, [_H, _i32]),
    "cct_columnar_topk": (_i64, [_LP, _H, _i32, _i32, _P8, _i64, _i32, _P64, _P8, _P32, ctypes.c_char_p, _P32,
                                 _i32, _P8, _P64, _i32, _P64, _P32]),
    "cct_columnar_score_orders": (None, [_LP, _H, _i32, ctypes.c_char_p, _i64, ctypes.c_char_p, _P32, _i32, _P64,
                                         _P8]),
    "cct_double_columnar": (_i64, [_LP, _LP, _H, _i32, _P8, _i64, _i64, _P64, _P64, _P64, _P8, _P8, _P32]),
}


def _c(name):
    restype, argtypes = _SIGNATURES[name]
    return native.function(name, restype, argtypes)


class Stack:
    """A C layer stack (layered_engine.c). ``layers``: list of (kind, param,
    variant, mode) in DECRYPTION order; kind 'sub' / 'trans' / 'periodic',
    param = width or period, variant = periodic variant name, mode =
    transposition layout. The n-gram table is used in place (not copied)."""

    def __init__(self, cipher, layers, weights, ngram_scores, ngram_size, entropy_weight, fixed_factor, seed):
        native.require()
        cipher = bytes(cipher)
        n = len(cipher)
        if not 1 <= len(layers) <= MAXLAYERS:
            raise ValueError(f"The C engine takes 1-{MAXLAYERS} layers.")
        if any(code > 25 for code in cipher):
            raise ValueError("The ciphertext must be letter codes 0-25.")
        kinds, params, variants = [], [], []
        layouts = (native.Layout * len(layers))()
        self._keep = []
        for index, (kind, param, variant, mode) in enumerate(layers):
            kinds.append(KINDS[kind])
            variants.append(VARIANTS.get(variant, 0))
            if kind == "trans":
                if not 2 <= param <= min(MAXW, n):
                    raise ValueError(f"Transposition width {param} is outside 2-{min(MAXW, n)}.")
                layout, keep = native.layout_struct(cipher, param, mode)
                layouts[index] = layout
                self._keep.append(keep)
            elif kind == "periodic" and not 1 <= param <= MAXP:
                raise ValueError(f"Period {param} is outside 1-{MAXP}.")
            params.append(param if kind != "sub" else 26)
        self.lengths = params
        self._scores = ngram_scores                         # kept alive: C holds a pointer
        self._handle = _c("cct_layered_new")(
            cipher, n, len(layers), native.i32(kinds), native.i32(params), native.i32(variants), layouts,
            (_f64 * len(layers))(*weights), fast._scores_pointer(ngram_scores), ngram_size, entropy_weight,
            -1.0 if fixed_factor is None else float(fixed_factor), seed & 0xFFFFFFFFFFFFFFFF)
        if not self._handle:
            raise ValueError("The C engine rejected the layer stack.")
        self.n = n
        self._free = _c("cct_layered_free")

    def __del__(self):
        handle, self._handle = getattr(self, "_handle", None), None
        if handle:
            self._free(handle)

    def get_key(self, layer, best=False):
        out = (ctypes.c_uint8 * 128)()
        length = _c("cct_layered_get_key")(self._handle, layer, int(best), out)
        return list(out[:length])

    def set_key(self, layer, key):
        if len(key) != self.lengths[layer]:
            raise ValueError(f"Layer {layer} needs a key of length {self.lengths[layer]}.")
        return _c("cct_layered_set_key")(self._handle, layer, bytes(key))

    def randomize(self):
        return _c("cct_layered_randomize")(self._handle)

    def plaintext(self):
        out = (ctypes.c_uint8 * self.n)()
        _c("cct_layered_plaintext")(self._handle, out)
        return bytes(out)

    def score(self):
        return _c("cct_layered_score")(self._handle)

    def propose(self):
        return _c("cct_layered_propose")(self._handle)

    def undo(self):
        _c("cct_layered_undo")(self._handle)

    def schedule(self, iterations, t_start, t_end):
        _c("cct_layered_schedule")(self._handle, int(iterations), float(t_start), float(t_end))

    def anneal(self, max_steps):
        """Runs up to max_steps of the scheduled run; returns the steps run."""
        return _c("cct_layered_anneal")(self._handle, int(max_steps))

    def status(self):
        """(step, current fitness, best fitness, temperature)"""
        out = (_f64 * 3)()
        step = _c("cct_layered_status")(self._handle, out)
        return step, out[0], out[1], out[2]

    def restore_best(self):
        return _c("cct_layered_restore_best")(self._handle)

    def polish(self, max_rounds=20):
        return _c("cct_layered_polish")(self._handle, int(max_rounds))


# ---------------------------------------------------------------- tool 45 searches

def _words(required_codes):
    """(packed codes, lengths array, count) for the required-word check."""
    words = [bytes(word) for word in required_codes if word]
    return b"".join(words) or b"\0", native.i32([len(word) for word in words] or [0]), len(words)


class TopK:
    """Resumable top-k column-order search over every order after a fixed
    prefix (cct_columnar_topk). Call step() until it returns False."""

    def __init__(self, codes, width, mode, ngram_model, k, prefix=(), required_codes=(), max_matches=10_000):
        native.require()
        codes = bytes(codes)
        if not 2 <= width <= min(MAXW, len(codes)):
            raise ValueError(f"Width {width} is outside 2-{min(MAXW, len(codes))}.")
        self.width, self.k, self.max_matches = width, k, max_matches
        self.layout, self._keep = native.layout_struct(codes, width, mode)
        self._scores = ngram_model.scores
        self._pointer = fast._scores_pointer(self._scores)
        self.size = ngram_model.size
        rest = [column for column in range(width) if column not in prefix]
        self.prefix_len = len(prefix)
        self.key = (ctypes.c_uint8 * MAXW)(*(list(prefix) + rest))
        self.totals = (_i64 * max(1, k))()
        self.keys = (ctypes.c_uint8 * (MAXW * max(1, k)))()
        self.nkept = _i32(0)
        self.words, self.word_lengths, self.nwords = _words(required_codes)
        self.match_keys = (ctypes.c_uint8 * (MAXW * max(1, max_matches)))()
        self.match_totals = (_i64 * max(1, max_matches))()
        self.nmatch = _i64(0)
        self.done = False
        self.processed = 0

    def step(self, max_orders=1_000_000):
        if self.done:
            return False
        done = _i32(0)
        self.processed += _c("cct_columnar_topk")(
            ctypes.byref(self.layout), self._pointer, self.size, self.prefix_len, self.key, int(max_orders), self.k,
            self.totals, self.keys, ctypes.byref(self.nkept), self.words, self.word_lengths, self.nwords,
            self.match_keys, self.match_totals, self.max_matches, ctypes.byref(self.nmatch), ctypes.byref(done))
        self.done = bool(done.value)
        return not self.done

    def best(self):
        """[(total, order)] best first (ties: the earlier order)."""
        w = self.width
        found = [(self.totals[i], list(self.keys[i * MAXW:i * MAXW + w])) for i in range(self.nkept.value)]
        return sorted(found, key=lambda item: (-item[0], item[1]))

    def matches(self):
        """[(total, order)] for the orders containing every required word (up to max_matches)."""
        w = self.width
        count = min(self.nmatch.value, self.max_matches)
        return [(self.match_totals[i], list(self.match_keys[i * MAXW:i * MAXW + w])) for i in range(count)]


def score_orders(codes, width, mode, ngram_model, orders, required_codes=()):
    """(totals, matches) for a list of column orders of one width: the n-gram
    total of each decryption and whether it contains every required word."""
    native.require()
    codes = bytes(codes)
    if not 2 <= width <= min(MAXW, len(codes)):
        raise ValueError(f"Width {width} is outside 2-{min(MAXW, len(codes))}.")
    layout, keep = native.layout_struct(codes, width, mode)
    packed = b"".join(bytes(order) for order in orders) or b"\0"
    count = len(orders)
    totals = (_i64 * max(1, count))()
    matched = (ctypes.c_uint8 * max(1, count))()
    words, lengths, nwords = _words(required_codes)
    _c("cct_columnar_score_orders")(ctypes.byref(layout), fast._scores_pointer(ngram_model.scores), ngram_model.size,
                                    packed, count, words, lengths, nwords, totals, matched)
    return list(totals[:count]), [bool(value) for value in matched[:count]]


def unrank_permutation(index, width):
    """The index-th permutation of 0..width-1 in lexicographic order."""
    import math
    items, out = list(range(width)), []
    for position in range(width, 0, -1):
        block = math.factorial(position - 1)
        out.append(items.pop(index // block))
        index %= block
    return out


class DoubleColumnar:
    """Double columnar search (cct_double_columnar) over the key2 strings with
    indices [first, last): resumable; call step() until it returns False."""

    def __init__(self, codes, width1, width2, ngram_model, first, last, mode="write_rows_read_cols"):
        native.require()
        codes = bytes(codes)
        for width in (width1, width2):
            if not 2 <= width <= min(MAXW, len(codes)):
                raise ValueError(f"Width {width} is outside 2-{min(MAXW, len(codes))}.")
        self.width1, self.width2 = width1, width2
        self.outer, keep_outer = native.layout_struct(codes, width2, mode)
        self.inner, keep_inner = native.layout_struct(codes, width1, mode)
        self._keep = (keep_outer, keep_inner)
        self._scores = ngram_model.scores
        self._pointer = fast._scores_pointer(self._scores)
        self.size = ngram_model.size
        self.key2 = (ctypes.c_uint8 * MAXW)(*unrank_permutation(first, width2))
        self.first, self.next_index, self.last = first, first, last
        self.best_total, self.best_i, self.best_j = _i64(-1), _i64(0), _i64(0)
        self.best_key1 = (ctypes.c_uint8 * MAXW)()
        self.best_key2 = (ctypes.c_uint8 * MAXW)()
        self.done = first >= last

    @property
    def processed(self):
        """key2 strings done so far"""
        return self.next_index - self.first

    def step(self, max_outer=8):
        if self.done:
            return False
        count = min(int(max_outer), self.last - self.next_index)
        done = _i32(0)
        ran = _c("cct_double_columnar")(
            ctypes.byref(self.outer), ctypes.byref(self.inner), self._pointer, self.size, self.key2, self.next_index,
            count, ctypes.byref(self.best_total), ctypes.byref(self.best_i), ctypes.byref(self.best_j),
            self.best_key1, self.best_key2, ctypes.byref(done))
        self.next_index += ran
        self.done = bool(done.value) or self.next_index >= self.last
        return not self.done

    def best(self):
        """(total, key1 index, key2 index, key1 digits, key2 digits) or None."""
        if self.best_total.value < 0:
            return None
        return (self.best_total.value, self.best_i.value, self.best_j.value,
                list(self.best_key1[:self.width1]), list(self.best_key2[:self.width2]))
