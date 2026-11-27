"""Python side of the periodic-key C engines (periodic_engine.c, periodic_dict.c).

* anneal: one restart of the periodic-key annealer (solve_periodic), run in
  chunks so progress can be shown and Ctrl+C keeps the best key so far.
* TextContext: a ciphertext prepared for the dictionary and exhaustive key
  searches (which characters the key decrypts, which pass through unchanged,
  how the plaintext is scored, counted and searched for phrases).
* dictionary_batch, exhaustive: attack_support.run_batches and the Gronsfeld
  exhaustive search.
* xor_dict, modular_dict: the XOR and modular-arithmetic word-list attacks.

Every function raises native.NativeUnavailable (with build instructions) when
the C library is not built.
"""
import array
import ctypes
import itertools
import time

from ngram_scoring import text_to_codes

import native
from native.fast import _scores_pointer

_i32, _i64, _u8, _f64, _u64 = ctypes.c_int32, ctypes.c_int64, ctypes.c_uint8, ctypes.c_double, ctypes.c_uint64
_P8, _P32, _P64, _PF = (ctypes.POINTER(_u8), ctypes.POINTER(_i32), ctypes.POINTER(_i64), ctypes.POINTER(_f64))
_VP = ctypes.c_void_p


class Problem(ctypes.Structure):
    _fields_ = [("sym", _P8), ("n", _i32), ("period", _i32), ("tables", _P8), ("nsym", _i32), ("scores", _VP),
                ("size", _i32), ("weight", _f64), ("mode", _i32), ("min_ioc", _f64), ("max_ioc", _f64),
                ("m", _i32), ("slot", _P32), ("nslots", _i32), ("max_codes", _i32), ("code_offsets", _P32),
                ("codes", _P8)]


class AnnealState(ctypes.Structure):
    _fields_ = [("current", _f64), ("best", _f64), ("temp", _f64), ("ratio", _f64), ("step", _i64),
                ("iterations", _i64), ("rng", _u64 * 4)]


class Text(ctypes.Structure):
    _fields_ = [("sym", _P8), ("nsym", _i32), ("table", _P8), ("rows", _i32), ("m", _i32),
                ("code_offsets", _P32), ("codes", _P8), ("single", _i32), ("bucket_offsets", _P32),
                ("buckets", _P32), ("nbuckets", _i32), ("fixed_buckets", _P32), ("slot", _P32), ("nslots", _i32),
                ("max_codes", _i32), ("stream", _P32), ("nstream", _i32), ("max_render", _i32),
                ("render_offsets", _P32), ("render", _P32), ("render_single", _i32), ("phrases", _P32), ("phrase_offsets", _P32),
                ("nphrases", _i32), ("phrase_all", _i32), ("scores", _VP), ("size", _i32)]


class Selection(ctypes.Structure):
    _fields_ = [("min_ioc", _f64), ("max_ioc", _f64), ("top_k", _i32), ("outside_needs_text", _i32),
                ("win_index", _P32), ("win_cost", _PF), ("win_ioc", _PF), ("n_win", _i32),
                ("top_index", _P32), ("top_cost", _PF), ("top_ioc", _PF), ("n_top", _i32)]


class ModularSpec(ctypes.Structure):
    _fields_ = [("modulus", _i32), ("subtract", _i32), ("keymap", _P32), ("code_offsets", _P32), ("codes", _P8),
                ("bucket_offsets", _P32), ("buckets", _P32), ("nbuckets", _i32), ("blank", _P8),
                ("identity_valid", _i32), ("identity_blank", _i32), ("identity_cost", _f64),
                ("identity_ioc", _f64)]


def _bytes(values):
    return native.u8(values)


def _i32s(values):
    return native.i32(list(values))


# ------------------------------------------------------------------ annealer

def _start():
    return native.function("cct_periodic_start", _i32, [ctypes.POINTER(Problem), _u64, _i64, _f64, _f64,
                                                         ctypes.POINTER(AnnealState), _P8, _P8])


def _anneal():
    return native.function("cct_periodic_anneal", _i64, [ctypes.POINTER(Problem), _i64, ctypes.POINTER(AnnealState),
                                                          _P8, _P8])


def _polish():
    return native.function("cct_periodic_polish", _f64, [ctypes.POINTER(Problem), _i32, _P8, _P8, _P32])


def _score():
    return native.function("cct_periodic_score", _f64, [ctypes.POINTER(Problem), _P8])


def problem(symbols, period, tables, nsym, ngram_model, weight=0.5, mode=1, ioc_range=(0.060, 0.070), m=26,
            layout=None, symbol_codes=None):
    """(Problem, keep-alive) for cipher symbols (alphabet indices 0..m-1), a key
    period and nsym x m tables, one row per key symbol.

    Simple form (layout None): every cipher symbol is one scored letter and the
    tables give its plaintext letter code (0-25).
    General form: the tables give the plaintext symbol (0..m-1);
    ``symbol_codes[p]`` = the A-Z codes (bytes) plaintext symbol p adds to the
    scored text, and ``layout`` lists the scored text in order: an int >= 0 is
    a position in ``symbols`` (its plaintext symbol's codes), an int < 0 a
    letter that is not decrypted, -(code + 1)."""
    if not 1 <= m <= 256:
        raise ValueError("the periodic annealer takes alphabets of 1 to 256 symbols")
    tables, limit = bytes(tables), (26 if layout is None else m)
    if len(tables) != nsym * m or (tables and max(tables) >= limit) or any(not 0 <= s < m for s in symbols):
        raise ValueError("tables or cipher symbols outside the alphabet")
    keep = [_bytes(bytes(symbols)), _bytes(bytes(tables))]
    mode = {"2": 2, "3": 3}.get(str(mode), 1)
    slot, nslots, max_codes, code_offsets, codes = None, 0, 0, None, None
    if layout is not None:
        offsets, flat = [0], bytearray()
        for symbol_code in symbol_codes:
            flat += symbol_code
            offsets.append(len(flat))
        longest = max(map(len, symbol_codes), default=0)
        max_codes = sum(1 if item < 0 else longest for item in layout)
        keep += [_i32s(layout), _i32s(offsets), _bytes(bytes(flat))]
        slot, nslots, code_offsets, codes = keep[2], len(layout), keep[3], keep[4]
    built = Problem(keep[0], len(symbols), period, keep[1], nsym, _scores_pointer(ngram_model.scores),
                    ngram_model.size, float(weight), mode, float(ioc_range[0]), float(ioc_range[1]), m, slot, nslots,
                    max_codes, code_offsets, codes)
    return built, keep


def score_key(built, key):
    """The annealer's score of one key (list of symbol indices)."""
    native.require()
    return _score()(ctypes.byref(built), _bytes(bytes(key)))


def anneal(built, iterations, t_start, t_end, seed, report=None, report_seconds=0.5, polish_rounds=50):
    """One restart: random key, annealing, hill-climb polish.
    Returns (key as a list of symbol indices, score, scored plaintext letter codes).
    ``report(step, temperature, best score, best key tuple)`` is called at most
    every report_seconds. Ctrl+C stops the annealing early (the polish still
    runs)."""
    native.require()
    period = built.period
    key, best_key = (_u8 * period)(), (_u8 * period)()
    state = AnnealState()
    if not _start()(ctypes.byref(built), seed & (2 ** 64 - 1), int(iterations), float(t_start), float(t_end),
                    ctypes.byref(state), key, best_key):
        raise ValueError("the periodic annealer needs at least one cipher symbol, key symbol and key column")
    chunk = max(2_000, min(200_000, 30_000_000 // max(1, built.n)))
    run = _anneal()
    next_report = time.time() + report_seconds
    try:
        while state.step < state.iterations:
            if run(ctypes.byref(built), chunk, ctypes.byref(state), key, best_key) <= 0:
                break
            if report is not None and time.time() >= next_report:
                report(state.step, state.temp, state.best, tuple(best_key))
                next_report = time.time() + report_seconds
    except KeyboardInterrupt:
        print("\nPass interrupted; keeping the best result so far.")
    plain = (_u8 * max(1, built.n if not built.slot else built.max_codes))()
    length = _i32()
    polished = (_u8 * period)(*best_key)
    score = _polish()(ctypes.byref(built), polish_rounds, polished, plain, ctypes.byref(length))
    return list(polished), score, bytes(plain[:length.value])


# ------------------------------------------------------------------ prepared ciphertexts

def _dict_fn():
    return native.function("cct_periodic_dict", _i32, [ctypes.POINTER(Text), _P8, _P64, _i32, _i32, _f64, _f64, _i32,
                                                        _P32, _PF, _PF, _P8])


def _exhaustive_fn():
    return native.function("cct_periodic_exhaustive", _i32, [ctypes.POINTER(Text), _i32, _i32, _i64, _i64, _i32,
                                                              _P64, _PF, _PF, _P64, _P64, _PF, _PF])


class TextContext:
    """A ciphertext prepared for the C key searches, for an alphabet of m
    symbols (1-256, any characters).

    ``pieces``: the ciphertext in order, each item either an int (a symbol the
    key decrypts: its alphabet index; the key advances) or a str (the text that
    character becomes in the plaintext, unchanged by the key).
    ``table``: rows x m bytes, plaintext symbol for (key row, cipher symbol).
    ``symbol_texts``: m strings, the text each plaintext symbol becomes (the
    decrypt functions' alphabet[p].lower()).
    Scoring mirrors the Python tools on the rendered plaintext: score_text (A-Z
    letters after upper(), cost 255 - mean, +inf below the n-gram size) and
    utils.calculate_ioc (every alphabetic character after upper()).
    Phrases: searched in ``phrase_view(plaintext)`` (applied piece by piece,
    so it must work character by character, as upper() and removing spaces
    do). ``phrase_all``: every phrase must occur (True) or any one (False).
    """

    def __init__(self, pieces, table, rows, symbol_texts, ngram_model, phrases=(), phrase_all=True,
                 phrase_view=lambda text: text):
        m = len(symbol_texts)
        if not 1 <= m <= 256:
            raise ValueError("the C key searches take alphabets of 1 to 256 symbols")
        table = bytes(table)
        if len(table) != rows * m or (table and max(table) >= m) or                 any(isinstance(piece, int) and not 0 <= piece < m for piece in pieces):
            raise ValueError("table or cipher symbols outside the alphabet")
        bucket_ids = {chr(65 + i): i for i in range(26)}

        def bucket_list(text):
            return [bucket_ids.setdefault(char, len(bucket_ids)) for char in text.upper() if char.isalpha()]

        symbol_codes = [text_to_codes(text) for text in symbol_texts]
        symbol_buckets = [bucket_list(text) for text in symbol_texts]
        symbol_render = [[ord(char) for char in phrase_view(text)] for text in symbol_texts]
        single = all(len(codes) == 1 for codes in symbol_codes)
        longest_codes = max(map(len, symbol_codes))
        longest_render = max(map(len, symbol_render))
        symbols, slots, stream, fixed = [], [], [], []
        max_codes = max_render = 0
        for piece in pieces:
            if isinstance(piece, int):
                slots.append(len(symbols))
                stream.append(-(len(symbols) + 1))
                symbols.append(piece)
                max_codes += longest_codes
                max_render += longest_render
            else:
                codes = text_to_codes(piece)
                slots.extend(-(code + 1) for code in codes)
                view = phrase_view(piece)
                stream.extend(ord(char) for char in view)
                fixed.extend(bucket_list(piece))
                max_codes += len(codes)
                max_render += len(view)
        fixed_buckets = [0] * len(bucket_ids)
        for bucket in fixed:
            fixed_buckets[bucket] += 1

        def flatten(lists):
            offsets, flat = [0], []
            for values in lists:
                flat.extend(values)
                offsets.append(len(flat))
            return offsets, flat

        code_offsets, codes = flatten(symbol_codes)
        bucket_offsets, buckets = flatten(symbol_buckets)
        render_offsets, render = flatten(symbol_render)
        phrase_offsets, flat_phrases = flatten([ord(char) for char in phrase] for phrase in phrases)
        self.symbols = bytes(symbols)
        self.keep = [_bytes(self.symbols), _bytes(bytes(table)), _i32s(code_offsets), _bytes(bytes(codes)),
                     _i32s(bucket_offsets), _i32s(buckets), _i32s(fixed_buckets), _i32s(slots), _i32s(stream),
                     _i32s(render_offsets), _i32s(render), _i32s(flat_phrases), _i32s(phrase_offsets)]
        k = self.keep
        self.text = Text(k[0], len(symbols), k[1], rows, m, k[2], k[3], int(single), k[4], k[5], len(bucket_ids),
                         k[6], k[7], len(slots), max_codes, k[8], len(stream), max_render, k[9], k[10],
                         int(all(len(r) == 1 for r in symbol_render)), k[11], k[12],
                         len(phrase_offsets) - 1, int(phrase_all), _scores_pointer(ngram_model.scores),
                         ngram_model.size)


class KeyList:
    """Word keys flattened for C: each word a run of bytes (key rows, or the
    key characters for xor/modular). Build with KeyList(list of bytes) or
    KeyList.joined(all bytes concatenated, the length of each key)."""

    def __init__(self, keys=None):
        if keys is not None:
            self._set(b"".join(keys), map(len, keys), len(keys))

    @classmethod
    def joined(cls, flat, lengths):
        built = cls()
        lengths = list(lengths)
        built._set(bytes(flat), lengths, len(lengths))
        return built

    def _set(self, flat, lengths, count):
        offsets = array.array("q", [0])
        offsets.extend(itertools.accumulate(lengths))
        self.count = count
        self.flat = flat
        self.buffer = _bytes(flat)
        self._offsets = offsets
        self.offsets = (_i64 * len(offsets)).from_buffer(offsets)

    def key(self, index):
        return self.flat[self._offsets[index]:self._offsets[index + 1]]


def dictionary_batch(context, keys, first, count, min_ioc, max_ioc, top_k):
    """attack_support's batch rule on words first..first+count-1: rows matching
    the phrases or inside the IoC window (word order), then the top_k others by
    cost. Returns [(word index, cost, ioc, phrase match)]."""
    native.require()
    index, cost, ioc = (_i32 * max(1, count + top_k))(), (_f64 * max(1, count + top_k))(), (_f64 * max(1, count + top_k))()
    phrase = (_u8 * max(1, count + top_k))()
    rows = _dict_fn()(ctypes.byref(context.text), keys.buffer, keys.offsets, first, count, float(min_ioc),
                      float(max_ioc), top_k, index, cost, ioc, phrase)
    if rows < 0:
        raise MemoryError("cct_periodic_dict could not allocate its buffers")
    return [(index[i], cost[i], ioc[i], bool(phrase[i])) for i in range(rows)]


def exhaustive(context, period, base, first, count, top_k):
    """Every key number first..first+count-1 as `period` base-`base` digits.
    Returns (phrase matches, best top_k others), each [(number, cost, ioc)]."""
    native.require()
    capacity = max(1, count) if context.text.nphrases else 1     # every key can match only when words are given
    match_number, match_cost, match_ioc = (_i64 * capacity)(), (_f64 * capacity)(), (_f64 * capacity)()
    keep_number, keep_cost, keep_ioc = (_i64 * max(1, top_k))(), (_f64 * max(1, top_k))(), (_f64 * max(1, top_k))()
    matched = _i64()
    kept = _exhaustive_fn()(ctypes.byref(context.text), period, base, first, count, top_k, match_number, match_cost,
                            match_ioc, ctypes.byref(matched), keep_number, keep_cost, keep_ioc)
    if kept < 0:
        raise MemoryError("cct_periodic_exhaustive could not allocate its buffers")
    return ([(match_number[i], match_cost[i], match_ioc[i]) for i in range(matched.value)],
            [(keep_number[i], keep_cost[i], keep_ioc[i]) for i in range(kept)])


# ------------------------------------------------------------------ XOR and modular word lists

def _xor_fn():
    return native.function("cct_xor_dict", _i32, [_P8, _i32, _P8, _P64, _i32, _i32, _VP, _i32,
                                                   ctypes.POINTER(Selection)])


def _modular_fn():
    return native.function("cct_modular_dict", _i32, [_P32, _i32, ctypes.POINTER(ModularSpec), _P8, _P64, _i32, _i32,
                                                       _VP, _i32, ctypes.POINTER(Selection)])


def _selection(count, min_ioc, max_ioc, top_k, outside_needs_text):
    size = max(1, count)
    arrays = [(_i32 * size)(), (_f64 * size)(), (_f64 * size)(), (_i32 * max(1, top_k))(), (_f64 * max(1, top_k))(),
              (_f64 * max(1, top_k))()]
    selection = Selection(float(min_ioc), float(max_ioc), top_k, int(outside_needs_text), arrays[0], arrays[1],
                          arrays[2], 0, arrays[3], arrays[4], arrays[5], 0)
    return selection, arrays


def _selection_rows(selection):
    window = [(selection.win_index[i], selection.win_cost[i], selection.win_ioc[i]) for i in range(selection.n_win)]
    top = [(selection.top_index[i], selection.top_cost[i], selection.top_ioc[i]) for i in range(selection.n_top)]
    return window, top


def xor_dict(message, words, first, count, ngram_model, min_ioc, max_ioc, top_k):
    """message: bytes (values 0-127; 255 for anything else). words: KeyList of
    ASCII keys. Returns (window rows, top_k other non-blank rows by cost, later
    word winning ties), each [(word index, cost, ioc)]."""
    native.require()
    selection, keep = _selection(count, min_ioc, max_ioc, top_k, True)
    if _xor_fn()(_bytes(message), len(message), words.buffer, words.offsets, first, count,
                 _scores_pointer(ngram_model.scores), ngram_model.size, ctypes.byref(selection)) < 0:
        raise MemoryError("cct_xor_dict could not allocate its buffers")
    return _selection_rows(selection)


class ModularTables:
    """How each result value 0..modulus-1 appears in the text (its character),
    for cct_modular_dict: scored A-Z codes, IoC characters, whitespace flag."""

    def __init__(self, modulus, subtract, keymap, characters, identity=None):
        code_offsets, codes, bucket_offsets, buckets, blank = [0], [], [0], [], []
        bucket_ids = {chr(65 + i): i for i in range(26)}
        for char in characters:
            codes.extend(text_to_codes(char))
            code_offsets.append(len(codes))
            for upper in char.upper():
                if upper.isalpha():
                    buckets.append(bucket_ids.setdefault(upper, len(bucket_ids)))
            bucket_offsets.append(len(buckets))
            blank.append(int(char.isspace()))
        # identity = (cost, ioc, blank) of the unchanged message, or None if it cannot be shown
        valid = identity is not None
        cost, ioc, is_blank = identity if valid else (0.0, 0.0, 1)
        self.keep = [_i32s(keymap), _i32s(code_offsets), _bytes(bytes(codes)), _i32s(bucket_offsets), _i32s(buckets),
                     _bytes(bytes(blank))]
        self.spec = ModularSpec(modulus, int(subtract), self.keep[0], self.keep[1], self.keep[2], self.keep[3],
                                self.keep[4], len(bucket_ids), self.keep[5], int(valid), int(is_blank), float(cost),
                                float(ioc))


def modular_dict(message, tables, words, first, count, ngram_model, min_ioc, max_ioc, top_k):
    """message: values reduced modulo the modulus, -1 for a gap. Returns
    (window rows, top_k other rows by cost, later word winning ties)."""
    native.require()
    selection, keep = _selection(count, min_ioc, max_ioc, top_k, False)
    if _modular_fn()(_i32s(message), len(message), ctypes.byref(tables.spec), words.buffer, words.offsets, first,
                     count, _scores_pointer(ngram_model.scores), ngram_model.size, ctypes.byref(selection)) < 0:
        raise MemoryError("cct_modular_dict could not allocate its buffers")
    return _selection_rows(selection)
