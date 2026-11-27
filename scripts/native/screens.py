"""Python side of the transposition-screen, reference-statistics and
word-pattern kernels (screens_transposition.c, screens_stats.c,
screens_pattern.c).

``Sources`` is a list of permutation families described by a few numbers each
(a grid width, a rail count, a keyword's column order...). The C engine
generates every permutation ("source": plaintext[i] = text[src[i]]) and scores
it with annealing.Fitness; Python only describes the families, and turns the
ids of the best readings back into descriptions and plaintexts.

Iterating a ``Sources`` yields (info, src) pairs, generated in C, in the order
the original Python generators of transposition_families yielded them.
Raises native.NativeUnavailable when the C library is not built.
"""
import ctypes
from array import array

import native

_i32, _i64, _f64, _u64 = ctypes.c_int32, ctypes.c_int64, ctypes.c_double, ctypes.c_uint64
_P8, _P32, _P64, _PF = (ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(_i32), ctypes.POINTER(_i64),
                        ctypes.POINTER(_f64))
_VP = ctypes.c_void_p

REC_FIELDS = 8
EXPLICIT, ROUTE, ZIGZAG, DOUBLE_ROTATION, MYSZKOWSKI, AMSCO, COLUMNAR = range(7)
READ, WRITE = 1, 2                      # direction mask bits (0 = both)
FORWARD, REVERSED, BOTH = 1, 2, 3       # text direction mask
DIRECTIONS = ("read", "write")
# transposition_families.route_orders, in its dict order
ROUTES = ("rows_snake", "rows_right_to_left", "columns_down", "columns_up", "columns_snake",
          "columns_right_to_left_down", "columns_right_to_left_up", "diagonals", "diagonals_snake",
          "spiral_clockwise", "spiral_counterclockwise")
AMSCO_RULES = ((1, "continue"), (1, "alternate_rows"), (2, "continue"), (2, "alternate_rows"))
LAYOUTS = {"write_rows_read_cols": 0, "write_cols_read_cols": 1, "write_rows_read_rows": 2,
           "write_cols_read_rows": 3}
_ERRORS = {-2: "a source holds a position outside the text", -3: "output buffer too small",
           -4: "out of memory", -5: "a record has more sources than a source id holds"}
# Source id: (record << ID_SHIFT) | (sub << 1) | reversed (screens_transposition.c)
ID_SHIFT = 25
SUB_LIMIT = 1 << (ID_SHIFT - 1)
ROUTE_SUBS = 22                         # 11 routes x 2 directions per grid offset


def record_of(ident):
    """The record index of a source id."""
    return ident >> ID_SHIFT


def sub_of(ident):
    """The source number within its record (direction bit included)."""
    return (ident >> 1) & (SUB_LIMIT - 1)


def _fn(name, restype, argtypes):
    return native.function(name, restype, argtypes)


def _run():
    return _fn("cct_screens_run", _i64, [_P8, _i32, _P32, _i32, _i64, _P32, _i32, _VP, _i32, _f64, _f64, _i32,
                                         _PF, _P64, _P32, _i64])


def _sources():
    return _fn("cct_screens_sources", _i64, [_i32, _P32, _i32, _i64, _P32, _P32, _P64, _i64])


def _plain():
    return _fn("cct_screens_plain", _i32, [_P8, _i32, _P32, _i32, _P32, _P64, _i32, _P8])


def _max_sources():
    return _fn("cct_screens_max_sources", _i64, [_P32, _i32])


def _check(code):
    if code < 0:
        raise ValueError(f"transposition screen: {_ERRORS.get(code, f'error {code}')}")
    return code


_scores_cache = {}


def scores_pointer(scores):
    """A pointer to an n-gram table (bytes or bytearray), kept alive per table."""
    cached = _scores_cache.get(id(scores))
    if cached is not None and cached[0] is scores:
        return cached[1]
    if isinstance(scores, bytearray):
        keep = (ctypes.c_uint8 * len(scores)).from_buffer(scores)
    else:
        keep = ctypes.c_char_p(bytes(scores))
    pointer = ctypes.cast(keep, _VP)
    _scores_cache[id(scores)] = (scores, pointer, keep)
    return pointer


def _ptr32(values):
    """ctypes int32 pointer to an array('i') (no copy)."""
    if not len(values):
        values = array("i", [0])
    return (_i32 * len(values)).from_buffer(values), values


def _u8(data):
    data = bytes(data)
    return (ctypes.c_uint8 * max(1, len(data))).from_buffer_copy(data or b"\0")


def fitness_parameters(fitness, codes):
    """(scores, size, factor, weight) of an annealing.Fitness for permutations of
    ``codes``: the entropy factor is the one Fitness computes (it is the same for
    every permutation), so C scores equal fitness(plaintext) exactly."""
    from annealing import letter_entropy
    letters = bytes(c for c in codes if c < 26)
    factor = fitness.fixed_factor
    if factor is None:
        factor = letter_entropy(letters) ** fitness.entropy_weight
    return fitness.scores, fitness.size, factor, fitness.entropy_weight


def symbol_codes(text):
    """Codes of a string that may hold other symbols, for the C screen.
    Returns (codes, shown, decode):
      codes: A-Z and a-z are letter codes 0-25 (scored, case folded as
             ngram_scoring.text_to_codes does); every other character is 26
             (carried, not scored);
      shown: every distinct character its own code, so a reading taken with
             Sources.plain(shown, ids) keeps case and symbols;
      decode(bytes of shown codes) gives the string back."""
    distinct = sorted(set(text))
    if len(distinct) > 256:
        raise ValueError("too many distinct characters (at most 256)")
    index = {ch: i for i, ch in enumerate(distinct)}
    letter = {ch: (ord(ch.upper()) - 65 if ("A" <= ch <= "Z" or "a" <= ch <= "z") else 26) for ch in distinct}
    codes = bytes(letter[ch] for ch in text)
    shown = bytes(index[ch] for ch in text)
    table = {i: ord(ch) for i, ch in enumerate(distinct)}
    return codes, shown, lambda data: bytes(data).decode("latin-1").translate(table)


class Sources:
    """Permutation families for the C screen. ``meta`` per record describes it
    for info(): a tuple (kind, ...) for the families, or the info dict and the
    src list for explicit sources."""

    def __init__(self, n):
        self.n = n
        self.fields = array("i")
        self.keys = array("i")
        self.meta = []

    # ---------------------------------------------------------------- building
    def add(self, family, params=(), key=(), meta=None, directions=0):
        p = list(params) + [0] * (4 - len(params))
        if family == ROUTE:
            if p[0] < 1:
                raise ValueError(f"grid width {p[0]} must be at least 1")
            if any(offset < 0 for offset in key):
                raise ValueError("grid offsets must be 0 or more")
            if len(key) * ROUTE_SUBS > SUB_LIMIT:
                raise ValueError(f"at most {SUB_LIMIT // ROUTE_SUBS:,} grid offsets per width")
        elif family == DOUBLE_ROTATION and (p[0] < 1 or p[2] < 1):
            raise ValueError(f"grid widths {p[0]}, {p[2]} must be at least 1")
        elif family == DOUBLE_ROTATION and p[1] < 0:
            raise ValueError("grid offsets must be 0 or more")
        self.fields.extend((family, p[0], p[1], p[2], p[3], directions, len(self.keys), len(key)))
        self.keys.extend(key)
        self.meta.append(meta)

    def add_explicit(self, info, src):
        self.fields.extend((EXPLICIT, 0, 0, 0, 0, 0, len(self.keys), len(src)))
        self.keys.extend(src)
        self.meta.append((info, src))

    def extend(self, other):
        if other.n != self.n:
            raise ValueError("sources for different text lengths")
        base = len(self.keys)
        fields = array("i", other.fields)
        for i in range(6, len(fields), REC_FIELDS):
            fields[i] += base
        self.fields.extend(fields)
        self.keys.extend(other.keys)
        self.meta.extend(other.meta)
        return self

    @classmethod
    def chain(cls, n, parts):
        out = cls(n)
        for part in parts:
            out.extend(part)
        return out

    def __len__(self):
        """Number of records (each gives one or more sources)."""
        return len(self.meta)

    def block(self, start, stop):
        """Records start..stop-1 as their own Sources (keys shared)."""
        part = Sources(self.n)
        part.fields = self.fields[start * REC_FIELDS:stop * REC_FIELDS]
        part.keys = self.keys
        part.meta = self.meta[start:stop]
        return part

    def max_sources(self):
        fields, keep = _ptr32(self.fields)
        return _max_sources()(fields, len(self.meta))

    # ---------------------------------------------------------------- describing
    def info(self, ident):
        """The description of a source id (without the text direction)."""
        meta = self.meta[record_of(ident)]
        sub = sub_of(ident)
        kind = meta[0]
        if isinstance(kind, dict):               # explicit source
            return dict(kind)
        direction = DIRECTIONS[sub & 1]
        if kind in ("route", "offset_grid"):
            _, width, offsets = meta
            route, index = ROUTES[(sub >> 1) % len(ROUTES)], (sub >> 1) // len(ROUTES)
            if kind == "route":
                return {"transposition": "route", "route": route, "width": width, "direction": direction}
            return {"transposition": "offset_grid", "route": route, "width": width, "grid_offset": offsets[index],
                    "direction": direction}
        if kind == "rail_fence":
            return {"transposition": "rail_fence", "rails": meta[1], "direction": direction}
        if kind == "redefence":
            return {"transposition": "redefence", "rails": meta[1], "rail_order": list(meta[2]), "direction": direction}
        if kind == "double_rotation":
            return {"transposition": "double_rotation", "widths": [meta[1], meta[2]], "clockwise": [meta[3], meta[4]],
                    "direction": direction}
        if kind == "offset_double_rotation":
            return {"transposition": "offset_double_rotation", "widths": [meta[1], meta[2]], "grid_offset": meta[5],
                    "clockwise": [meta[3], meta[4]], "direction": direction}
        if kind == "myszkowski":            # (kind, label, value): label "keyword" or "ranks"
            return {"transposition": "myszkowski", meta[1]: _plain_value(meta[2]), "direction": direction}
        if kind == "amsco":
            first, rule = AMSCO_RULES[sub >> 1]
            return {"transposition": "amsco", meta[1]: _plain_value(meta[2]), "first_cell": first, "rows": rule,
                    "direction": direction}
        return {"kind": kind, "params": list(meta[1:]), "direction": direction}

    # ---------------------------------------------------------------- C calls
    def __iter__(self):
        """(info, src) for every source, generated in C, blocks of records."""
        n, size, start = self.n, 2000, 0
        while start < len(self.meta):
            part = self.block(start, min(len(self.meta), start + size))
            if any(isinstance(meta[0], dict) for meta in part.meta):
                raise TypeError("explicit sources are iterated from their own list")
            capacity = max(1, part.max_sources())
            src = array("i", bytes(4 * n * capacity))
            ids = (_i64 * capacity)()
            fields, keep_f = _ptr32(part.fields)
            keys, keep_k = _ptr32(part.keys)
            out, keep_o = _ptr32(src)
            count = _check(_sources()(n, fields, len(part.meta), 0, keys, out, ids, capacity))
            for k in range(count):
                local = ids[k]
                ident = ((start + record_of(local)) << ID_SHIFT) | (local & ((1 << ID_SHIFT) - 1))
                yield self.info(ident), src[k * n:(k + 1) * n].tolist()
            start += size

    def score(self, codes, fitness, top=0, text=BOTH, rec_base=0):
        """Score every source. top > 0: (tested, [(score, id)] best first);
        top = 0: (tested, [(score, id)] for every source, in order)."""
        n = self.n
        if len(codes) != n:
            raise ValueError("text length differs from the sources' length")
        scores, size, factor, weight = fitness_parameters(fitness, codes)
        capacity = top if top > 0 else max(1, self.max_sources() * (2 if text == BOTH else 1))
        out_scores, out_ids, count = (_f64 * capacity)(), (_i64 * capacity)(), _i32(0)
        fields, keep_f = _ptr32(self.fields)
        keys, keep_k = _ptr32(self.keys)
        tested = _check(_run()(_u8(codes), n, fields, len(self.meta), rec_base, keys, text, scores_pointer(scores),
                               size, factor, weight, top, out_scores, out_ids, ctypes.byref(count), capacity))
        return tested, list(zip(out_scores[:count.value], out_ids[:count.value]))

    def plain(self, codes, ids):
        """The readings of ``codes`` for the given ids (bytes each, every symbol kept)."""
        if not ids:
            return []
        n = self.n
        explicit = [k for k, ident in enumerate(ids) if isinstance(self.meta[record_of(ident)][0], dict)]
        out = [None] * len(ids)
        for k in explicit:                   # explicit sources: the src list is at hand
            ident = ids[k]
            src = self.meta[record_of(ident)][1]
            source = codes[::-1] if ident & 1 else codes
            out[k] = bytes(source[i] for i in src)
        family = [k for k in range(len(ids)) if out[k] is None]
        if family:
            wanted = (_i64 * len(family))(*[ids[k] for k in family])
            buffer = (ctypes.c_uint8 * (n * len(family)))()
            fields, keep_f = _ptr32(self.fields)
            keys, keep_k = _ptr32(self.keys)
            _check(_plain()(_u8(codes), n, fields, len(self.meta), keys, wanted, len(family), buffer))
            data = bytes(buffer)
            for j, k in enumerate(family):
                out[k] = data[j * n:(j + 1) * n]
        return out


def keyword_sources(n, words):
    """Myszkowski and AMSCO records for dictionary keywords, derived and
    de-duplicated in C (cct_screens_keyword_records; the rules are documented in
    transposition_screen.keyword_sources)."""
    words = list(words)
    lengths = array("i", map(len, words))
    chars = "".join(words).encode("utf-32-le")
    records = 2 * len(words)
    fields = array("i", bytes(4 * REC_FIELDS * max(1, records)))
    keys = array("i", bytes(4 * max(1, 2 * sum(lengths))))
    owner = array("i", bytes(4 * max(1, records)))
    kernel = _fn("cct_screens_keyword_records", _i64, [ctypes.c_char_p, _P32, _i32, _i32, _P32, _P32, _P32])
    lengths_p, keep_l = _ptr32(lengths)
    fields_p, keep_f = _ptr32(fields)
    keys_p, keep_k = _ptr32(keys)
    owner_p, keep_o = _ptr32(owner)
    count = _check(kernel(chars, lengths_p, len(words), n, fields_p, keys_p, owner_p))
    del fields_p, keys_p, keep_f, keep_k
    sources = Sources(n)
    sources.fields = fields[:count * REC_FIELDS]
    used = sum(sources.fields[7::REC_FIELDS])
    sources.keys = keys[:used]
    names = {MYSZKOWSKI: "myszkowski", AMSCO: "amsco"}
    sources.meta = [(names[family], "keyword", words[w])
                    for family, w in zip(sources.fields[0::REC_FIELDS], owner[:count])]
    return sources


def _plain_value(value):
    return list(value) if isinstance(value, tuple) else value


# ------------------------------------------------------------------ statistics

def _periodicity():
    return _fn("cct_screens_periodicity", _i32, [_P8, _i32, _i32, _i32, _u64, _P8, _PF, _PF, _PF])


def _text_stats():
    return _fn("cct_screens_text_stats", None, [_P8, _i32, _i32, _VP, _i32, _f64, _PF, _PF, _PF, _PF, _PF])


def _reference_samples():
    return _fn("cct_screens_reference_samples", None, [_P8, _i32, _i32, _u64, _P8, _P8])


def periodicity(codes, max_period, english, seed):
    """Column IoC for periods 1..max_period: (values, chance rows, English rows);
    chance: ``len(english)`` successive shuffles of the text per period (seeded),
    English: each sample split the same way."""
    n, samples = len(codes), len(english)
    if any(len(text) != n for text in english):
        raise ValueError("English samples must have the text's length")
    values = (_f64 * max(1, max_period))()
    chance = (_f64 * max(1, max_period * samples))()
    eng = (_f64 * max(1, max_period * samples))()
    if _periodicity()(_u8(codes), n, max_period, samples, seed, _u8(b"".join(english)), values, chance, eng):
        raise MemoryError("periodicity: out of memory")
    rows = [(list(chance[p * samples:(p + 1) * samples]), list(eng[p * samples:(p + 1) * samples]))
            for p in range(max_period)]
    return list(values[:max_period]), rows


def text_stats(texts, length, fitness, english_percent, wanted=("ioc", "chi", "adjacency", "fitness")):
    """{statistic: [value per text]} for texts of ``length`` letter codes."""
    count = len(texts)
    outs = {name: (_f64 * max(1, count))() for name in ("ioc", "chi", "adjacency", "fitness")}
    pointers = [outs[name] if name in wanted else None for name in ("ioc", "chi", "adjacency", "fitness")]
    _text_stats()(_u8(b"".join(texts)), count, length, scores_pointer(fitness.scores), fitness.size,
                  fitness.entropy_weight, (_f64 * 26)(*english_percent), *pointers)
    return {name: list(outs[name][:count]) for name in wanted}


def reference_samples(english, length, seed):
    """(shuffled copies of the English texts, as many uniformly random texts)."""
    count = len(english)
    shuffled = (ctypes.c_uint8 * max(1, count * length))()
    uniform = (ctypes.c_uint8 * max(1, count * length))()
    _reference_samples()(_u8(b"".join(english)), count, length, seed, shuffled, uniform)
    a, b = bytes(shuffled), bytes(uniform)
    return ([a[i * length:(i + 1) * length] for i in range(count)],
            [b[i * length:(i + 1) * length] for i in range(count)])


# ------------------------------------------------------------------ word patterns (screens_pattern.c)

class PatternDictionary:
    """A word list in C form for pattern_isomorphism: letter codes, offsets and
    every word's score (cct_pattern_word_scores: mean n-gram score; words shorter
    than the n-gram size score 120 when listed in ``short_common``, else 60)."""

    def __init__(self, words, ngram_scores, size, short_common=()):
        native.require()
        if any(not (w.isascii() and w.isalpha() and w.isupper()) for w in words):
            raise ValueError("dictionary words must be A-Z")
        self.words = list(words)
        self.letters = _u8(b"".join(w.encode("ascii") for w in self.words).translate(_PACK))
        offsets = array("i", [0])
        for word in self.words:
            offsets.append(offsets[-1] + len(word))
        self._offsets = offsets
        self.offsets = (_i32 * len(offsets)).from_buffer(offsets)
        common = bytearray(26 * 27)
        for word in short_common:
            codes = word.encode("ascii").translate(_PACK)
            if len(codes) == 1:
                common[codes[0] * 27 + 26] = 1
            elif len(codes) == 2:
                common[codes[0] * 27 + codes[1]] = 1
        self.scores = (_f64 * max(1, len(self.words)))()
        _fn("cct_pattern_word_scores", None, [_P8, _P32, _i32, _VP, _i32, _P8, _PF])(
            self.letters, self.offsets, len(self.words), scores_pointer(ngram_scores), size, _u8(common), self.scores)

    def matches(self, word, limit):
        """(number of dictionary words with the letter pattern of ``word``, the best
        ``limit`` of them, best score first; ties in dictionary order)."""
        codes = _codes(word)
        out = (_i32 * max(1, limit))()
        total = _fn("cct_pattern_matches", _i32, [_P8, _P32, _i32, _PF, _P8, _i32, _i32, _P32])(
            self.letters, self.offsets, len(self.words), self.scores, _u8(codes), len(codes), limit, out)
        if total < 0:
            raise MemoryError("word pattern matches: out of memory")
        return total, [self.words[i] for i in out[:min(total, limit)]]

    def solve(self, cipher_words, beam, per_word):
        """Beam search for joint letter mappings (cct_pattern_solve) over the
        distinct cipher words in the given order: [(score, {cipher letter: plain
        letter})], best first."""
        if beam < 1 or per_word < 1:
            raise ValueError("beam and per_word must be at least 1")
        codes = [_codes(w) for w in cipher_words]
        offsets = array("i", [0])
        for c in codes:
            offsets.append(offsets[-1] + len(c))
        forward = (ctypes.c_uint8 * (26 * beam))()
        scores = (_f64 * beam)()
        count = _fn("cct_pattern_solve", _i32, [_P8, _P32, _i32, _PF, _P8, _P32, _i32, _i32, _i32, _P8, _PF])(
            self.letters, self.offsets, len(self.words), self.scores, _u8(b"".join(codes)),
            (_i32 * len(offsets)).from_buffer(offsets), len(codes), beam, per_word, forward, scores)
        if count < 0:
            raise (MemoryError if count == -4 else ValueError)(f"word pattern search failed ({count})")
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return [(scores[b], {upper[c]: upper[forward[b * 26 + c]] for c in range(26) if forward[b * 26 + c] < 26})
                for b in range(count)]


_PACK = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", bytes(range(26)))


def _codes(word):
    """Letter codes of an A-Z word (ValueError for anything else)."""
    if not (word.isascii() and word.isalpha() and word.isupper()):
        raise ValueError(f"not an A-Z word: {word!r}")
    return word.encode("ascii").translate(_PACK)
