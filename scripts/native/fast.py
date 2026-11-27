"""Python wrappers for the version-2 kernels: n-gram totals, keyed-alphabet
periodic fits and the Gromark primer screen. Each returns None when the C
library is not available, so callers fall back to their Python code."""
import ctypes

import native

_i32, _i64, _f64 = ctypes.c_int32, ctypes.c_int64, ctypes.c_double
_scores_cache = {}


def _keyed_chi():
    return native.function("cct_keyed_periodic_chi", None,
                           [ctypes.POINTER(_i32), _i32, ctypes.c_char_p, _i32, _i32, _i32,
                            ctypes.POINTER(_f64), ctypes.POINTER(_f64)])


def _gromark():
    return native.function("cct_gromark_scores", None,
                           [ctypes.c_char_p, _i32, _i32, _i32, _i32, ctypes.POINTER(_f64), _i64, _i64,
                            ctypes.POINTER(_f64)])


def _scores_pointer(scores):
    """A pointer to an n-gram table (bytes or bytearray), cached per table."""
    key = id(scores)
    cached = _scores_cache.get(key)
    if cached is not None and cached[0] is scores:
        return cached[1]
    if isinstance(scores, bytearray):
        buffer = (ctypes.c_uint8 * len(scores)).from_buffer(scores)
        pointer = ctypes.cast(buffer, ctypes.c_void_p)
        keep = buffer
    else:
        keep = ctypes.c_char_p(scores)
        pointer = ctypes.cast(keep, ctypes.c_void_p)
    _scores_cache[key] = (scores, pointer, keep)
    return pointer


def ngram_total(codes, scores, size):
    lib = native.library()
    if lib is None:
        return None
    if not isinstance(codes, bytes):
        codes = bytes(codes)
    return lib.cct_ngram_total(codes, len(codes), _scores_pointer(scores), size)


def keyed_periodic_chi(counts, period, alphabets, mode, variant, expected):
    """counts: list of period lists of 26 ints; alphabets: list of 26-byte
    letter-code strings. Returns a list of total chi-squared values."""
    if native.library() is None:
        return None
    flat = (ctypes.c_int32 * (period * 26))(*[value for column in counts for value in column])
    packed = b"".join(alphabets)
    expected_c = (ctypes.c_double * 26)(*expected)
    out = (ctypes.c_double * len(alphabets))()
    _keyed_chi()(flat, period, packed, len(alphabets), mode, variant, expected_c, out)
    return list(out)


def gromark_scores(cipher, base, plen, sign, logp, first, count):
    if native.library() is None:
        return None
    cipher = bytes(cipher)
    logp_c = (ctypes.c_double * 26)(*logp)
    out = (ctypes.c_double * count)()
    _gromark()(cipher, len(cipher), base, plen, sign, logp_c, first, count, out)
    return list(out)
