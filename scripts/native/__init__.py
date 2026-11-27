"""The toolkit's C engines (and the optional OpenCL GPU search).

Every search, annealing, brute-force and dictionary engine runs in this one C
library; there is no Python fallback. Build it once per machine (needs zig's C
compiler, a pip package):

    python -m pip install ziglang
    python scripts/native_tools.py build        (or menu 91, C Engines & GPU)

Without the library (or with CCT_NATIVE=0) the solvers raise NativeUnavailable
with these instructions. Each engine is its own .c file in this folder sharing
cct_common.h; its Python wrapper declares its C functions with function(). The
tests check the engines against known answers, planted ciphertexts and small
test-only reference implementations.
"""
import ctypes
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Every engine is its own .c file in this folder (they share cct_common.h).
SOURCES = sorted(os.path.join(HERE, name) for name in os.listdir(HERE) if name.endswith(".c"))
BUILD = os.path.join(HERE, "build")
VERSION = 3
LIBRARY = os.path.join(BUILD, {"win32": "cct_native.dll", "darwin": "libcct_native.dylib"}.get(sys.platform,
                                                                                             "libcct_native.so"))
# A different library file (for example a private test build); used as is.
LIBRARY = os.environ.get("CCT_NATIVE_LIBRARY", LIBRARY)
MAXW, MAXCRIB, MAXP = 64, 128, 128
HIT_FIELDS = MAXW + 4
_lib = None
_tried = False

_i32, _i64, _u8, _f64 = ctypes.c_int32, ctypes.c_int64, ctypes.c_uint8, ctypes.c_double
_P8, _P32, _P64 = ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int64)


class Layout(ctypes.Structure):
    _fields_ = [("n", _i32), ("cipher", _P8), ("width", _i32), ("read_rows", _i32), ("remainder", _i32),
                ("partial_base", _i32), ("col_len", _P32), ("d_col", _P32), ("d_base", _P32), ("d_kind", _P32)]


class AnnealState(ctypes.Structure):
    _fields_ = [("current", _u8 * MAXW), ("best", _u8 * MAXW), ("current_score", _f64), ("best_score", _f64),
                ("temp", _f64), ("iteration", _i64), ("rng", ctypes.c_uint64 * 4)]


PENDING = LIBRARY + ".new"


def _install_pending():
    """Move a freshly built library into place (possible once no process has the old one loaded)."""
    if os.path.exists(PENDING):
        try:
            os.replace(PENDING, LIBRARY)
        except OSError:
            pass


def build(verbose=True):
    """Compile the C engines with zig's C compiler (python -m pip install ziglang).

    The library is written next to the current one and then moved into place.
    On Windows a library that a running process has loaded cannot be replaced:
    the new build then waits as cct_native.dll.new and is installed the next
    time the toolkit starts. Returns "built" or "pending"."""
    os.makedirs(BUILD, exist_ok=True)
    # -march=native: the library is built on the machine that runs it.
    # -ffp-contract=off: no fused multiply-add, so C fitness values equal the Python definitions.
    command = [sys.executable, "-m", "ziglang", "cc", "-O3", "-march=native", "-ffp-contract=off", "-shared", "-o", PENDING,
               *SOURCES]
    if sys.platform != "win32":
        command.insert(5, "-fPIC")
    if verbose:
        print(" ".join(command))
    subprocess.run(command, check=True)
    try:
        os.replace(PENDING, LIBRARY)
    except OSError:
        return "pending"
    global _lib, _tried
    _lib, _tried = None, False
    _functions.clear()
    return "built"


def library():
    """The loaded library, or None (not built, wrong version, or CCT_NATIVE=0)."""
    global _lib, _tried
    if _tried:
        return _lib
    _tried = True
    _install_pending()
    if os.environ.get("CCT_NATIVE", "1") == "0" or not os.path.exists(LIBRARY):
        return None
    try:
        lib = ctypes.CDLL(LIBRARY)
        if lib.cct_native_version() != VERSION:
            return None
        _register(lib)
    except (OSError, AttributeError):    # a stale build that lacks a function counts as not built
        return None
    _lib = lib
    return _lib


class NativeUnavailable(RuntimeError):
    """The C engines are not built (menu 91, or: python scripts/native_tools.py build)."""


MISSING_MESSAGE = ("The C engines are not built. Build them once with menu 91 (C Engines & GPU), or:\n"
                   "    python -m pip install ziglang\n    python scripts/native_tools.py build")
_functions = {}


def function(name, restype, argtypes):
    """A C function of the library with its signature set (cached). Each engine's
    Python wrapper declares its own functions this way. Raises NativeUnavailable
    when the library is missing or stale (lacks the function)."""
    cached = _functions.get(name)
    if cached is not None:
        return cached
    lib = library()
    if lib is None:
        raise NativeUnavailable(MISSING_MESSAGE)
    try:
        found = getattr(lib, name)
    except AttributeError:
        raise NativeUnavailable(f"The C library is out of date (it lacks {name}): rebuild it with menu 91.") from None
    found.restype = restype
    found.argtypes = argtypes
    _functions[name] = found
    return found


def require():
    """Raise NativeUnavailable with the build instructions when the library is missing."""
    if library() is None:
        raise NativeUnavailable(MISSING_MESSAGE)


def _register(lib):
    lib.cct_perm_bruteforce.restype = _i64
    lib.cct_perm_bruteforce.argtypes = [ctypes.POINTER(Layout), _P8, _i32, _i32, _P8, _i64, _P64, _P8, _P32]
    lib.cct_order_total.restype = _i64
    lib.cct_order_total.argtypes = [ctypes.POINTER(Layout), _P8, _P8, _i32]
    lib.cct_perm_anneal.restype = _i32
    lib.cct_perm_anneal.argtypes = [ctypes.POINTER(Layout), _P8, _i32, _f64, _f64, _i32, _i32, _f64, _i32,
                                    ctypes.POINTER(AnnealState)]
    lib.cct_crib_columnar_periodic.restype = _i64
    lib.cct_crib_columnar_periodic.argtypes = [ctypes.POINTER(Layout), _i32, _P32, _P32, _P32, _P32, _i32, _P8,
                                               _i32, _P8, _i32, _P32, _i32, _i64, _P32, _i32, _P32, _P32]
    # shared scoring (version 2); the other engines declare their functions through function()
    lib.cct_ngram_total.restype = _i64
    lib.cct_ngram_total.argtypes = [ctypes.c_char_p, _i32, ctypes.c_void_p, _i32]


def available():
    return library() is not None


def u8(values):
    if isinstance(values, (bytes, bytearray)):
        return (ctypes.c_uint8 * max(1, len(values))).from_buffer_copy(bytes(values) or bytes(1))
    return (ctypes.c_uint8 * max(1, len(values)))(*values)


_table_cache = {}


def scores_u8(scores):
    """An n-gram table as a uint8 array for the C engines, made once per table
    (a bytearray is shared without copying; bytes are copied once). Copying the
    11.9 MB 5-gram table on every call cost more than many searches."""
    cached = _table_cache.get(id(scores))
    if cached is not None and cached[0] is scores:
        return cached[1]
    if isinstance(scores, bytearray):
        array = (ctypes.c_uint8 * len(scores)).from_buffer(scores)
    else:
        array = (ctypes.c_uint8 * len(scores)).from_buffer_copy(scores)
    _table_cache[id(scores)] = (scores, array)
    return array


def i32(values):
    return (ctypes.c_int32 * max(1, len(values)))(*values)


def columnar_descriptors(length, width, layout, positions):
    """For each position in ``positions``: (column, base, kind) such that the source
    position under any column order is start[column] + base (kind 0), rank[column]
    + base (kind 1) or partial_base + partial_rank[column] (kind 2). Mirrors
    transposition_core.make_permuter (tested). Returns (read_rows, column lengths,
    remainder, partial_base, descriptors)."""
    height = (length + width - 1) // width
    remainder = length % width or width
    full_rows = height if remainder == width else height - 1
    full_end = full_rows * width
    column_lengths = [height if column < remainder else height - 1 for column in range(width)]
    table = {}
    if layout == "write_rows_read_cols":
        table = {i: (i % width, i // width, 0) for i in range(length)}
    elif layout == "write_cols_read_cols":
        i = 0
        for column in range(width):
            for k in range(column_lengths[column]):
                table[i] = (column, k, 0)
                i += 1
    elif layout == "write_rows_read_rows":
        table = {i: ((i % width, (i // width) * width, 1) if i < full_end else (i - (height - 1) * width, 0, 2))
                 for i in range(length)}
    elif layout == "write_cols_read_rows":
        i = 0
        for column in range(width):
            for k in range(full_rows):
                table[i] = (column, k * width, 1)
                i += 1
            if remainder != width and column < remainder:
                table[i] = (column, 0, 2)
                i += 1
    else:
        raise ValueError(layout)
    read_rows = layout in ("write_rows_read_rows", "write_cols_read_rows")
    return read_rows, column_lengths, remainder, (height - 1) * width, [table[p] for p in positions]


def layout_struct(codes, width, layout):
    """(Layout, keep-alive list) for a text of letter codes."""
    read_rows, lengths, remainder, partial_base, desc = columnar_descriptors(len(codes), width, layout,
                                                                           range(len(codes)))
    keep = [u8(bytes(codes)), i32(lengths), i32([d[0] for d in desc]), i32([d[1] for d in desc]),
            i32([d[2] for d in desc])]
    return Layout(len(codes), keep[0], width, int(read_rows), remainder, partial_base, *keep[1:]), keep
