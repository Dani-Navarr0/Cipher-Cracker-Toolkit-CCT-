"""Optional native (C) and GPU (OpenCL) engines for the toolkit.

Build once per machine (needs zig's C compiler, a pip package):

    python -m pip install ziglang
    python scripts/native_tools.py build        (or menu 45, Native Engines)

Without the library, or with the environment variable CCT_NATIVE=0, every tool
uses its pure-Python code, which stays the reference: the tests require the
native engines to give identical results.
"""
import ctypes
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = [os.path.join(HERE, "cct_native.c")]
BUILD = os.path.join(HERE, "build")
VERSION = 1
LIBRARY = os.path.join(BUILD, {"win32": "cct_native.dll", "darwin": "libcct_native.dylib"}.get(sys.platform,
                                                                                             "libcct_native.so"))
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


def build(verbose=True):
    """Compile the C engines with zig's C compiler (python -m pip install ziglang)."""
    os.makedirs(BUILD, exist_ok=True)
    # -march=native: the library is built on the machine that runs it
    command = [sys.executable, "-m", "ziglang", "cc", "-O3", "-march=native", "-shared", "-o", LIBRARY, *SOURCES]
    if sys.platform != "win32":
        command.insert(5, "-fPIC")
    if verbose:
        print(" ".join(command))
    subprocess.run(command, check=True)
    global _lib, _tried
    _lib, _tried = None, False
    return LIBRARY


def library():
    """The loaded library, or None (not built, wrong version, or CCT_NATIVE=0)."""
    global _lib, _tried
    if _tried:
        return _lib
    _tried = True
    if os.environ.get("CCT_NATIVE", "1") == "0" or not os.path.exists(LIBRARY):
        return None
    try:
        lib = ctypes.CDLL(LIBRARY)
        if lib.cct_native_version() != VERSION:
            return None
    except OSError:
        return None
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
    _lib = lib
    return _lib


def available():
    return library() is not None


def u8(values):
    if isinstance(values, (bytes, bytearray)):
        return (ctypes.c_uint8 * max(1, len(values))).from_buffer_copy(bytes(values) or bytes(1))
    return (ctypes.c_uint8 * max(1, len(values)))(*values)


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
