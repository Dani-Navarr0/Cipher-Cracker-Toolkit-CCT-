"""Known-plaintext search: columnar transposition + periodic (Vigenere-family) key.

For every column order of a columnar transposition (4 layouts) and every
periodic key length, each known plaintext letter implies one key value. Letters
that fall on the same key slot must imply the same value; a hypothesis is kept
when at least ``min_checks`` such agreements hold and none fails. A wrong
hypothesis passes each agreement by chance with probability 1/26.

Two orders of the layers are tested:
  * key then transposition: the key slot is the plaintext position i (mod L);
  * transposition then key: the key slot is the ciphertext position (mod L).
Key conventions (alphabets as index tables, PA plaintext, CA ciphertext):
  Vigenere  c = CA[PA(p) + k]   ->  k = CA(c) - PA(p)
  Beaufort  c = CA[k - PA(p)]   ->  k = CA(c) + PA(p)
(Variant Beaufort's key is minus the Vigenere key, so it passes the same checks.)

Engines: C (native library) and OpenCL GPU; the tests require identical
results (and compare them with a small test-only reference search).
"""
import ctypes
import math

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LAYOUTS = ("write_rows_read_cols", "write_rows_read_rows", "write_cols_read_rows", "write_cols_read_cols")
ORDERS = ("key then transposition", "transposition then key")
HIT_CAPACITY = 4096


def same_slot_pairs(slots, period):
    """Chained pairs of clue indices sharing a key slot (each later clue with the previous one)."""
    last, pairs = {}, []
    for index, slot in enumerate(slots):
        residue = slot % period
        if residue in last:
            pairs.append((last[residue], index))
        last[residue] = index
    return pairs


def make_combos(alphabets, variants=("vigenere", "beaufort")):
    """[(label, plain alphabet, cipher alphabet, variant)] for alphabet pairs given as
    {name: alphabet string} -> every (plain, cipher) pairing, each variant."""
    combos = []
    for plain_name, plain in alphabets.items():
        for cipher_name, cipher in alphabets.items():
            for variant in variants:
                combos.append((f"{plain_name}/{cipher_name} {variant}", plain, cipher, variant))
    return combos


def value_table(combos, crib_plain):
    """bytes: value[combo][clue][cipher letter] = implied key value (as a cipher-alphabet index)."""
    out = bytearray()
    for _, plain, cipher, variant in combos:
        pa = {ord(ch) - 65: i for i, ch in enumerate(plain)}
        ca = {ord(ch) - 65: i for i, ch in enumerate(cipher)}
        for p in crib_plain:
            term = -pa[p] if variant == "vigenere" else pa[p]
            out += bytes((ca[c] + term) % 26 for c in range(26))
    return bytes(out)


def source_positions(length, width, mode, key):
    """src[i] = ciphertext position read at plaintext position i. Uses
    transposition_core.make_permuter (bytes, so up to 256 letters) and the
    position formulas of native.columnar_descriptors beyond that."""
    if length <= 256:
        from transposition_core import make_permuter
        return list(make_permuter(length, width, mode)(bytes(range(length)), list(key)))
    import native
    read_rows, lengths, remainder, partial_base, desc = native.columnar_descriptors(length, width, mode,
                                                                                  range(length))
    start, rank, prank, s, pr = {}, {}, {}, 0, 0
    for j, column in enumerate(key):
        start[column], rank[column] = s, j
        s += lengths[column]
        if column < remainder:
            prank[column], pr = pr, pr + 1
    return [start[c] + b if k == 0 else rank[c] + b if k == 1 else partial_base + prank[c] for c, b, k in desc]


def native_records(codes, crib_pos, valtab, ncombo, width, mode, prefix, periods, min_checks,
                   start_tail=None, max_orders=None):
    """C engine (tests/test_native.py checks it against a reference search)."""
    import native
    lib = native.library()
    layout, keep = native.layout_struct(codes, width, mode)
    _, _, _, _, desc = native.columnar_descriptors(len(codes), width, mode, crib_pos)
    rest = sorted(c for c in range(width) if c not in prefix)
    key = native.u8(list(prefix) + list(start_tail if start_tail is not None else rest))
    hits = (ctypes.c_int32 * (HIT_CAPACITY * native.HIT_FIELDS))()
    nhits, done = ctypes.c_int32(0), ctypes.c_int32(0)
    args = [ctypes.byref(layout), len(crib_pos), native.i32(crib_pos), native.i32([d[0] for d in desc]),
            native.i32([d[1] for d in desc]), native.i32([d[2] for d in desc]), len(prefix), key, ncombo,
            native.u8(valtab), len(periods), native.i32(periods), min_checks]
    remaining = max_orders if max_orders is not None else 1 << 62
    records, orders = [], 0
    while not done.value and remaining > 0:
        nhits.value = 0
        step = lib.cct_crib_columnar_periodic(*args, remaining, hits, HIT_CAPACITY, ctypes.byref(nhits),
                                              ctypes.byref(done))
        orders += step
        remaining -= step
        for h in range(nhits.value):
            rec = hits[h * native.HIT_FIELDS:(h + 1) * native.HIT_FIELDS]
            records.append((rec[:width], *rec[native.MAXW:native.MAXW + 4]))
    return records, orders


def search(codes, crib_pos, valtab, ncombo, width, mode, prefix, periods, min_checks, engine="auto"):
    """Records of every consistent hypothesis, using the fastest engine available."""
    import native
    from native import gpu
    usable = len(codes) >= width and len(crib_pos) <= native.MAXCRIB and max(periods) < native.MAXP
    if engine == "gpu" or (engine == "auto" and usable and gpu.enabled() and width - len(prefix) >= gpu.MIN_WIDTH):
        return gpu.crib_records(codes, crib_pos, valtab, ncombo, width, mode, tuple(prefix), list(periods),
                                min_checks)
    native.require()
    if not usable or width > native.MAXW:
        raise ValueError(f"Outside the C engine's limits: width at most {native.MAXW} and the text length, at most "
                         f"{native.MAXCRIB} known letters, key lengths below {native.MAXP}.")
    return native_records(codes, crib_pos, valtab, ncombo, width, mode, prefix, list(periods), min_checks)


def decrypt(codes, crib_pos, crib_plain, combo, width, mode, column_order, order, period):
    """Plaintext of a hit ('?' where the key slot holds no known letter) and the key."""
    _, plain, cipher, variant = combo
    pa_inv = {i: ch for i, ch in enumerate(plain)}
    ca = {ord(ch) - 65: i for i, ch in enumerate(cipher)}
    pa = {ord(ch) - 65: i for i, ch in enumerate(plain)}
    n = len(codes)
    src = source_positions(n, width, mode, column_order)
    key = [None] * period
    for p, letter in zip(crib_pos, crib_plain):
        slot = (p if order == 0 else src[p]) % period
        c = ca[codes[src[p]]]
        key[slot] = (c - pa[letter]) % 26 if variant == "vigenere" else (c + pa[letter]) % 26
    out = []
    for i in range(n):
        k = key[(i if order == 0 else src[i]) % period]
        if k is None:
            out.append("?")
            continue
        c = ca[codes[src[i]]]
        out.append(pa_inv[(c - k) % 26 if variant == "vigenere" else (k - c) % 26])
    return "".join(out), key


def expected_chance(tests, checks):
    return tests * 26.0 ** -checks


def default_min_checks(tests, target=1.0):
    """Smallest m such that the expected number of chance hits is at most ``target``."""
    m = 1
    while expected_chance(tests, m) > target:
        m += 1
    return m
