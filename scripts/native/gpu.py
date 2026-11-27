"""GPU (OpenCL) engines for the columnar searches.

Enabled with the environment variable CCT_GPU=1 (or from menu 91, C
Engines & GPU); CCT_GPU_DEVICE=<text> picks the GPU whose name contains <text>
(default: a discrete GPU before an integrated one). Needs only the OpenCL
runtime that ships with the graphics driver (NVIDIA, AMD, Intel). Results are
identical to the CPU code: the tests compare them on every GPU present.
"""
import ctypes
import math
import os

from native import opencl

KERNEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "columnar.cl")
TUNING = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build", "gpu_tuning.json")
MIN_WIDTH = 9            # narrower searches are faster on the CPU
BATCH = 1 << 24          # column orders per kernel launch
MAX_HITS = 1 << 16       # known-plaintext hits per launch before the CPU redoes that launch
PER_ITEM = None          # orders per work-item; None = tuned per device
PER_ITEM_CHOICES = (1, 16, 128, 512)
_contexts = {}


def enabled():
    return os.environ.get("CCT_GPU", "0") == "1" and opencl.pick_device(os.environ.get("CCT_GPU_DEVICE")) is not None


def context(width=32, ncrib=64, max_period=63):
    sizes = (os.environ.get("CCT_GPU_DEVICE") or "", width, ncrib, max_period + 1)
    if sizes not in _contexts:
        with open(KERNEL, encoding="utf-8") as handle:
            source = handle.read()
        device = opencl.pick_device(sizes[0] or None)
        if device is None:
            raise opencl.OpenCLError("no OpenCL GPU found")
        _contexts[sizes] = opencl.Context(source, device,
                                          options=f"-D MAXW={width} -D MAXCRIB={ncrib} -D MAXP={max_period + 1}")
    return _contexts[sizes]


def unrank(index, items):
    items, out = list(items), []
    for j in range(len(items), 0, -1):
        d, index = divmod(index, math.factorial(j - 1))
        out.append(items.pop(d))
    return out


def rank(order, items):
    items, index = list(items), 0
    for value in order:
        d = items.index(value)
        index += d * math.factorial(len(items) - 1)
        items.pop(d)
    return index


def _i32(values):
    return (ctypes.c_int32 * max(1, len(values)))(*values)


def _u8(values):
    return (ctypes.c_uint8 * max(1, len(values)))(*values)


def _layout_buffers(ctx, codes, width, mode, positions):
    import native
    read_rows, lengths, remainder, partial_base, desc = native.columnar_descriptors(len(codes), width, mode, positions)
    buffers = [ctx.buffer(bytes(codes), read_only=True), ctx.buffer(_i32(lengths), read_only=True),
               ctx.buffer(_i32([d[0] for d in desc]), read_only=True), ctx.buffer(_i32([d[1] for d in desc]), read_only=True),
               ctx.buffer(_i32([d[2] for d in desc]), read_only=True)]
    return read_rows, remainder, partial_base, buffers


def _per_item(name):
    return PER_ITEM or tuned_per_item(name)


def best_order(codes, width, mode, ngram_model, prefix=()):
    """Same column order as native.perm.best_order (first order with the highest total)."""
    ctx = context(width)
    i32, i64, u64 = ctypes.c_int32, ctypes.c_int64, ctypes.c_uint64
    rest = sorted(c for c in range(width) if c not in prefix)
    total_orders = math.factorial(len(rest))
    read_rows, remainder, partial_base, (cipher_b, collen_b, dcol_b, dbase_b, dkind_b) = _layout_buffers(
        ctx, codes, width, mode, range(len(codes)))
    others = [ctx.buffer(_u8(list(prefix) or [0]), read_only=True), ctx.buffer(_u8(rest or [0]), read_only=True),
              ctx.buffer((ctypes.c_uint64 * 21)(*[math.factorial(k) for k in range(21)]), read_only=True),
              ctx.buffer(ngram_model.scores if isinstance(ngram_model.scores, (bytes, bytearray))
                         else bytes(ngram_model.scores), read_only=True)]
    prefix_b, rest_b, fact_b, scores_b = others
    per_item = _per_item("perm_score")
    best = (-1, 0)
    try:
        for base in range(0, total_orders, BATCH):
            count = min(BATCH, total_orders - base)
            items = (count + per_item - 1) // per_item
            totals_b, index_b = ctx.buffer(size=8 * items), ctx.buffer(size=8 * items)
            ctx.run("perm_score", [cipher_b, i32(len(codes)), i32(width), i32(int(read_rows)), collen_b, i32(remainder),
                                   i32(partial_base), dcol_b, dbase_b, dkind_b, i32(len(prefix)), prefix_b,
                                   i32(len(rest)), rest_b, fact_b, u64(base), u64(count), i32(per_item), scores_b,
                                   i32(ngram_model.size), i64(26 ** (ngram_model.size - 1)), totals_b, index_b], items)
            totals = memoryview(ctx.read(totals_b)).cast("q")
            indexes = memoryview(ctx.read(index_b)).cast("Q")
            for total, index in zip(totals, indexes):
                if total > best[0] or (total == best[0] and index < best[1]):
                    best = (total, index)
            totals_b.release()
            index_b.release()
    finally:
        for b in [cipher_b, collen_b, dcol_b, dbase_b, dkind_b] + others:
            b.release()
    return list(prefix) + unrank(best[1], rest)


def crib_records(codes, crib_pos, valtab, ncombo, width, mode, prefix, periods, min_checks):
    """Same ([(column order, combo, order, period, checks)], orders) as the CPU engines of
    crib_columnar_search, computed on the GPU (CPU redo of overflowing launches)."""
    import native
    from native import crib
    ncrib = len(crib_pos)
    ctx = context(width, ncrib, max(periods))
    i32, u64 = ctypes.c_int32, ctypes.c_uint64
    rest = sorted(c for c in range(width) if c not in prefix)
    total_orders = math.factorial(len(rest))
    read_rows, remainder, partial_base, (cipher_b, collen_b, dcol_b, dbase_b, dkind_b) = _layout_buffers(
        ctx, codes, width, mode, crib_pos)
    fixed_a, fixed_b, fixed_n = [], [], []
    for period in periods:
        pairs = crib.same_slot_pairs(crib_pos, period)
        fixed_a += [a for a, _ in pairs] + [0] * (ncrib - len(pairs))
        fixed_b += [b for _, b in pairs] + [0] * (ncrib - len(pairs))
        fixed_n.append(len(pairs))
    others = [ctx.buffer(_i32(crib_pos), read_only=True), ctx.buffer(_u8(list(prefix) or [0]), read_only=True),
              ctx.buffer(_u8(rest or [0]), read_only=True),
              ctx.buffer((ctypes.c_uint64 * 21)(*[math.factorial(k) for k in range(21)]), read_only=True),
              ctx.buffer(bytes(valtab), read_only=True), ctx.buffer(_i32(periods), read_only=True),
              ctx.buffer(_u8(fixed_a), read_only=True), ctx.buffer(_u8(fixed_b), read_only=True),
              ctx.buffer(_i32(fixed_n), read_only=True)]
    crib_b, prefix_b, rest_b, fact_b, valtab_b, periods_b, fa_b, fb_b, fn_b = others
    nhits_b, index_b, info_b = ctx.buffer(size=4), ctx.buffer(size=8 * MAX_HITS), ctx.buffer(size=16 * MAX_HITS)
    per_item = _per_item("crib_periodic")
    records = []
    try:
        for base in range(0, total_orders, BATCH):
            count = min(BATCH, total_orders - base)
            ctx.write(nhits_b, bytes(4))
            ctx.run("crib_periodic", [cipher_b, i32(ncrib), crib_b, i32(width), i32(int(read_rows)), collen_b,
                                      i32(remainder), i32(partial_base), dcol_b, dbase_b, dkind_b, i32(len(prefix)),
                                      prefix_b, i32(len(rest)), rest_b, fact_b, u64(base), u64(count), i32(per_item),
                                      i32(ncombo), valtab_b, i32(len(periods)), periods_b, i32(min_checks), fa_b,
                                      fb_b, fn_b, nhits_b, i32(MAX_HITS), index_b, info_b],
                    (count + per_item - 1) // per_item)
            found = int.from_bytes(ctx.read(nhits_b, 4), "little")
            if found > MAX_HITS:
                raw, _ = crib.native_records(codes, crib_pos, valtab, ncombo, width, mode, prefix, periods, min_checks,
                                             start_tail=unrank(base, rest), max_orders=count)
                records += [(rank(r[0][len(prefix):], rest), r[1], r[2], periods.index(r[3]), r[4]) for r in raw]
                continue
            if found:
                index, info = ctx.read(index_b, 8 * found), ctx.read(info_b, 16 * found)
                idx = memoryview(index).cast("Q")
                fields = memoryview(info).cast("i")
                records += [(idx[h], fields[4 * h], fields[4 * h + 1], fields[4 * h + 2], fields[4 * h + 3])
                            for h in range(found)]
    finally:
        for b in [cipher_b, collen_b, dcol_b, dbase_b, dkind_b, nhits_b, index_b, info_b] + others:
            b.release()
    records.sort()
    return [(list(prefix) + unrank(i, rest), c, o, periods[p], n) for i, c, o, p, n in records], total_orders


# ------------------------------------------------------------------ device tuning

def _device_key():
    ctx = context()
    return f"{ctx.properties['name']} | {ctx.platform_name}"


def benchmark(kernel, per_item, repeats=2):
    """Column orders per second on the current device for one kernel."""
    import random
    import time
    global PER_ITEM
    rng = random.Random(1)
    codes = bytes(rng.randrange(26) for _ in range(120))
    saved, PER_ITEM = PER_ITEM, per_item
    try:
        best = 0.0
        for _ in range(repeats):
            started = time.time()
            if kernel == "perm_score":
                model = type("Model", (), {"size": 4, "scores": bytes(26 ** 4)})()
                best_order(codes, 11, "write_rows_read_cols", model, prefix=(0,))
            else:
                crib_pos = list(range(20, 40))
                crib_records(codes, crib_pos, bytes(8 * 20 * 26), 8, 11, "write_rows_read_cols", (0,), list(range(1, 25)), 30)
            best = max(best, math.factorial(10) / (time.time() - started))
        return best
    finally:
        PER_ITEM = saved


def tuned_per_item(kernel, retune=False):
    """Fastest orders-per-work-item for this device and kernel, measured once and cached."""
    import json
    key = f"{_device_key()} | {kernel}"
    try:
        with open(TUNING, encoding="utf-8") as handle:
            table = json.load(handle)
    except (OSError, ValueError):
        table = {}
    if key in table and not retune:
        return table[key]["per_item"]
    speeds = {choice: benchmark(kernel, choice) for choice in PER_ITEM_CHOICES}
    best = max(speeds, key=speeds.get)
    table[key] = {"per_item": best, "orders_per_second": {str(k): round(v) for k, v in speeds.items()}}
    os.makedirs(os.path.dirname(TUNING), exist_ok=True)
    with open(TUNING, "w", encoding="utf-8") as handle:
        json.dump(table, handle, indent=1)
    return best


def describe():
    lines = []
    for platform, _, props in opencl.devices():
        lines.append(f"{props['name']} ({platform}): {props['compute_units']} compute units, {props['clock_mhz']} MHz, "
                     f"{props['global_mem'] / 2**30:.1f} GB, {'integrated' if props['unified_memory'] else 'discrete'}")
    return lines or ["no OpenCL GPU found"]
