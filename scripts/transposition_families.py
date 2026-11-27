"""Transposition families beyond keyed columnar, as permutations ("sources").

Ported from the K4 workbench (kryptos/transpositions.py). Changed: the
duplicate check in offset_grid_sources uses tuple(src) instead of bytes(src),
so texts longer than 255 letters work. A source is a list with plaintext[i] = ciphertext[src[i]].
Every route is used in both directions: "read" (plaintext written row by row,
ciphertext read along the route) and "write" (ciphertext written along the
route, read row by row), because which convention was used is unknown.

Families: grid routes (rows, columns, snakes, diagonals, spirals; any width;
optionally starting part-way into the first row), rail fence, redefence,
K3-style double rotation, Myszkowski and AMSCO.
"""
from itertools import permutations, product


def _cells(length, width, offset=0):
    """Grid of plaintext positions; the text starts ``offset`` cells into the
    first row (cells before it, and after its end, are empty)."""
    rows = -(-(length + offset) // width)
    return rows, [[r * width + c - offset if 0 <= r * width + c - offset < length else None for c in range(width)]
                  for r in range(rows)]


def route_orders(length, width, offset=0):
    """Named orders of grid cells (lists of plaintext positions)."""
    rows, grid = _cells(length, width, offset)
    cols = [[grid[r][c] for r in range(rows)] for c in range(width)]
    clean = lambda seq: [x for x in seq if x is not None]
    routes = {
        "rows_snake": clean(x for r in range(rows) for x in (grid[r] if r % 2 == 0 else grid[r][::-1])),
        "rows_right_to_left": clean(x for r in range(rows) for x in grid[r][::-1]),
        "columns_down": clean(x for c in range(width) for x in cols[c]),
        "columns_up": clean(x for c in range(width) for x in cols[c][::-1]),
        "columns_snake": clean(x for c in range(width) for x in (cols[c] if c % 2 == 0 else cols[c][::-1])),
        "columns_right_to_left_down": clean(x for c in reversed(range(width)) for x in cols[c]),
        "columns_right_to_left_up": clean(x for c in reversed(range(width)) for x in cols[c][::-1]),
        "diagonals": clean(grid[r][d - r] for d in range(rows + width - 1) for r in range(rows) if 0 <= d - r < width),
        "diagonals_snake": clean(x for d in range(rows + width - 1)
                                 for x in ([grid[r][d - r] for r in range(rows) if 0 <= d - r < width][::(1 if d % 2 else -1)])),
        "spiral_clockwise": clean(_spiral(grid, rows, width)),
        "spiral_counterclockwise": clean(_spiral([list(row) for row in zip(*grid)], width, rows)),
    }
    return {name: order for name, order in routes.items() if len(order) == length}


def _spiral(grid, rows, width):
    top, bottom, left, right = 0, rows - 1, 0, width - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            yield grid[top][c]
        for r in range(top + 1, bottom + 1):
            yield grid[r][right]
        if top < bottom:
            for c in range(right - 1, left - 1, -1):
                yield grid[bottom][c]
        if left < right:
            for r in range(bottom - 1, top, -1):
                yield grid[r][left]
        top, bottom, left, right = top + 1, bottom - 1, left + 1, right - 1


def both_directions(order):
    """src arrays for 'route is the reading order' and its inverse."""
    length = len(order)
    read = [0] * length              # cipher[k] = plain[order[k]]  ->  src[order[k]] = k
    for k, plain_position in enumerate(order):
        read[plain_position] = k
    return {"read": read, "write": list(order)}


def route_sources(length, widths=range(2, 49)):
    for width in widths:
        for name, order in route_orders(length, width).items():
            for direction, src in both_directions(order).items():
                yield {"transposition": "route", "route": name, "width": width, "direction": direction}, src


def rail_fence_order(length, rails):
    cycle = 2 * (rails - 1)
    rail_of = [min(i % cycle, cycle - i % cycle) for i in range(length)]
    return [i for rail in range(rails) for i in range(length) if rail_of[i] == rail]


def rail_fence_sources(length, rails_range=range(2, 49)):
    for rails in rails_range:
        for direction, src in both_directions(rail_fence_order(length, rails)).items():
            yield {"transposition": "rail_fence", "rails": rails, "direction": direction}, src


def rotation_order(length, width, clockwise):
    """Write rows of ``width``, rotate the grid 90 degrees, read rows (K3-style step).
    Clockwise rotation reads columns bottom-to-top, left-to-right; counter-
    clockwise reads columns top-to-bottom, right-to-left."""
    routes = route_orders(length, width)
    return routes["columns_up"] if clockwise else routes["columns_right_to_left_down"]


def compose(first, second):
    """src for applying transposition-decryption ``second`` then ``first``:
    plain[i] = mid[first[i]], mid[j] = cipher[second[j]]."""
    return [second[j] for j in first]


def double_rotation_sources(length, widths=range(2, 25)):
    for w1, w2 in product(widths, repeat=2):
        for cw1, cw2 in product((True, False), repeat=2):
            o1, o2 = rotation_order(length, w1, cw1), rotation_order(length, w2, cw2)
            for d1, s1 in both_directions(o1).items():
                for d2, s2 in both_directions(o2).items():
                    if d1 != d2:
                        continue  # same convention for both steps
                    yield ({"transposition": "double_rotation", "widths": [w1, w2],
                            "clockwise": [cw1, cw2], "direction": d1}, compose(s1, s2))


# ------------------------------------------------------------------ sculpture geometry (hypothesis 2)
#
# On the sculpture K4 does not start a fresh grid: its first four letters, OBKR,
# end the row that holds the end of K3, then three rows of 31 letters follow
# (kryptos/k4.py). If that row is 31 wide too, K4 starts 27 cells into a 4 x 31
# grid (27 + 97 = 124 = 4 x 31). The row width there is not confirmed, so the
# offset grids cover every width 2-48 and every starting offset 1..width-1; the
# sculpture case is width 31, offset 27. Offset 0 is the ordinary route family.

SCULPTURE_WIDTH, SCULPTURE_OFFSET = 31, 27


def offset_grid_sources(length, widths=range(2, 49), offsets=None):
    """Routes through a grid in which the text starts ``offset`` cells into the
    first row; both directions. Duplicate permutations within a width are dropped."""
    for width in widths:
        seen = set()
        for offset in (offsets if offsets is not None else range(1, width)):
            for name, order in route_orders(length, width, offset).items():
                for direction, src in both_directions(order).items():
                    key = tuple(src)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield ({"transposition": "offset_grid", "route": name, "width": width, "grid_offset": offset,
                            "direction": direction}, src)


def offset_double_rotation_sources(length, first_width, offsets=None, widths2=range(2, 25)):
    """K3-style double rotation whose FIRST grid starts ``offset`` cells in
    (the text continuing a previous one); the second grid is a fresh one."""
    for offset in (offsets if offsets is not None else range(1, first_width)):
        routes = route_orders(length, first_width, offset)
        for cw1 in (True, False):
            o1 = routes["columns_up"] if cw1 else routes["columns_right_to_left_down"]
            for w2 in widths2:
                for cw2 in (True, False):
                    o2 = rotation_order(length, w2, cw2)
                    for d, s1 in both_directions(o1).items():
                        s2 = both_directions(o2)[d]
                        yield ({"transposition": "offset_double_rotation", "widths": [first_width, w2],
                                "grid_offset": offset, "clockwise": [cw1, cw2], "direction": d}, compose(s1, s2))


def segment_sources(segments, allow_reverse=True, first=None):
    """Reorder (and optionally reverse) W-delimited segments.
    ``segments`` are (start, length) in the ciphertext; yields src over the
    concatenation of all segment letters."""
    count = len(segments)
    for order in permutations(range(count)):
        if first is not None and order[0] != first:
            continue
        for flips in (product((False, True), repeat=count) if allow_reverse else [(False,) * count]):
            src = []
            for index in order:
                start, size = segments[index]
                positions = list(range(start, start + size))
                src.extend(reversed(positions) if flips[index] else positions)
            yield {"transposition": "w_segments", "segment_order": list(order),
                   "reversed": [i for i in range(count) if flips[i]]}, src


# ------------------------------------------------------------------ other classic (ACA) transpositions
# Each returns the READING order: ciphertext[k] = plaintext[order[k]]; both_directions()
# turns it into the src arrays of the engines (the transposition and its inverse).

def myszkowski_order(length, ranks):
    """Myszkowski: plaintext written in rows under the key; columns are taken in key
    order, but columns whose key letters are equal are read together, row by row,
    left to right. ``ranks`` is the keyword as letter ranks (equal letters equal ranks)."""
    width = len(ranks)
    order = []
    for rank in sorted(set(ranks)):
        columns = [c for c in range(width) if ranks[c] == rank]
        for row in range((length + width - 1) // width):
            order.extend(row * width + c for c in columns if row * width + c < length)
    return order


def amsco_cells(length, width, first, row_rule):
    """AMSCO grid: cells of 1 and 2 letters alternating along each row, written row by
    row. ``first`` (1 or 2) is the size of the first cell; ``row_rule`` 'continue' keeps
    alternating across row ends, 'alternate_rows' starts each row with the other size
    than the row above (both conventions are in use). Returns [row][column] -> plaintext
    positions of that cell."""
    rows, position, size, row_start = [], 0, first, first
    while position < length:
        if row_rule == "alternate_rows":
            size = row_start
        row = []
        for _ in range(width):
            if position >= length:
                break
            row.append(list(range(position, min(position + size, length))))
            position += size
            size = 3 - size
        rows.append(row)
        row_start = 3 - row_start
    return rows


def amsco_order(length, column_order, first=1, row_rule="continue"):
    """AMSCO reading order: columns in key order, cells top to bottom."""
    rows = amsco_cells(length, len(column_order), first, row_rule)
    order = []
    for column in column_order:
        for row in rows:
            if column < len(row):
                order.extend(row[column])
    return order


def redefence_order(length, rail_order):
    """Redefence: rail fence zigzag, rails read in the order given (a permutation of the rails)."""
    rails = len(rail_order)
    cycle = 2 * (rails - 1)
    rail_of = [min(i % cycle, cycle - i % cycle) for i in range(length)]
    return [i for rail in rail_order for i in range(length) if rail_of[i] == rail]


def redefence_sources(length, rails_range=range(3, 9)):
    from itertools import permutations
    for rails in rails_range:
        for rail_order in permutations(range(rails)):
            if list(rail_order) == sorted(rail_order):
                continue      # the plain rail fence (already searched)
            for direction, src in both_directions(redefence_order(length, rail_order)).items():
                yield {"transposition": "redefence", "rails": rails, "rail_order": list(rail_order),
                       "direction": direction}, src
