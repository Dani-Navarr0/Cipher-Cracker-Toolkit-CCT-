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

The *_order functions build ONE reading order (one-shot: planting test
ciphertexts, describing a result). The *_sources enumerators return a
native.screens.Sources: the C engine (screens_transposition.c) generates and
scores every permutation; iterating it yields the (info, src) pairs, generated
in C, in the order documented here. tests/test_c_screens.py checks the C
generators against these order functions.
"""
from itertools import permutations, product

from native.screens import DOUBLE_ROTATION, ROUTE, ZIGZAG, Sources


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
    """Every route of route_orders for each width, both directions (C-generated)."""
    sources = Sources(length)
    for width in widths:
        sources.add(ROUTE, (width, 0), key=[0], meta=("route", width, [0]))
    return sources


def rail_fence_order(length, rails):
    cycle = 2 * (rails - 1)
    rail_of = [min(i % cycle, cycle - i % cycle) for i in range(length)]
    return [i for rail in range(rails) for i in range(length) if rail_of[i] == rail]


def rail_fence_sources(length, rails_range=range(2, 49)):
    sources = Sources(length)
    for rails in rails_range:
        sources.add(ZIGZAG, (rails, 0), meta=("rail_fence", rails))
    return sources


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
    """compose(s1, s2) of two rotation steps, the same direction for both steps."""
    sources = Sources(length)
    for w1, w2 in product(widths, repeat=2):
        for cw1, cw2 in product((True, False), repeat=2):
            sources.add(DOUBLE_ROTATION, (w1, 0, w2, int(cw1) | int(cw2) << 1),
                        meta=("double_rotation", w1, w2, cw1, cw2))
    return sources


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
    first row; both directions. Duplicate permutations within a width are dropped
    (in C)."""
    sources = Sources(length)
    for width in widths:
        chosen = list(offsets if offsets is not None else range(1, width))
        if chosen:
            sources.add(ROUTE, (width, 1), key=chosen, meta=("offset_grid", width, chosen))
    return sources


def offset_double_rotation_sources(length, first_width, offsets=None, widths2=range(2, 25)):
    """K3-style double rotation whose FIRST grid starts ``offset`` cells in
    (the text continuing a previous one); the second grid is a fresh one."""
    sources = Sources(length)
    for offset in (offsets if offsets is not None else range(1, first_width)):
        for cw1 in (True, False):
            for w2 in widths2:
                for cw2 in (True, False):
                    sources.add(DOUBLE_ROTATION, (first_width, offset, w2, int(cw1) | int(cw2) << 1),
                                meta=("offset_double_rotation", first_width, w2, cw1, cw2, offset))
    return sources


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
    sources = Sources(length)
    for rails in rails_range:
        for rail_order in permutations(range(rails)):
            if list(rail_order) == sorted(rail_order):
                continue      # the plain rail fence (already searched)
            sources.add(ZIGZAG, (rails, 0), key=rail_order, meta=("redefence", rails, rail_order))
    return sources
