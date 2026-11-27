/* Keyless and irregular transposition screens (tools 42, 41, 43 and the analyzer, tool 1):
 * generate permutation families and score every reading, forward and on the
 * reversed text, with annealing.Fitness.
 *
 * A "source" (src) is a permutation with plaintext[i] = text[src[i]]; on the
 * reversed text plaintext[i] = text[n - 1 - src[i]]. Most families define a
 * READING order (ciphertext[k] = plaintext[order[k]]); each reading order gives
 * two sources, as transposition_families.both_directions:
 *   direction 0 "read"  = the inverse of the order,
 *   direction 1 "write" = the order itself.
 *
 * Records (REC_FIELDS int32 each): family, p1, p2, p3, p4, direction mask
 * (bit 0 read, bit 1 write; 0 = both), key offset, key length (into `keys`).
 *   F_EXPLICIT    key = the src itself (any length, values 0..n-1); 1 source
 *   F_ROUTE       p1 width, p2 dedup (drop repeated sources within the record),
 *                 p3 route mask (bit r = route r, 0 = all 11); key = grid offsets;
 *                 sub = ((offset index * 11) + route) * 2 + direction
 *   F_ZIGZAG      p1 rails, p2 starting offset; key = rail reading order (empty =
 *                 0, 1, 2, ...): rail fence (rail_fence.rail_order) and redefence
 *   F_DOUBLE_ROT  p1 first width, p2 first grid offset, p3 second width,
 *                 p4 bit 0 / bit 1 = first / second rotation clockwise
 *   F_MYSZKOWSKI  key = column ranks (equal ranks are read together)
 *   F_AMSCO       key = column order; p1 cell-rule mask (bit c, 0 = all four):
 *                 c = 0 (1, continue), 1 (1, alternate_rows), 2 (2, continue),
 *                 3 (2, alternate_rows); sub = c * 2 + direction
 *   F_COLUMNAR    p1 width, p2 layout (0 write_rows_read_cols, 1 write_cols_read_cols,
 *                 2 write_rows_read_rows, 3 write_cols_read_rows), key = column order
 *                 (empty = identity); the src of transposition_core.make_permuter
 * Every source has the id (record << ID_SHIFT) | (sub << 1) | reversed (a
 * 24-bit sub field; a record with more subs is rejected), so ids sort in
 * the order the Python generators yielded them (ties keep the first, like a
 * stable sort). Symbols >= 26 are carried but not scored (Scytale keeps
 * punctuation in place).
 */
#include "cct_common.h"

#define REC_FIELDS 8
#define F_EXPLICIT 0
#define F_ROUTE 1
#define F_ZIGZAG 2
#define F_DOUBLE_ROT 3
#define F_MYSZKOWSKI 4
#define F_AMSCO 5
#define F_COLUMNAR 6
#define NROUTES 11
#define ROUTE_COLUMNS_UP 3
#define ROUTE_RTL_DOWN 5
#define ERR_SOURCE -2      /* an explicit source holds a position outside 0..n-1 */
#define ERR_CAPACITY -3    /* output arrays too small */
#define ERR_MEMORY -4
#define ERR_RECORD -5      /* a record has more sources than its id field holds */
#define ID_SHIFT 25
#define SUB_LIMIT (1 << (ID_SHIFT - 1))
#define SUB_OF(id) ((int)(((id) >> 1) & (SUB_LIMIT - 1)))

typedef struct {
    int n, dim;
    int32_t *order, *inv, *order2, *inv2, *rank_tmp;
    int32_t *cell_start, *cell_size, *row_first, *row_len;
    int32_t *stamp;
    int32_t stamp_value;
} Work;

/* dim: at least n, every key length, rail count and columnar width of the records. */
static int work_init(Work *w, int n, int dim) {
    size_t m = (size_t)(dim > n ? dim : n) + 1;
    w->n = n; w->dim = (int)m; w->stamp_value = 0;
    w->order = malloc(sizeof(int32_t) * m); w->inv = malloc(sizeof(int32_t) * m);
    w->order2 = malloc(sizeof(int32_t) * m); w->inv2 = malloc(sizeof(int32_t) * m);
    w->cell_start = malloc(sizeof(int32_t) * m); w->cell_size = malloc(sizeof(int32_t) * m);
    w->row_first = malloc(sizeof(int32_t) * m); w->row_len = malloc(sizeof(int32_t) * m);
    w->rank_tmp = malloc(sizeof(int32_t) * m); w->stamp = calloc(m, sizeof(int32_t));
    return w->order && w->inv && w->order2 && w->inv2 && w->cell_start && w->cell_size && w->row_first
           && w->row_len && w->rank_tmp && w->stamp;
}

static void work_free(Work *w) {
    free(w->order); free(w->inv); free(w->order2); free(w->inv2); free(w->cell_start); free(w->cell_size);
    free(w->row_first); free(w->row_len); free(w->rank_tmp); free(w->stamp);
}

/* ---------------------------------------------------------------- reading orders */

/* transposition_families._cells: plaintext position of grid cell (r, c), or -1. */
static inline int grid_cell(int r, int c, int width, int offset, int n) {
    int v = r * width + c - offset;
    return (v >= 0 && v < n) ? v : -1;
}

#define EMIT(v) do { int v_ = (v); if (v_ >= 0) out[k++] = v_; } while (0)
#define CELL(r, c) (transposed ? grid_cell((c), (r), width, offset, n) : grid_cell((r), (c), width, offset, n))

/* transposition_families._spiral over a rows x cols grid (transposed: the grid's transpose). */
static int spiral(int n, int width, int offset, int rows, int cols, int transposed, int32_t *out, int k) {
    int top = 0, bottom = rows - 1, left = 0, right = cols - 1;
    while (top <= bottom && left <= right) {
        for (int c = left; c <= right; c++) EMIT(CELL(top, c));
        for (int r = top + 1; r <= bottom; r++) EMIT(CELL(r, right));
        if (top < bottom) for (int c = right - 1; c >= left; c--) EMIT(CELL(bottom, c));
        if (left < right) for (int r = bottom - 1; r > top; r--) EMIT(CELL(r, left));
        top++; bottom--; left++; right--;
    }
    return k;
}

/* transposition_families.route_orders, route number `route` in its dict order:
 * rows_snake, rows_right_to_left, columns_down, columns_up, columns_snake,
 * columns_right_to_left_down, columns_right_to_left_up, diagonals,
 * diagonals_snake, spiral_clockwise, spiral_counterclockwise.
 * Returns the number of positions written (n for every valid grid). */
static int route_order(int n, int width, int offset, int route, int32_t *out) {
    if (width < 1 || offset < 0) return -1;
    int rows = (n + offset + width - 1) / width, k = 0;
    switch (route) {
    case 0: for (int r = 0; r < rows; r++) {
                if (r % 2 == 0) for (int c = 0; c < width; c++) EMIT(grid_cell(r, c, width, offset, n));
                else for (int c = width - 1; c >= 0; c--) EMIT(grid_cell(r, c, width, offset, n));
            } break;
    case 1: for (int r = 0; r < rows; r++) for (int c = width - 1; c >= 0; c--) EMIT(grid_cell(r, c, width, offset, n));
            break;
    case 2: for (int c = 0; c < width; c++) for (int r = 0; r < rows; r++) EMIT(grid_cell(r, c, width, offset, n));
            break;
    case 3: for (int c = 0; c < width; c++) for (int r = rows - 1; r >= 0; r--) EMIT(grid_cell(r, c, width, offset, n));
            break;
    case 4: for (int c = 0; c < width; c++) {
                if (c % 2 == 0) for (int r = 0; r < rows; r++) EMIT(grid_cell(r, c, width, offset, n));
                else for (int r = rows - 1; r >= 0; r--) EMIT(grid_cell(r, c, width, offset, n));
            } break;
    case 5: for (int c = width - 1; c >= 0; c--) for (int r = 0; r < rows; r++) EMIT(grid_cell(r, c, width, offset, n));
            break;
    case 6: for (int c = width - 1; c >= 0; c--) for (int r = rows - 1; r >= 0; r--) EMIT(grid_cell(r, c, width, offset, n));
            break;
    case 7: for (int d = 0; d < rows + width - 1; d++)
                for (int r = 0; r < rows; r++) if (d - r >= 0 && d - r < width) EMIT(grid_cell(r, d - r, width, offset, n));
            break;
    case 8: for (int d = 0; d < rows + width - 1; d++) {
                if (d % 2) { for (int r = 0; r < rows; r++) if (d - r >= 0 && d - r < width) EMIT(grid_cell(r, d - r, width, offset, n)); }
                else { for (int r = rows - 1; r >= 0; r--) if (d - r >= 0 && d - r < width) EMIT(grid_cell(r, d - r, width, offset, n)); }
            } break;
    case 9: k = spiral(n, width, offset, rows, width, 0, out, k); break;
    case 10: k = spiral(n, width, offset, width, rows, 1, out, k); break;
    default: return -1;
    }
    return k;
}

/* Zig-zag (rail fence) reading order: positions grouped by rail, rails in
 * `rail_order` (NULL = 0, 1, 2, ...), positions ascending within a rail;
 * rail_fence.rail_order (with its offset) and transposition_families.redefence_order. */
static void zigzag_order(int n, int rails, int offset, const int32_t *rail_order, int32_t *out, Work *w) {
    if (rails < 2) { for (int i = 0; i < n; i++) out[i] = i; return; }
    int cycle = 2 * (rails - 1);
    int32_t *row = w->order2, *start = w->row_first, *slot = w->row_len;   /* scratch */
    for (int r = 0; r <= rails; r++) start[r] = 0;
    for (int p = 0; p < n; p++) {
        int phase = ((p + offset) % cycle + cycle) % cycle;
        row[p] = phase < rails ? phase : cycle - phase;
        start[row[p]]++;
    }
    /* slot[rail] = first output index of that rail */
    int total = 0;
    for (int j = 0; j < rails; j++) {
        int rail = rail_order ? rail_order[j] : j;
        slot[rail] = total;
        total += start[rail];
    }
    for (int p = 0; p < n; p++) out[slot[row[p]]++] = p;
}

/* transposition_families.myszkowski_order */
static void myszkowski_order(int n, const int32_t *ranks, int width, int32_t *out, Work *w) {
    int32_t *distinct = w->rank_tmp;
    int nd = 0, k = 0, rows = (n + width - 1) / width;
    for (int c = 0; c < width; c++) {          /* sorted distinct ranks (insertion) */
        int v = ranks[c], j = 0, seen = 0;
        for (j = 0; j < nd; j++) if (distinct[j] == v) { seen = 1; break; }
        if (seen) continue;
        j = nd++;
        while (j > 0 && distinct[j - 1] > v) { distinct[j] = distinct[j - 1]; j--; }
        distinct[j] = v;
    }
    for (int d = 0; d < nd; d++)
        for (int row = 0; row < rows; row++)
            for (int c = 0; c < width; c++)
                if (ranks[c] == distinct[d] && row * width + c < n) out[k++] = row * width + c;
}

/* transposition_families.amsco_cells + amsco_order */
static void amsco_order(int n, const int32_t *column_order, int width, int first, int alternate_rows, int32_t *out,
                        Work *w) {
    int position = 0, size = first, row_start = first, nrows = 0, ncells = 0, k = 0;
    while (position < n) {
        if (alternate_rows) size = row_start;
        w->row_first[nrows] = ncells;
        int len = 0;
        for (int c = 0; c < width; c++) {
            if (position >= n) break;
            w->cell_start[ncells] = position;
            w->cell_size[ncells] = (position + size <= n) ? size : n - position;
            ncells++; len++;
            position += size;
            size = 3 - size;
        }
        w->row_len[nrows++] = len;
        row_start = 3 - row_start;
    }
    for (int j = 0; j < width; j++) {
        int column = column_order[j];
        for (int r = 0; r < nrows; r++) {
            if (column < w->row_len[r]) {
                int cell = w->row_first[r] + column;
                for (int q = 0; q < w->cell_size[cell]; q++) out[k++] = w->cell_start[cell] + q;
            }
        }
    }
}

/* transposition_core.make_permuter(n, width, layout)(text, key): src directly. */
static void columnar_src(int n, int width, int layout, const int32_t *key, int32_t *src, Work *w) {
    int height = (n + width - 1) / width;
    int remainder = n % width ? n % width : width;
    int full_rows = remainder == width ? height : height - 1;
    int full_end = full_rows * width, partial_base = (height - 1) * width;
    int32_t *pos = w->order2, *ppos = w->inv2;       /* scratch, width <= n */
#define KEY(j) (key ? key[j] : (j))
#define COL_LEN(c) ((c) < remainder ? height : height - 1)
    if (layout == 0 || layout == 1) {
        int start = 0;
        for (int j = 0; j < width; j++) { pos[KEY(j)] = start; start += COL_LEN(KEY(j)); }
        int offset = 0;
        for (int c = 0; c < width; c++) {
            int len = COL_LEN(c);
            for (int q = 0; q < len; q++) {
                if (layout == 0) src[c + q * width] = pos[c] + q;
                else src[offset + q] = pos[c] + q;
            }
            offset += len;
        }
    } else {
        for (int j = 0; j < width; j++) { pos[KEY(j)] = j; ppos[KEY(j)] = 0; }
        if (remainder != width) {
            int p = 0;
            for (int j = 0; j < width; j++) if (KEY(j) < remainder) ppos[KEY(j)] = p++;
        }
        int offset = 0;
        for (int c = 0; c < width; c++) {
            if (layout == 2) {
                for (int q = 0; q < full_rows; q++) src[c + q * width] = pos[c] + q * width;
                if (remainder != width && c < remainder) src[partial_base + c] = partial_base + ppos[c];
            } else {
                for (int q = 0; q < full_rows; q++) src[offset + q] = pos[c] + q * width;
                offset += full_rows;
                if (remainder != width && c < remainder) src[offset++] = partial_base + ppos[c];
            }
        }
        (void)full_end;
    }
#undef KEY
#undef COL_LEN
}

static void invert(const int32_t *order, int n, int32_t *inv) { for (int k = 0; k < n; k++) inv[order[k]] = k; }

static int64_t max_subs(const int32_t *rec) {
    switch (rec[0]) {
    case F_ROUTE: return (int64_t)rec[7] * NROUTES * 2;
    case F_ZIGZAG: case F_DOUBLE_ROT: case F_MYSZKOWSKI: return 2;
    case F_AMSCO: return 8;
    case F_COLUMNAR: case F_EXPLICIT: return 1;
    default: return 0;
    }
}

static inline int dir_ok(const int32_t *rec, int d) { return rec[5] == 0 || (rec[5] >> d) & 1; }

/* The source number `sub` of a record into src (length *len). Returns 1, 0 when
 * that sub does not exist / is masked out, or ERR_SOURCE. `perm` is set to 1
 * when the source is known to be a permutation of 0..n-1. */
static int family_src(const int32_t *rec, const int32_t *keys, int n, int sub, int32_t *src, int *len, int *perm,
                      Work *w) {
    const int32_t *key = keys + rec[6];
    int keylen = rec[7];
    *len = n; *perm = 1;
    switch (rec[0]) {
    case F_EXPLICIT: {
        if (sub) return 0;
        *len = keylen;
        if (++w->stamp_value == INT32_MAX) { memset(w->stamp, 0, sizeof(int32_t) * (n > 0 ? n : 1)); w->stamp_value = 1; }
        int distinct = 1;
        for (int i = 0; i < keylen; i++) {
            int p = key[i];
            if (p < 0 || p >= n) return ERR_SOURCE;
            if (w->stamp[p] == w->stamp_value) distinct = 0;
            w->stamp[p] = w->stamp_value;
            src[i] = p;
        }
        *perm = distinct && keylen == n;
        return 1;
    }
    case F_ROUTE: {
        int d = sub & 1, t = sub >> 1, route = t % NROUTES, oi = t / NROUTES;
        if (oi >= keylen || !dir_ok(rec, d) || (rec[3] && !((rec[3] >> route) & 1))) return 0;
        if (route_order(n, rec[1], key[oi], route, w->order) != n) return 0;
        if (d) memcpy(src, w->order, sizeof(int32_t) * n); else invert(w->order, n, src);
        return 1;
    }
    case F_ZIGZAG: {
        if (sub > 1 || !dir_ok(rec, sub)) return 0;
        zigzag_order(n, rec[1], rec[2], keylen ? key : NULL, w->order, w);
        if (sub) memcpy(src, w->order, sizeof(int32_t) * n); else invert(w->order, n, src);
        return 1;
    }
    case F_DOUBLE_ROT: {
        if (sub > 1 || !dir_ok(rec, sub)) return 0;
        int cw1 = rec[4] & 1, cw2 = (rec[4] >> 1) & 1;
        if (route_order(n, rec[1], rec[2], cw1 ? ROUTE_COLUMNS_UP : ROUTE_RTL_DOWN, w->order) != n) return 0;
        if (route_order(n, rec[3], 0, cw2 ? ROUTE_COLUMNS_UP : ROUTE_RTL_DOWN, w->inv) != n) return 0;
        /* compose(s1, s2): src[i] = s2[s1[i]] with s = the order (write) or its inverse (read) */
        if (sub) {
            for (int i = 0; i < n; i++) src[i] = w->inv[w->order[i]];
        } else {
            invert(w->order, n, w->order2);           /* s1 */
            invert(w->inv, n, w->inv2);               /* s2 */
            for (int i = 0; i < n; i++) src[i] = w->inv2[w->order2[i]];
        }
        return 1;
    }
    case F_MYSZKOWSKI: {
        if (sub > 1 || !dir_ok(rec, sub) || keylen < 1) return 0;
        myszkowski_order(n, key, keylen, w->order, w);
        if (sub) memcpy(src, w->order, sizeof(int32_t) * n); else invert(w->order, n, src);
        return 1;
    }
    case F_AMSCO: {
        int d = sub & 1, combo = sub >> 1;
        if (combo > 3 || !dir_ok(rec, d) || (rec[1] && !((rec[1] >> combo) & 1)) || keylen < 1) return 0;
        amsco_order(n, key, keylen, combo < 2 ? 1 : 2, combo & 1, w->order, w);
        if (d) memcpy(src, w->order, sizeof(int32_t) * n); else invert(w->order, n, src);
        return 1;
    }
    case F_COLUMNAR: {
        if (sub || rec[1] < 1 || rec[2] < 0 || rec[2] > 3) return 0;
        columnar_src(n, rec[1], rec[2], keylen ? key : NULL, src, w);
        return 1;
    }
    default: return 0;
    }
}

/* Fitness of the reading: annealing.Fitness with the (fixed) entropy factor, or
 * the factor recomputed from the plaintext when the source is not a permutation. */
static double score_src(const uint8_t *text, int n, const int32_t *src, int len, int rev, int perm, uint8_t *buf,
                        const uint8_t *scores, int size, double factor, double weight) {
    int m = 0;
    if (rev) { for (int i = 0; i < len; i++) { uint8_t c = text[n - 1 - src[i]]; if (c < 26) buf[m++] = c; } }
    else { for (int i = 0; i < len; i++) { uint8_t c = text[src[i]]; if (c < 26) buf[m++] = c; } }
    int count = m - size + 1;
    if (count <= 0) return -9999.0;
    double f = perm ? factor : cct_entropy_factor(buf, m, weight);
    return (double)cct_total(buf, m, scores, size) / count * f;
}

static uint64_t hash_src(const int32_t *src, int len) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < len; i++) { h ^= (uint32_t)src[i]; h *= 1099511628211ULL; }
    return h;
}

/* maxlen: longest source; dim: scratch size (see work_init). */
static void scan_sizes(const int32_t *records, int32_t nrec, int n, int *maxlen, int *dim) {
    *maxlen = n; *dim = n;
    for (int i = 0; i < nrec; i++) {
        const int32_t *rec = records + (size_t)i * REC_FIELDS;
        if (rec[7] > *dim) *dim = rec[7];
        if ((rec[0] == F_ZIGZAG || rec[0] == F_COLUMNAR) && rec[1] > *dim) *dim = rec[1];
        if (rec[0] == F_EXPLICIT && rec[7] > *maxlen) *maxlen = rec[7];
    }
}

/* Upper bound of the number of sources of the records. */
EXPORT int64_t cct_screens_max_sources(const int32_t *records, int32_t nrec) {
    int64_t total = 0;
    for (int i = 0; i < nrec; i++) total += max_subs(records + (size_t)i * REC_FIELDS);
    return total;
}

/* Score every source of the records (forward when rev_mask bit 0, reversed
 * text when bit 1). top > 0: keep the best `top` (score descending, then id)
 * in out_scores/out_ids, sorted; top <= 0: write every score in order (up to
 * `capacity`). *out_count = entries written. Returns the number of distinct
 * sources tested, or a negative error code. weight: the entropy exponent, used
 * for explicit sources that are not permutations. */
EXPORT int64_t cct_screens_run(const uint8_t *text, int32_t n, const int32_t *records, int32_t nrec, int64_t rec_base,
                               const int32_t *keys, int32_t rev_mask, const uint8_t *scores, int32_t size,
                               double factor, double weight, int32_t top, double *out_scores, int64_t *out_ids,
                               int32_t *out_count, int64_t capacity) {
    int maxlen, dim;
    scan_sizes(records, nrec, n, &maxlen, &dim);
    Work w;
    int32_t *src = malloc(sizeof(int32_t) * (maxlen > 0 ? maxlen : 1));
    uint8_t *buf = malloc((size_t)(maxlen > 0 ? maxlen : 1));
    int32_t *store = NULL;
    uint64_t *hashes = NULL;
    int64_t store_cap = 0, tested = 0, count = 0, result = 0;
    if (!work_init(&w, n, dim) || !src || !buf) { result = ERR_MEMORY; goto done; }
    for (int i = 0; i < nrec; i++) {
        const int32_t *rec = records + (size_t)i * REC_FIELDS;
        int64_t subs = max_subs(rec); int dedup = rec[0] == F_ROUTE && rec[2], stored = 0;
        if (subs > SUB_LIMIT || rec[7] < 0) { result = ERR_RECORD; goto done; }
        if (dedup && subs > store_cap) {
            free(store); free(hashes);
            store = malloc(sizeof(int32_t) * (size_t)subs * (n > 0 ? n : 1));
            hashes = malloc(sizeof(uint64_t) * (size_t)subs);
            store_cap = subs;
            if (!store || !hashes) { result = ERR_MEMORY; goto done; }
        }
        for (int sub = 0; sub < subs; sub++) {
            int len, perm;
            int ok = family_src(rec, keys, n, sub, src, &len, &perm, &w);
            if (ok < 0) { result = ok; goto done; }
            if (!ok) continue;
            if (dedup) {
                uint64_t h = hash_src(src, len);
                int duplicate = 0;
                for (int s = 0; s < stored && !duplicate; s++)
                    if (hashes[s] == h && !memcmp(store + (size_t)s * n, src, sizeof(int32_t) * len)) duplicate = 1;
                if (duplicate) continue;
                hashes[stored] = h;
                memcpy(store + (size_t)stored * n, src, sizeof(int32_t) * len);
                stored++;
            }
            tested++;
            for (int rev = 0; rev < 2; rev++) {
                if (!((rev_mask >> rev) & 1)) continue;
                double score = score_src(text, n, src, len, rev, perm, buf, scores, size, factor, weight);
                int64_t id = ((rec_base + i) << ID_SHIFT) | ((int64_t)sub << 1) | rev;
                if (top <= 0) {
                    if (count >= capacity) { result = ERR_CAPACITY; goto done; }
                    out_scores[count] = score; out_ids[count] = id; count++;
                } else if (count < top || score > out_scores[count - 1]) {
                    /* ids rise as we go, so an equal score never displaces an earlier entry */
                    int j = count < top ? (int)count++ : top - 1;
                    while (j > 0 && score > out_scores[j - 1]) {
                        out_scores[j] = out_scores[j - 1]; out_ids[j] = out_ids[j - 1]; j--;
                    }
                    out_scores[j] = score; out_ids[j] = id;
                }
            }
        }
    }
    result = tested;
done:
    *out_count = (int32_t)count;
    work_free(&w); free(src); free(buf); free(store); free(hashes);
    return result;
}

/* Every source of the records (duplicates dropped as in cct_screens_run), each
 * n positions, with its id (reversed bit 0). Explicit records are not allowed.
 * Returns the count, or a negative error code. */
EXPORT int64_t cct_screens_sources(int32_t n, const int32_t *records, int32_t nrec, int64_t rec_base,
                                   const int32_t *keys, int32_t *out_src, int64_t *out_ids, int64_t capacity) {
    int maxlen, dim;
    scan_sizes(records, nrec, n, &maxlen, &dim);
    Work w;
    int64_t count = 0, result = 0;
    if (!work_init(&w, n, dim)) { work_free(&w); return ERR_MEMORY; }
    for (int i = 0; i < nrec; i++) {
        const int32_t *rec = records + (size_t)i * REC_FIELDS;
        if (rec[0] == F_EXPLICIT) { result = ERR_SOURCE; goto done; }
        int64_t subs = max_subs(rec); int dedup = rec[0] == F_ROUTE && rec[2];
        if (subs > SUB_LIMIT || rec[7] < 0) { result = ERR_RECORD; goto done; }
        int64_t first = count;
        for (int sub = 0; sub < subs; sub++) {
            if (count >= capacity) { result = ERR_CAPACITY; goto done; }
            int len, perm;
            int32_t *src = out_src + (size_t)count * n;
            int ok = family_src(rec, keys, n, sub, src, &len, &perm, &w);
            if (ok < 0) { result = ok; goto done; }
            if (!ok) continue;
            if (dedup) {
                int duplicate = 0;
                for (int64_t s = first; s < count && !duplicate; s++)
                    if (!memcmp(out_src + (size_t)s * n, src, sizeof(int32_t) * n)) duplicate = 1;
                if (duplicate) continue;
            }
            out_ids[count++] = ((rec_base + i) << ID_SHIFT) | ((int64_t)sub << 1);
        }
    }
    result = count;
done:
    work_free(&w);
    return result;
}

/* The readings (text permuted, every symbol kept) for the given ids, n bytes
 * each; ids index `records` from 0. Returns 0, or a negative error code. */
EXPORT int32_t cct_screens_plain(const uint8_t *text, int32_t n, const int32_t *records, int32_t nrec,
                                 const int32_t *keys, const int64_t *ids, int32_t count, uint8_t *out) {
    int maxlen, dim;
    scan_sizes(records, nrec, n, &maxlen, &dim);
    Work w;
    int32_t *src = malloc(sizeof(int32_t) * (n > 0 ? n : 1));
    int32_t result = 0;
    if (!work_init(&w, n, dim) || !src) { result = ERR_MEMORY; goto done; }
    for (int k = 0; k < count; k++) {
        int64_t rec_index = ids[k] >> ID_SHIFT;
        int sub = SUB_OF(ids[k]), rev = (int)(ids[k] & 1), len, perm;
        if (rec_index < 0 || rec_index >= nrec) { result = ERR_SOURCE; goto done; }
        const int32_t *rec = records + (size_t)rec_index * REC_FIELDS;
        if (rec[0] == F_EXPLICIT) { result = ERR_SOURCE; goto done; }
        int ok = family_src(rec, keys, n, sub, src, &len, &perm, &w);
        if (ok <= 0) { result = ok < 0 ? ok : ERR_SOURCE; goto done; }
        uint8_t *row = out + (size_t)k * n;
        for (int i = 0; i < n; i++) row[i] = rev ? text[n - 1 - src[i]] : text[src[i]];
    }
done:
    work_free(&w); free(src);
    return result;
}

/* ---------------------------------------------------------------- dictionary keywords */

typedef struct { int32_t *slots; uint32_t mask; } KeySet;    /* record indexes, -1 = empty */

static uint64_t hash_key(const int32_t *key, int len) {
    uint64_t h = 1469598103934665603ULL ^ (uint64_t)len;
    for (int i = 0; i < len; i++) { h ^= (uint32_t)key[i]; h *= 1099511628211ULL; }
    return h ^ (h >> 29);
}

/* Index of the record holding the same key, or the empty slot to use (returned as -2 - slot). */
static int64_t keyset_find(const KeySet *set, const int32_t *fields, const int32_t *keys, const int32_t *key, int len) {
    uint32_t slot = (uint32_t)hash_key(key, len) & set->mask;
    for (;;) {
        int32_t rec = set->slots[slot];
        if (rec < 0) return -2 - (int64_t)slot;
        const int32_t *f = fields + (size_t)rec * REC_FIELDS;
        if (f[7] == len && !memcmp(keys + f[6], key, sizeof(int32_t) * len)) return rec;
        slot = (slot + 1) & set->mask;
    }
}

/* transposition_screen.keyword_sources: for every word (characters as code
 * points, `lengths` per word) with 3 <= length < n // 2: a Myszkowski record
 * (column ranks, equal letters equal ranks) when the word repeats a letter and
 * its rank pattern is new, then an AMSCO record (columns in alphabetical order
 * of their letters, ties left to right) when that order is new. out_word: the
 * word index of each record. Capacity: 2 records and 2 x length key values per
 * word. Returns the number of records, or a negative error code. */
EXPORT int64_t cct_screens_keyword_records(const uint32_t *chars, const int32_t *lengths, int32_t count, int32_t n,
                                           int32_t *out_fields, int32_t *out_keys, int32_t *out_word) {
    int64_t total_chars = 0, nrec = 0, nkeys = 0, result = 0;
    int maxlen = 1;
    for (int w = 0; w < count; w++) { total_chars += lengths[w]; if (lengths[w] > maxlen) maxlen = lengths[w]; }
    uint32_t cap = 16;
    while (cap < (uint64_t)count * 4 + 16) cap <<= 1;
    KeySet mysz = {malloc(sizeof(int32_t) * cap), cap - 1}, amsco = {malloc(sizeof(int32_t) * cap), cap - 1};
    int32_t *ranks = malloc(sizeof(int32_t) * maxlen), *order = malloc(sizeof(int32_t) * maxlen);
    uint32_t *distinct = malloc(sizeof(uint32_t) * maxlen);
    if (!mysz.slots || !amsco.slots || !ranks || !order || !distinct) { result = ERR_MEMORY; goto done; }
    memset(mysz.slots, 0xFF, sizeof(int32_t) * cap);
    memset(amsco.slots, 0xFF, sizeof(int32_t) * cap);
    const uint32_t *word = chars;
    for (int w = 0; w < count; word += lengths[w], w++) {
        int len = lengths[w];
        if (len < 3 || len >= n / 2) continue;
        /* ranks: index of each letter among the word's sorted distinct letters */
        int nd = 0;
        for (int i = 0; i < len; i++) {
            uint32_t v = word[i];
            int j, seen = 0;
            for (j = 0; j < nd; j++) if (distinct[j] == v) { seen = 1; break; }
            if (seen) continue;
            j = nd++;
            while (j > 0 && distinct[j - 1] > v) { distinct[j] = distinct[j - 1]; j--; }
            distinct[j] = v;
        }
        for (int i = 0; i < len; i++) {
            int r = 0;
            while (distinct[r] != word[i]) r++;
            ranks[i] = r;
        }
        if (nd < len) {
            int64_t found = keyset_find(&mysz, out_fields, out_keys, ranks, len);
            if (found <= -2) {
                mysz.slots[-2 - found] = (int32_t)nrec;
                int32_t *f = out_fields + (size_t)nrec * REC_FIELDS;
                f[0] = F_MYSZKOWSKI; f[1] = f[2] = f[3] = f[4] = f[5] = 0; f[6] = (int32_t)nkeys; f[7] = len;
                memcpy(out_keys + nkeys, ranks, sizeof(int32_t) * len);
                nkeys += len; out_word[nrec++] = w;
            }
        }
        /* stable argsort by letter: sorted((ch, i) for i, ch in enumerate(word)) */
        for (int i = 0; i < len; i++) {
            int j = i;
            while (j > 0 && word[order[j - 1]] > word[i]) { order[j] = order[j - 1]; j--; }
            order[j] = i;
        }
        int64_t found = keyset_find(&amsco, out_fields, out_keys, order, len);
        if (found <= -2) {
            amsco.slots[-2 - found] = (int32_t)nrec;
            int32_t *f = out_fields + (size_t)nrec * REC_FIELDS;
            f[0] = F_AMSCO; f[1] = f[2] = f[3] = f[4] = f[5] = 0; f[6] = (int32_t)nkeys; f[7] = len;
            memcpy(out_keys + nkeys, order, sizeof(int32_t) * len);
            nkeys += len; out_word[nrec++] = w;
        }
    }
    result = nrec;
    (void)total_chars;
done:
    free(mysz.slots); free(amsco.slots); free(ranks); free(order); free(distinct);
    return result;
}
