/* Native (C) engines for the Cipher Cracker Toolkit.
 *
 * Built per machine by `python scripts/native_tools.py build` (zig's C compiler from
 * pip). The solvers need it: there is no Python fallback. The tests check the
 * engines against known answers and small test-only reference implementations.
 *
 * Columnar layouts: for a column order (key), plaintext position i reads
 * ciphertext position
 *   kind 0: start[col] + base            (layouts that read columns)
 *   kind 1: rank[col] + base             (layouts that read rows, full rows)
 *   kind 2: partial_base + prank[col]    (layouts that read rows, partial row)
 * with (col, base, kind) per position from native.columnar_descriptors, which
 * the tests check against transposition_core.make_permuter.
 *
 *  - cct_perm_bruteforce: every column order, n-gram total of the decryption;
 *    returns the first (lexicographic) order with the highest total.
 *  - cct_perm_anneal: simulated annealing over column orders, the moves and
 *    acceptance rule of permutation_solver (tool 44; moves 1 swap or reverse,
 *    moves 0 swap only).
 *  - cct_crib_columnar_periodic: every column order + a periodic key, both
 *    orders, consistent with known plaintext letters (crib_columnar_search.py).
 */
#include "cct_common.h"

#define MAXW 64
#define MAXCRIB 128
#define MAXP 128

EXPORT int32_t cct_native_version(void) { return 3; }

typedef struct {
    int32_t n;                    /* text length (letters) */
    const uint8_t *cipher;        /* letter codes 0-25 */
    int32_t width, read_rows, remainder, partial_base;
    const int32_t *col_len, *d_col, *d_base, *d_kind;   /* descriptors for every position */
} Layout;

static void key_tables(const Layout *t, const uint8_t *key, int32_t *start, int32_t *rank, int32_t *prank) {
    if (!t->read_rows) {
        int32_t s = 0;
        for (int j = 0; j < t->width; j++) { start[key[j]] = s; s += t->col_len[key[j]]; }
    } else {
        int pr = 0;
        for (int j = 0; j < t->width; j++) { rank[key[j]] = j; if (key[j] < t->remainder) prank[key[j]] = pr++; }
    }
}

static inline int32_t source_of(const Layout *t, int i, const int32_t *start, const int32_t *rank,
                                const int32_t *prank) {
    if (!t->read_rows) return start[t->d_col[i]] + t->d_base[i];
    return t->d_kind[i] == 2 ? t->partial_base + prank[t->d_col[i]] : rank[t->d_col[i]] + t->d_base[i];
}

/* ngram_scoring.ngram_total of the decryption under `key` (no plaintext buffer) */
static int64_t order_total(const Layout *t, const uint8_t *key, const uint8_t *scores, int size, int64_t modulus) {
    int32_t start[MAXW], rank[MAXW], prank[MAXW];
    key_tables(t, key, start, rank, prank);
    if (t->n < size) return 0;
    int64_t index = 0, total = 0;
    for (int i = 0; i < size - 1; i++) index = index * 26 + t->cipher[source_of(t, i, start, rank, prank)];
    for (int i = size - 1; i < t->n; i++) {
        index = (index % modulus) * 26 + t->cipher[source_of(t, i, start, rank, prank)];
        total += scores[index];
    }
    return total;
}

static int next_permutation(uint8_t *a, int n) {
    int i = n - 2;
    while (i >= 0 && a[i] >= a[i + 1]) i--;
    if (i < 0) return 0;
    int j = n - 1;
    while (a[j] <= a[i]) j--;
    uint8_t t = a[i]; a[i] = a[j]; a[j] = t;
    for (int l = i + 1, r = n - 1; l < r; l++, r--) { t = a[l]; a[l] = a[r]; a[r] = t; }
    return 1;
}

/* Every column order after `prefix_len` fixed columns, starting from `key` (the
 * first order: prefix + remaining columns ascending), for at most max_orders.
 * Keeps the first order with the highest total. Returns orders processed. */
EXPORT int64_t cct_perm_bruteforce(const Layout *t, const uint8_t *scores, int32_t size, int32_t prefix_len,
                                   uint8_t *key, int64_t max_orders, int64_t *best_total, uint8_t *best_key,
                                   int32_t *done) {
    int64_t modulus = 1;
    for (int i = 0; i < size - 1; i++) modulus *= 26;
    int64_t processed = 0;
    *done = 0;
    while (processed < max_orders) {
        int64_t total = order_total(t, key, scores, size, modulus);
        if (total > *best_total) { *best_total = total; memcpy(best_key, key, (size_t)t->width); }
        processed++;
        if (!next_permutation(key + prefix_len, t->width - prefix_len)) { *done = 1; break; }
    }
    return processed;
}

EXPORT int64_t cct_order_total(const Layout *t, const uint8_t *key, const uint8_t *scores, int32_t size) {
    int64_t modulus = 1;
    for (int i = 0; i < size - 1; i++) modulus *= 26;
    return order_total(t, key, scores, size, modulus);
}

/* ---------------------------------------------------------------- annealing */
/* Rng, rng_next, rng_double, rng_below: cct_common.h */

typedef struct {
    uint8_t current[MAXW], best[MAXW];
    double current_score, best_score, temp;
    int64_t iteration;
    uint64_t rng[4];
} AnnealState;

/* Runs up to `levels` temperature levels of
 *   while temp > 0.1: steps_per_temp moves; temp *= cooling_rate; iteration += 1
 * moves: 0 = swap two positions (simulated_annealing_transposition.modify_key),
 *        1 = 70% swap, 30% reverse the slice [i, j) (permutation_solver.modify_perm).
 * score = total / count * factor (the solvers' fitness). Returns levels run. */
EXPORT int32_t cct_perm_anneal(const Layout *t, const uint8_t *scores, int32_t size, double count, double factor,
                               int32_t moves, int32_t steps_per_temp, double cooling_rate, int32_t levels,
                               AnnealState *st) {
    int64_t modulus = 1;
    for (int i = 0; i < size - 1; i++) modulus *= 26;
    Rng rng;
    memcpy(rng.s, st->rng, sizeof rng.s);
    int w = t->width, run = 0;
    uint8_t cand[MAXW];
    for (; run < levels && st->temp > 0.1; run++) {
        for (int step = 0; step < steps_per_temp; step++) {
            memcpy(cand, st->current, (size_t)w);
            if (w >= 2) {
                if (moves == 0 || rng_double(&rng) < 0.7) {
                    int a = rng_below(&rng, w), b = rng_below(&rng, w - 1);
                    if (b >= a) b++;
                    uint8_t x = cand[a]; cand[a] = cand[b]; cand[b] = x;
                } else {
                    int a = rng_below(&rng, w), b = rng_below(&rng, w - 1);
                    if (b >= a) b++;
                    if (a > b) { int x = a; a = b; b = x; }
                    for (int l = a, r = b - 1; l < r; l++, r--) { uint8_t x = cand[l]; cand[l] = cand[r]; cand[r] = x; }
                }
            }
            double score = (double)order_total(t, cand, scores, size, modulus) / count * factor;
            double diff = score - st->current_score;
            if (diff > 0) {
                memcpy(st->current, cand, (size_t)w);
                st->current_score = score;
                if (score > st->best_score) { st->best_score = score; memcpy(st->best, cand, (size_t)w); }
            } else if (st->temp > 0) {
                if (rng_double(&rng) < exp(diff / st->temp)) {
                    memcpy(st->current, cand, (size_t)w);
                    st->current_score = score;
                }
            }
        }
        st->temp *= cooling_rate;
        st->iteration++;
    }
    memcpy(st->rng, rng.s, sizeof rng.s);
    return run;
}

/* ---------------------------------------------------------------- known plaintext: columnar + periodic */
#define HIT_FIELDS (MAXW + 4)

static int slot_pairs(const int32_t *slots, int ncrib, int period, uint8_t *pa, uint8_t *pb) {
    int last[MAXP];
    int count = 0;
    for (int r = 0; r < period; r++) last[r] = -1;
    for (int k = 0; k < ncrib; k++) {
        int res = slots[k] % period;
        if (last[res] >= 0) { pa[count] = (uint8_t)last[res]; pb[count] = (uint8_t)k; count++; }
        last[res] = k;
    }
    return count;
}

/* Every column order after the prefix; for each, the clue letters' source positions,
 * then for every alphabet/variant combo, both orders and every period: the chained
 * same-slot pairs must all imply the same key value (at least min_checks of them).
 * Hit records: key[MAXW], combo, order, period, checks. Resumable from `key`. */
EXPORT int64_t cct_crib_columnar_periodic(
        const Layout *t, int32_t ncrib, const int32_t *crib_pos, const int32_t *cd_col, const int32_t *cd_base,
        const int32_t *cd_kind, int32_t prefix_len, uint8_t *key, int32_t ncombo, const uint8_t *valtab,
        int32_t nperiod, const int32_t *periods, int32_t min_checks, int64_t max_orders,
        int32_t *hits, int32_t max_hits, int32_t *nhits_out, int32_t *done_out) {
    uint8_t (*fixed_a)[MAXCRIB] = malloc(sizeof(uint8_t[MAXP][MAXCRIB]));
    uint8_t (*fixed_b)[MAXCRIB] = malloc(sizeof(uint8_t[MAXP][MAXCRIB]));
    uint8_t (*move_a)[MAXCRIB] = malloc(sizeof(uint8_t[MAXP][MAXCRIB]));
    uint8_t (*move_b)[MAXCRIB] = malloc(sizeof(uint8_t[MAXP][MAXCRIB]));
    int fixed_n[MAXP], move_n[MAXP];
    int32_t src[MAXCRIB], start[MAXW], rank[MAXW], prank[MAXW];
    uint8_t letters[MAXCRIB], values[MAXCRIB];
    int32_t nhits = *nhits_out;
    int64_t processed = 0;
    int per_order_max = ncombo * 2 * nperiod;
    *done_out = 0;
    for (int p = 0; p < nperiod; p++) fixed_n[p] = slot_pairs(crib_pos, ncrib, periods[p], fixed_a[p], fixed_b[p]);
    while (processed < max_orders) {
        if (max_hits - nhits < per_order_max) break;
        key_tables(t, key, start, rank, prank);
        for (int k = 0; k < ncrib; k++) {
            src[k] = !t->read_rows ? start[cd_col[k]] + cd_base[k]
                   : cd_kind[k] == 2 ? t->partial_base + prank[cd_col[k]] : rank[cd_col[k]] + cd_base[k];
            letters[k] = t->cipher[src[k]];
        }
        for (int p = 0; p < nperiod; p++) move_n[p] = slot_pairs(src, ncrib, periods[p], move_a[p], move_b[p]);
        for (int c = 0; c < ncombo; c++) {
            const uint8_t *table = valtab + (size_t)c * ncrib * 26;
            for (int k = 0; k < ncrib; k++) values[k] = table[k * 26 + letters[k]];
            for (int order = 0; order < 2; order++) {
                for (int p = 0; p < nperiod; p++) {
                    int n = order ? move_n[p] : fixed_n[p];
                    if (n < min_checks) continue;
                    const uint8_t *pa = order ? move_a[p] : fixed_a[p];
                    const uint8_t *pb = order ? move_b[p] : fixed_b[p];
                    int ok = 1;
                    for (int q = 0; q < n; q++) if (values[pa[q]] != values[pb[q]]) { ok = 0; break; }
                    if (!ok) continue;
                    int32_t *rec = hits + (size_t)nhits * HIT_FIELDS;
                    for (int j = 0; j < t->width; j++) rec[j] = key[j];
                    rec[MAXW] = c; rec[MAXW + 1] = order; rec[MAXW + 2] = periods[p]; rec[MAXW + 3] = n;
                    nhits++;
                }
            }
        }
        processed++;
        if (!next_permutation(key + prefix_len, t->width - prefix_len)) { *done_out = 1; break; }
    }
    free(fixed_a); free(fixed_b); free(move_a); free(move_b);
    *nhits_out = nhits;
    return processed;
}

/* ---------------------------------------------------------------- shared scoring (version 2) */

/* ngram_scoring.ngram_total: sum of the table scores of every overlapping
 * n-gram of `codes` (0-25), rolling index. */
EXPORT int64_t cct_ngram_total(const uint8_t *codes, int32_t n, const uint8_t *scores, int32_t size) {
    return cct_total(codes, n, scores, size);
}

