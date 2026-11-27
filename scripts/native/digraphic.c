/* Square-key ciphers: Playfair, Four-square, Bifid/Trifid (fractionation).
 *
 * Whole simulated-annealing runs over the key square(s), with the toolkit's
 * fitness (cct_fitness: mean n-gram score x letter_entropy^weight, entropy
 * recomputed every step since these ciphers change letter counts), geometric
 * cooling (cct_cooling_ratio), the acceptance rule cct_accept and a final
 * hill-climb polish over every single swap.
 * Runs are chunked: cct_dg_anneal does up to max_steps moves and keeps all of
 * its state (keys, scores, temperature, step, RNG) in DgState, so Python can
 * show progress and stop on Ctrl+C between chunks.
 *
 * Plus the one-shot decrypts (cct_fraction_decrypt, cct_foursquare_decrypt,
 * cct_dg_score) and the Playfair keyword (dictionary) scorer. */
#include "cct_common.h"

#define DG_MAXSYM 36
enum { DG_PLAYFAIR = 0, DG_FOURSQUARE = 1, DG_FRACTION = 2 };

/* The cipher being attacked (mirrored by native/digraphic.py). */
typedef struct {
    int32_t kind;            /* DG_PLAYFAIR, DG_FOURSQUARE or DG_FRACTION */
    int32_t n;               /* cipher symbols (Playfair/Four-square: even) */
    const uint8_t *cipher;   /* symbol indices 0..nsym-1 */
    int32_t period;          /* fractionation block length (0 = whole text) */
    int32_t dims, side;      /* fractionation: 2/5 (Bifid) or 3/3 (Trifid) */
    int32_t nsym;            /* symbols per key: 25 (27 for Trifid) */
    const uint8_t *to_az;    /* plaintext symbol -> letter code 0-25 */
    const uint8_t *scores;   /* n-gram table */
    int32_t size;            /* n-gram length */
    double weight;           /* entropy weight (0.5) */
} DgCipher;

/* Resumable annealing state. Keys are cell -> symbol (Four-square: [0] the
 * top-right square, [1] the bottom-left square). */
typedef struct {
    uint8_t current[2][DG_MAXSYM];
    uint8_t best[2][DG_MAXSYM];
    double current_score, best_score, temp, ratio;
    int64_t step, iterations;
    uint64_t rng[4];
    int32_t started;
} DgState;

typedef struct {
    const DgCipher *c;
    uint8_t *plain, *az, *trial, *seq;   /* az: letters of the accepted key; trial: of the proposed key */
    uint8_t *win, *trial_win;            /* n-gram score of each window of az / trial (full rescore) */
    int32_t full;                        /* the trial was rescored in full (trial_win is valid) */
    int32_t *changed, nchanged;          /* windows whose trial score differs ... */
    uint8_t *changed_score;              /* ... and their trial scores */
    uint8_t pos[2][DG_MAXSYM];           /* symbol -> cell */
    int64_t total, trial_total;          /* n-gram totals of az / trial */
    int32_t counts[26], trial_counts[26];
} DgWork;

static int dg_keys(const DgCipher *c) { return c->kind == DG_FOURSQUARE ? 2 : 1; }

static int dg_work_init(DgWork *w, const DgCipher *c) {
    size_t n = (size_t)(c->n > 0 ? c->n : 1);
    memset(w, 0, sizeof *w);
    w->c = c;
    w->plain = (uint8_t *)malloc(n);
    w->az = (uint8_t *)malloc(n);
    w->trial = (uint8_t *)malloc(n);
    w->seq = (uint8_t *)malloc(n * 3 + 3);
    w->win = (uint8_t *)malloc(n);
    w->trial_win = (uint8_t *)malloc(n);
    w->changed = (int32_t *)malloc(n * sizeof(int32_t));
    w->changed_score = (uint8_t *)malloc(n);
    return w->plain && w->az && w->trial && w->seq && w->win && w->trial_win && w->changed && w->changed_score;
}

static void dg_work_free(DgWork *w) {
    free(w->plain); free(w->az); free(w->trial); free(w->seq); free(w->win); free(w->trial_win); free(w->changed); free(w->changed_score);
}

/* Fractionation decryption with a caller-supplied buffer (see cct_fraction_decrypt). */
static void fraction_decrypt(const uint8_t *cipher, int32_t n, int32_t period, int32_t dims, int32_t side,
                             const uint8_t *cell_of, const uint8_t *grid, uint8_t *out, uint8_t *seq) {
    int32_t block = period > 0 ? period : n;
    for (int32_t b = 0; b < n; b += block) {
        int32_t len = n - b < block ? n - b : block;
        for (int32_t k = 0; k < len; k++) {
            int32_t cell = cell_of[cipher[b + k]];
            for (int32_t j = dims - 1; j >= 0; j--) { seq[k * dims + j] = (uint8_t)(cell % side); cell /= side; }
        }
        for (int32_t k = 0; k < len; k++) {
            int32_t cell = 0;
            for (int32_t j = 0; j < dims; j++) cell = cell * side + seq[j * len + k];
            out[b + k] = grid[cell];
        }
    }
}

/* Playfair decryption on a dim x dim square (same row: letter to the left;
 * same column: letter above; otherwise the rectangle's other corners). */
static void playfair_decrypt(const uint8_t *cipher, int32_t n, int dim, const uint8_t *grid, const uint8_t *pos,
                             uint8_t *out) {
    for (int32_t i = 0; i + 1 < n; i += 2) {
        int a = pos[cipher[i]], b = pos[cipher[i + 1]];
        int ra = a / dim, ca = a % dim, rb = b / dim, cb = b % dim;
        if (ra == rb) {
            out[i] = grid[ra * dim + (ca + dim - 1) % dim];
            out[i + 1] = grid[rb * dim + (cb + dim - 1) % dim];
        } else if (ca == cb) {
            out[i] = grid[((ra + dim - 1) % dim) * dim + ca];
            out[i + 1] = grid[((rb + dim - 1) % dim) * dim + cb];
        } else {
            out[i] = grid[ra * dim + cb];
            out[i + 1] = grid[rb * dim + ca];
        }
    }
}

/* Four-square: c1 = cipher[2i] in the top-right square, c2 = cipher[2i+1] in
 * the bottom-left; the plain squares are the plain alphabet. */
static void foursquare_decrypt(const uint8_t *cipher, int32_t n, const uint8_t *tr_pos, const uint8_t *bl_pos,
                               uint8_t *out) {
    for (int32_t i = 0; i + 1 < n; i += 2) {
        int a = tr_pos[cipher[i]], b = bl_pos[cipher[i + 1]];
        out[i] = (uint8_t)((a / 5) * 5 + b % 5);
        out[i + 1] = (uint8_t)((b / 5) * 5 + a % 5);
    }
}

/* Decrypt with keys into w->plain (symbols). */
static void dg_decrypt(DgWork *w, uint8_t keys[2][DG_MAXSYM]) {
    const DgCipher *c = w->c;
    int nkeys = dg_keys(c);
    for (int k = 0; k < nkeys; k++)
        for (int cell = 0; cell < c->nsym; cell++) w->pos[k][keys[k][cell]] = (uint8_t)cell;
    if (c->kind == DG_PLAYFAIR) playfair_decrypt(c->cipher, c->n, 5, keys[0], w->pos[0], w->plain);
    else if (c->kind == DG_FOURSQUARE) foursquare_decrypt(c->cipher, c->n, w->pos[0], w->pos[1], w->plain);
    else fraction_decrypt(c->cipher, c->n, c->period, c->dims, c->side, w->pos[0], keys[0], w->plain, w->seq);
}

static inline int64_t dg_gram(const uint8_t *az, int32_t at, int size) {
    int64_t index = 0;
    for (int k = 0; k < size; k++) index = index * 26 + az[at + k];
    return index;
}

/* cct_fitness from an n-gram total and letter counts (same arithmetic as
 * cct_fitness / cct_entropy_factor, so the value is identical). */
static double dg_fitness(const DgCipher *c, int64_t total, const int32_t *counts) {
    int32_t n = c->n, count = n - c->size + 1;
    if (count <= 0) return -9999.0;
    double entropy = 0.0;
    for (int k = 0; k < 26; k++) if (counts[k]) { double p = (double)counts[k] / n; entropy -= p * log2(p); }
    return (double)total / count * pow(entropy, c->weight);
}

/* Score keys from scratch and make them the accepted state (w->az, total, counts). */
static double dg_full(DgWork *w, uint8_t keys[2][DG_MAXSYM]) {
    const DgCipher *c = w->c;
    dg_decrypt(w, keys);
    memset(w->counts, 0, sizeof w->counts);
    for (int32_t i = 0; i < c->n; i++) { w->az[i] = c->to_az[w->plain[i]]; w->counts[w->az[i]]++; }
    w->total = 0;
    for (int32_t at = 0; at + c->size <= c->n; at++) {
        w->win[at] = c->scores[dg_gram(w->az, at, c->size)];
        w->total += w->win[at];
    }
    return dg_fitness(c, w->total, w->counts);
}

/* Score proposed keys into w->trial. When few letters differ from the
 * accepted plaintext, only the n-grams that cover them are rescored (the
 * accepted windows' scores are cached in w->win); when many differ, every
 * window is rescored (DG_FULL_SHARE: the share of windows above which that is
 * cheaper). Either way the total is the exact integer sum. dg_take() accepts. */
#ifndef DG_FULL_SHARE
#define DG_FULL_SHARE 0.5
#endif
static double dg_try(DgWork *w, uint8_t keys[2][DG_MAXSYM]) {
    const DgCipher *c = w->c;
    int32_t n = c->n, size = c->size, last = n - size;   /* last window start */
    const uint8_t *scores = c->scores, *old = w->az;
    uint8_t *az = w->trial;
    int32_t differ = 0;
    w->nchanged = 0;
    w->full = 0;
    dg_decrypt(w, keys);
    memcpy(w->trial_counts, w->counts, sizeof w->counts);
    for (int32_t i = 0; i < n; i++) {
        uint8_t letter = c->to_az[w->plain[i]];
        az[i] = letter;
        if (letter == old[i]) continue;
        differ++;
        w->trial_counts[old[i]]--;
        w->trial_counts[letter]++;
    }
    int64_t total = w->total;
    if (last >= 0 && differ) {
        if ((double)differ * size > DG_FULL_SHARE * (last + 1)) {
            int64_t modulus = cct_ngram_modulus(size), index = 0;
            total = 0;
            for (int32_t i = 0; i < size - 1; i++) index = index * 26 + az[i];
            for (int32_t i = size - 1; i < n; i++) {
                index = (index % modulus) * 26 + az[i];
                total += w->trial_win[i - size + 1] = scores[index];
            }
            w->full = 1;
        } else {
            int32_t next = 0;                             /* first window not yet rescored */
            for (int32_t i = 0; i < n; i++) {
                if (az[i] == old[i]) continue;
                int32_t lo = i - size + 1, hi = i < last ? i : last;
                if (lo < next) lo = next;
                for (int32_t at = lo; at <= hi; at++) {
                    uint8_t value = scores[dg_gram(az, at, size)];
                    total += (int64_t)value - w->win[at];
                    w->changed[w->nchanged] = at;
                    w->changed_score[w->nchanged++] = value;
                }
                if (hi + 1 > next) next = hi + 1;
            }
        }
    }
    w->trial_total = total;
    return dg_fitness(c, total, w->trial_counts);
}

static void dg_take(DgWork *w) {
    uint8_t *t = w->az; w->az = w->trial; w->trial = t;
    w->total = w->trial_total;
    memcpy(w->counts, w->trial_counts, sizeof w->counts);
    if (w->full) { t = w->win; w->win = w->trial_win; w->trial_win = t; }
    else for (int32_t k = 0; k < w->nchanged; k++) w->win[w->changed[k]] = w->changed_score[k];
}

static inline void dg_pair(Rng *r, int count, int *i, int *j) {
    *i = rng_below(r, count);
    *j = rng_below(r, count - 1);
    if (*j >= *i) (*j)++;
}

/* One random move (playfair_anneal's move mix for Playfair; a swap of two
 * cells of one key otherwise). */
static void dg_move(const DgCipher *c, uint8_t keys[2][DG_MAXSYM], Rng *r) {
    int i, j;
    if (c->kind != DG_PLAYFAIR) {
        int k = c->kind == DG_FOURSQUARE ? rng_below(r, 2) : 0;
        dg_pair(r, c->nsym, &i, &j);
        uint8_t t = keys[k][i]; keys[k][i] = keys[k][j]; keys[k][j] = t;
        return;
    }
    uint8_t *g = keys[0], copy[25];
    double roll = rng_double(r);
    if (roll < 0.9) {                       /* swap two letters */
        dg_pair(r, 25, &i, &j);
        uint8_t t = g[i]; g[i] = g[j]; g[j] = t;
    } else if (roll < 0.94) {               /* swap two rows */
        dg_pair(r, 5, &i, &j);
        for (int col = 0; col < 5; col++) { uint8_t t = g[i * 5 + col]; g[i * 5 + col] = g[j * 5 + col]; g[j * 5 + col] = t; }
    } else if (roll < 0.98) {               /* swap two columns */
        dg_pair(r, 5, &i, &j);
        for (int row = 0; row < 5; row++) { uint8_t t = g[row * 5 + i]; g[row * 5 + i] = g[row * 5 + j]; g[row * 5 + j] = t; }
    } else {
        memcpy(copy, g, 25);
        for (int row = 0; row < 5; row++)
            for (int col = 0; col < 5; col++) {
                if (roll < 0.99) g[row * 5 + col] = copy[(4 - row) * 5 + col];          /* flip top-bottom */
                else if (roll < 0.995) g[row * 5 + col] = copy[row * 5 + (4 - col)];    /* flip left-right */
                else g[row * 5 + col] = copy[col * 5 + row];                            /* transpose */
            }
    }
}

/* Reset the state for a run of `iterations` moves cooling from t_start to t_end.
 * The caller fills state->current with the starting key(s) afterwards. */
EXPORT void cct_dg_init(DgState *st, uint64_t seed, int64_t iterations, double t_start, double t_end) {
    Rng r;
    rng_seed(&r, seed);
    memcpy(st->rng, r.s, sizeof r.s);
    st->iterations = iterations > 0 ? iterations : 1;
    st->temp = t_start;
    st->ratio = cct_cooling_ratio(t_start, t_end, st->iterations);
    st->step = 0;
    st->started = 0;
    st->current_score = st->best_score = -1e300;
}

/* Up to max_steps annealing moves; returns the number done (0 once the run is
 * over, or -1 when out of memory). */
EXPORT int64_t cct_dg_anneal(const DgCipher *c, int64_t max_steps, DgState *st) {
    DgWork w;
    if (!dg_work_init(&w, c)) { dg_work_free(&w); return -1; }
    Rng r;
    memcpy(r.s, st->rng, sizeof r.s);
    double start = dg_full(&w, st->current);
    if (!st->started) {
        st->current_score = st->best_score = start;
        memcpy(st->best, st->current, sizeof st->best);
        st->started = 1;
    }
    uint8_t saved[2][DG_MAXSYM];
    int64_t done = 0;
    while (done < max_steps && st->step < st->iterations) {
        memcpy(saved, st->current, sizeof saved);
        dg_move(c, st->current, &r);
        double score = dg_try(&w, st->current);
        if (cct_accept(&r, score - st->current_score, st->temp)) {
            dg_take(&w);
            st->current_score = score;
            if (score > st->best_score) {
                st->best_score = score;
                memcpy(st->best, st->current, sizeof st->best);
            }
        } else {
            memcpy(st->current, saved, sizeof saved);
        }
        st->temp *= st->ratio;
        st->step++;
        done++;
    }
    memcpy(st->rng, r.s, sizeof r.s);
    dg_work_free(&w);
    return done;
}

/* Hill-climb polish of state->best over every single swap of two cells (each
 * key in turn), keeping a swap only if it raises the fitness by more than
 * 1e-12, for up to max_rounds passes. Returns the final
 * fitness (also stored in best_score). */
EXPORT double cct_dg_polish(const DgCipher *c, int32_t max_rounds, DgState *st) {
    DgWork w;
    if (!dg_work_init(&w, c)) { dg_work_free(&w); return st->best_score; }
    double score = dg_full(&w, st->best);
    int nkeys = dg_keys(c);
    for (int32_t round = 0; round < max_rounds; round++) {
        int improved = 0;
        for (int k = 0; k < nkeys; k++)
            for (int i = 0; i < c->nsym; i++)
                for (int j = i + 1; j < c->nsym; j++) {
                    uint8_t *g = st->best[k], t = g[i];
                    g[i] = g[j]; g[j] = t;
                    double s = dg_try(&w, st->best);
                    if (s > score + 1e-12) { dg_take(&w); score = s; improved = 1; }
                    else { t = g[i]; g[i] = g[j]; g[j] = t; }
                }
        if (!improved) break;
    }
    score = dg_full(&w, st->best);   /* recomputed from scratch (equal to the running value) */
    st->best_score = score;
    dg_work_free(&w);
    return score;
}

/* One-shot: fitness of key0 (and key1 for Four-square); the plaintext symbols
 * go to `out` when it is not NULL. */
EXPORT double cct_dg_score(const DgCipher *c, const uint8_t *key0, const uint8_t *key1, uint8_t *out) {
    DgWork w;
    if (!dg_work_init(&w, c)) { dg_work_free(&w); return -9999.0; }
    uint8_t keys[2][DG_MAXSYM];
    memset(keys, 0, sizeof keys);
    memcpy(keys[0], key0, (size_t)c->nsym);
    if (key1) memcpy(keys[1], key1, (size_t)c->nsym);
    double score = dg_full(&w, keys);
    if (out) memcpy(out, w.plain, (size_t)c->n);
    dg_work_free(&w);
    return score;
}

/* Fractionation (Bifid: dims 2, side 5; Trifid: dims 3, side 3) decryption.
 * cipher: symbol indices; cell_of[symbol] = cell (0..side^dims-1);
 * grid[cell] = symbol. Per block of `period` symbols (0 = whole text): the
 * cipher symbols' coordinates, in order, form dims rows of the block length;
 * plaintext symbol k has coordinates (row 0 [k], row 1 [k], ...). */
EXPORT void cct_fraction_decrypt(const uint8_t *cipher, int32_t n, int32_t period, int32_t dims, int32_t side,
                                 const uint8_t *cell_of, const uint8_t *grid, uint8_t *out) {
    uint8_t *seq = (uint8_t *)malloc((size_t)n * (size_t)dims + 1);
    if (!seq) return;
    fraction_decrypt(cipher, n, period, dims, side, cell_of, grid, out, seq);
    free(seq);
}

/* Four-square decryption. c1/c2: first and second letters of each ciphertext
 * pair as indices 0-24 in the 25-letter alphabet; tr_pos/bl_pos: position of
 * each letter in the top-right / bottom-left key square. Plaintext comes from
 * the plain squares: p1 = row(c1) * 5 + col(c2), p2 = row(c2) * 5 + col(c1). */
EXPORT void cct_foursquare_decrypt(const uint8_t *c1, const uint8_t *c2, int32_t pairs, const uint8_t *tr_pos,
                                   const uint8_t *bl_pos, uint8_t *out) {
    for (int32_t i = 0; i < pairs; i++) {
        int a = tr_pos[c1[i]], b = bl_pos[c2[i]];
        out[2 * i] = (uint8_t)((a / 5) * 5 + b % 5);
        out[2 * i + 1] = (uint8_t)((b / 5) * 5 + a % 5);
    }
}

/* Playfair keyword (dictionary) attack on a dim x dim square (dim 5 or 6).
 * cipher: n symbol indices (n even); words: keyword symbols, word w is
 * words[offsets[w] .. offsets[w+1]); its square is the keyword's distinct
 * symbols followed by the rest of the alphabet in order
 * (playfair.create_playfair_matrix). to_az: symbol -> letter code 0-25, or 255
 * for a symbol that is not a letter (dropped before scoring, as score_text
 * drops non-letters). For each word: fitness_out (cct_fitness of the letters),
 * ioc_out (index of coincidence of the letters) and crib_out (1 when every crib
 * occurs in the plaintext symbols; 0 when there are no cribs). */
EXPORT void cct_playfair_keywords(const uint8_t *cipher, int32_t n, int32_t dim, const uint8_t *to_az,
                                  const uint8_t *words, const int32_t *offsets, int32_t m, const uint8_t *scores,
                                  int32_t size, double weight, const uint8_t *cribs, const int32_t *crib_offsets,
                                  int32_t ncribs, double *fitness_out, double *ioc_out, uint8_t *crib_out) {
    int nsym = dim * dim;
    uint8_t *plain = (uint8_t *)malloc((size_t)n + 1), *az = (uint8_t *)malloc((size_t)n + 1);
    if (!plain || !az) { free(plain); free(az); return; }
    uint8_t grid[DG_MAXSYM], pos[DG_MAXSYM], seen[DG_MAXSYM];
    for (int32_t w = 0; w < m; w++) {
        int cells = 0;
        memset(seen, 0, sizeof seen);
        for (int32_t i = offsets[w]; i < offsets[w + 1]; i++) {
            uint8_t s = words[i];
            if (s < nsym && !seen[s]) { seen[s] = 1; grid[cells++] = s; }
        }
        for (int s = 0; s < nsym; s++) if (!seen[s]) grid[cells++] = (uint8_t)s;
        for (int cell = 0; cell < nsym; cell++) pos[grid[cell]] = (uint8_t)cell;
        playfair_decrypt(cipher, n, dim, grid, pos, plain);
        int32_t letters = 0, counts[26] = {0};
        for (int32_t i = 0; i < n; i++) {
            uint8_t a = to_az[plain[i]];
            if (a < 26) { az[letters++] = a; counts[a]++; }
        }
        fitness_out[w] = cct_fitness(az, letters, scores, size, weight, -1.0);
        double ioc = 0.0;
        if (letters >= 2) {
            int64_t num = 0;
            for (int c = 0; c < 26; c++) num += (int64_t)counts[c] * (counts[c] - 1);
            ioc = (double)num / ((double)letters * (double)(letters - 1));
        }
        ioc_out[w] = ioc;
        int hit = ncribs > 0;
        for (int32_t k = 0; k < ncribs && hit; k++) {
            const uint8_t *crib = cribs + crib_offsets[k];
            int32_t len = crib_offsets[k + 1] - crib_offsets[k], found = 0;
            for (int32_t start = 0; start + len <= n && !found; start++) {
                int32_t i = 0;
                while (i < len && plain[start + i] == crib[i]) i++;
                found = i == len;
            }
            hit = found;
        }
        crib_out[w] = (uint8_t)hit;
    }
    free(plain);
    free(az);
}
