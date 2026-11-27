/* Ciphertext-only Hill attack over A-Z, row by row (hill.row_attack).
 *
 * Decryption is p_block = D * c_block, so row i of the inverse key D alone
 * produces plaintext letters i, i+size, i+2*size, ... Stage 1
 * (cct_hill_best_rows) scores every possible row, 26^size of them, by the
 * chi-squared of its letters against English and keeps the best. Stage 2
 * (cct_hill_combine) tries every ordered choice of `size` kept rows that forms
 * a matrix invertible mod 26 and ranks the interleaved plaintexts by the
 * toolkit's fitness (cct_fitness, entropy recomputed). size: 1-4. */
#include "cct_common.h"

#define HILL_MAXSIZE 4

static int hill_gcd(int a, int b) {
    while (b) { int t = a % b; a = b; b = t; }
    return a < 0 ? -a : a;
}

/* Integer determinant by cofactor expansion (entries 0-25, size <= 4). */
static int64_t hill_det(const int *m, int size) {
    if (size == 1) return m[0];
    if (size == 2) return (int64_t)m[0] * m[3] - (int64_t)m[1] * m[2];
    int64_t total = 0;
    int minor[HILL_MAXSIZE * HILL_MAXSIZE];
    for (int col = 0; col < size; col++) {
        int k = 0;
        for (int r = 1; r < size; r++)
            for (int c = 0; c < size; c++)
                if (c != col) minor[k++] = m[r * size + c];
        int64_t sub = hill_det(minor, size - 1);
        total += (col % 2 ? -1 : 1) * (int64_t)m[col] * sub;
    }
    return total;
}

/* hill.is_valid_key_matrix: det mod 26 is non-zero and coprime to 26. */
static int hill_invertible(const int *m, int size) {
    int det = (int)(((hill_det(m, size) % 26) + 26) % 26);
    return det != 0 && hill_gcd(det, 26) == 1;
}

/* Letters row . c_block mod 26 for every block. */
static void hill_row_outputs(const uint8_t *cipher, int32_t blocks, int size, const int *row, uint8_t *out) {
    for (int32_t b = 0; b < blocks; b++) {
        int sum = 0;
        for (int k = 0; k < size; k++) sum += row[k] * cipher[b * size + k];
        out[b] = (uint8_t)(sum % 26);
    }
}

/* Stage 1. cipher: n letter codes, n a multiple of size (padded by the
 * caller). Rows in itertools.product order (row[0] most significant); rows
 * whose entries' gcd is not coprime to 26 are skipped (no invertible matrix
 * has them). chi = sum over letters (count - E)^2 / E with
 * E = expected_pct[c] * blocks / 100. Keeps the `keep` lowest chi values, ties
 * by row order, in rows_out (keep x size) / chi_out, sorted. *kept_out = number
 * kept. Returns the number of rows scored. */
EXPORT int64_t cct_hill_best_rows(const uint8_t *cipher, int32_t n, int32_t size, const double *expected_pct,
                                  int32_t keep, uint8_t *rows_out, double *chi_out, int32_t *kept_out) {
    *kept_out = 0;
    if (size < 1 || size > HILL_MAXSIZE || keep < 1) return 0;
    int32_t blocks = n / size;
    if (blocks < 1) return 0;
    uint8_t *out = (uint8_t *)malloc((size_t)blocks);
    int64_t *order = (int64_t *)malloc(sizeof(int64_t) * (size_t)keep);
    double *chis = (double *)malloc(sizeof(double) * (size_t)keep);
    if (!out || !order || !chis) { free(out); free(order); free(chis); return 0; }
    double expected[26];
    for (int c = 0; c < 26; c++) expected[c] = expected_pct[c] * blocks / 100;
    int64_t total_rows = 1, scored = 0;
    int32_t kept = 0;
    for (int k = 0; k < size; k++) total_rows *= 26;
    int row[HILL_MAXSIZE];
    for (int64_t index = 0; index < total_rows; index++) {
        int64_t rest = index;
        int g = 0;
        for (int k = size - 1; k >= 0; k--) { row[k] = (int)(rest % 26); rest /= 26; }
        for (int k = 0; k < size; k++) g = hill_gcd(g, row[k]);
        if (hill_gcd(g, 26) != 1) continue;
        scored++;
        hill_row_outputs(cipher, blocks, size, row, out);
        int counts[26] = {0};
        for (int32_t b = 0; b < blocks; b++) counts[out[b]]++;
        double chi = 0.0;
        for (int c = 0; c < 26; c++) { double d = counts[c] - expected[c]; chi += d * d / expected[c]; }
        if (kept == keep && chi >= chis[kept - 1]) continue;   /* ties keep the earlier row */
        int32_t at = kept < keep ? kept++ : keep - 1;
        while (at > 0 && chis[at - 1] > chi) { chis[at] = chis[at - 1]; order[at] = order[at - 1]; at--; }
        chis[at] = chi;
        order[at] = index;
    }
    for (int32_t i = 0; i < kept; i++) {
        int64_t rest = order[i];
        for (int k = size - 1; k >= 0; k--) { rows_out[i * size + k] = (uint8_t)(rest % 26); rest /= 26; }
        chi_out[i] = chis[i];
    }
    *kept_out = kept;
    free(out); free(order); free(chis);
    return scored;
}

typedef struct {
    const uint8_t *cipher, *scores;
    const uint8_t *rows;        /* k x size */
    uint8_t *outputs;           /* k x blocks: each row's letters */
    uint8_t *plain;
    int32_t blocks, size, k, ngsize, top, found;
    double weight;
    int32_t combo[HILL_MAXSIZE];
    int used[256];
    int32_t *combo_out;         /* top x size */
    double *fit_out;
} HillCombine;

/* Is combination a (score sa) ranked below b (score sb)? Lower score first,
 * then the later combination in lexicographic order. */
static int hill_below(double sa, const int32_t *a, double sb, const int32_t *b, int size) {
    if (sa != sb) return sa < sb;
    for (int i = 0; i < size; i++) if (a[i] != b[i]) return a[i] > b[i];
    return 0;
}

static void hill_consider(HillCombine *h) {
    int size = h->size, m[HILL_MAXSIZE * HILL_MAXSIZE];
    for (int r = 0; r < size; r++)
        for (int c = 0; c < size; c++) m[r * size + c] = h->rows[h->combo[r] * size + c];
    if (!hill_invertible(m, size)) return;
    for (int r = 0; r < size; r++) {
        const uint8_t *letters = h->outputs + (size_t)h->combo[r] * h->blocks;
        for (int32_t b = 0; b < h->blocks; b++) h->plain[b * size + r] = letters[b];
    }
    double score = cct_fitness(h->plain, h->blocks * size, h->scores, h->ngsize, h->weight, -1.0);
    int32_t slot;
    if (h->found < h->top) {
        slot = h->found++;
    } else {
        /* full: replace the lowest only by a strictly higher score (hill.row_attack's heap rule) */
        slot = 0;
        for (int32_t i = 1; i < h->top; i++)
            if (hill_below(h->fit_out[i], h->combo_out + i * size, h->fit_out[slot], h->combo_out + slot * size, size))
                slot = i;
        if (!(score > h->fit_out[slot])) return;
    }
    h->fit_out[slot] = score;
    for (int r = 0; r < size; r++) h->combo_out[slot * size + r] = h->combo[r];
}

static void hill_walk(HillCombine *h, int depth) {
    if (depth == h->size) { hill_consider(h); return; }
    for (int32_t i = 0; i < h->k; i++) {
        if (h->used[i]) continue;
        h->used[i] = 1;
        h->combo[depth] = i;
        hill_walk(h, depth + 1);
        h->used[i] = 0;
    }
}

/* Stage 2. rows: k kept rows (k <= 256) of `size` entries. Every ordered
 * choice of `size` distinct rows (itertools.permutations order) whose matrix
 * is invertible mod 26 is scored on its interleaved plaintext (blocks * size
 * letters). The `top` best go to combo_out (row indices, top x size) and
 * fit_out, best first (equal scores: earlier combination first). Returns how
 * many were kept. */
EXPORT int32_t cct_hill_combine(const uint8_t *cipher, int32_t n, int32_t size, const uint8_t *rows, int32_t k,
                                const uint8_t *scores, int32_t ngsize, double weight, int32_t top,
                                int32_t *combo_out, double *fit_out) {
    if (size < 1 || size > HILL_MAXSIZE || k < size || k > 256 || top < 1) return 0;
    HillCombine h;
    memset(&h, 0, sizeof h);
    h.cipher = cipher; h.scores = scores; h.rows = rows; h.size = size; h.k = k; h.ngsize = ngsize;
    h.weight = weight; h.top = top; h.combo_out = combo_out; h.fit_out = fit_out;
    h.blocks = n / size;
    h.outputs = (uint8_t *)malloc((size_t)k * (size_t)(h.blocks > 0 ? h.blocks : 1));
    h.plain = (uint8_t *)malloc((size_t)(h.blocks > 0 ? h.blocks : 1) * (size_t)size);
    if (!h.outputs || !h.plain) { free(h.outputs); free(h.plain); return 0; }
    for (int32_t i = 0; i < k; i++) {
        int row[HILL_MAXSIZE];
        for (int c = 0; c < size; c++) row[c] = rows[i * size + c];
        hill_row_outputs(cipher, h.blocks, size, row, h.outputs + (size_t)i * h.blocks);
    }
    hill_walk(&h, 0);
    /* sort best first (insertion sort; top is small) */
    for (int32_t i = 1; i < h.found; i++) {
        double s = fit_out[i];
        int32_t c[HILL_MAXSIZE];
        for (int r = 0; r < size; r++) c[r] = combo_out[i * size + r];
        int32_t j = i;
        while (j > 0 && hill_below(fit_out[j - 1], combo_out + (j - 1) * size, s, c, size)) {
            fit_out[j] = fit_out[j - 1];
            for (int r = 0; r < size; r++) combo_out[j * size + r] = combo_out[(j - 1) * size + r];
            j--;
        }
        fit_out[j] = s;
        for (int r = 0; r < size; r++) combo_out[j * size + r] = c[r];
    }
    free(h.outputs);
    free(h.plain);
    return h.found;
}
