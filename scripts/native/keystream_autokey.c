/* Autokey (autoclave) primer search: autoclave.py (solve_primer / attack).
 *
 * Kinds: 0 = plaintext autokey (key = primer + plaintext),
 *        1 = ciphertext autokey (key = primer + ciphertext).
 * Tableaux: 0 = Vigenere (p = c - k), 1 = Beaufort (p = k - c), mod 26.
 *
 * Plaintext position i depends only on primer letter i mod L (plaintext
 * autokey: the chain j, j+L, j+2L, ...; ciphertext autokey: position j only),
 * so changing primer[j] re-decrypts only that chain.
 *
 * Search (deterministic, no random numbers):
 *  1. each primer letter: the s in 0..25 whose chain has the lowest
 *     chi-squared against English letter frequencies (first s on ties);
 *  2. up to `rounds` rounds of coordinate hill-climbing: for each primer
 *     position, every other letter; keep a change when the fitness rises by
 *     more than 1e-9 (annealing.Fitness, computed by cct_fitness).
 * The chi-squared sum uses Python's float sum() (Neumaier compensation,
 * CPython 3.12+) so the start, and hence the result, match the Python
 * definition exactly. */
#pragma STDC FP_CONTRACT OFF   /* bit-exact annealing.Fitness: no fused multiply-add */
#include "cct_common.h"

static const double AUTOKEY_ENGLISH[26] = {8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69,
                                           3.98, 2.61, 6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11,
                                           2.09, 0.17, 2.11, 0.07};

/* Python's sum() over floats (CPython 3.12+): the first term is added
 * plainly to the int 0, the rest with Neumaier compensation. */
typedef struct { double f, c; int started; } AkSum;
static inline void ak_sum_add(AkSum *s, double x) {
    if (!s->started) { s->f = x; s->started = 1; return; }
    double t = s->f + x;
    if (fabs(s->f) >= fabs(x)) s->c += (s->f - t) + x; else s->c += (x - t) + s->f;
    s->f = t;
}
static inline double ak_sum_value(const AkSum *s) {
    if (!s->started) return 0.0;
    return (s->c != 0.0 && isfinite(s->c)) ? s->f + s->c : s->f;
}

/* autoclave._chi: chi-squared of letter counts against English. */
static double ak_chi(const int *counts, int total) {
    if (total == 0) total = 1;
    AkSum sum = {0.0, 0.0, 0};
    for (int c = 0; c < 26; c++) {
        double expected = AUTOKEY_ENGLISH[c] * total / 100.0;
        double d = (double)counts[c] - expected;
        ak_sum_add(&sum, d * d / expected);
    }
    return ak_sum_value(&sum);
}

static inline uint8_t ak_dec(int c, int k, int variant) {
    int p = variant == 0 ? c - k : k - c;
    p %= 26;
    return (uint8_t)(p < 0 ? p + 26 : p);
}

/* Decrypt the chain of primer position j with primer letter s into plain. */
static void ak_chain(const uint8_t *cipher, int n, int L, int j, int s, int kind, int variant, uint8_t *plain) {
    if (j >= n) return;
    plain[j] = ak_dec(cipher[j], s, variant);
    for (int i = j + L; i < n; i += L)
        plain[i] = ak_dec(cipher[i], kind == 0 ? plain[i - L] : cipher[i - L], variant);
}

/* One primer length, kind and tableau. Returns the fitness; writes the primer
 * (length codes) and the plaintext (n codes). fixed_factor < 0: recompute the
 * entropy factor (annealing.Fitness with fixed_letters None). */
EXPORT double cct_autokey_solve(const uint8_t *cipher, int32_t n, int32_t length, int32_t kind, int32_t variant,
                                const uint8_t *scores, int32_t size, double weight, double fixed_factor,
                                int32_t rounds, uint8_t *primer_out, uint8_t *plain_out) {
    int L = length;
    uint8_t *plain = plain_out;
    uint8_t *saved = (uint8_t *)malloc((size_t)(n > 0 ? n : 1));
    memset(plain, 0, (size_t)(n > 0 ? n : 0));
    for (int j = 0; j < L; j++) primer_out[j] = 0;
    /* 1. chi-squared start, chain by chain */
    for (int j = 0; j < L; j++) {
        double best = 0.0;
        int best_s = -1;
        for (int s = 0; s < 26; s++) {
            int counts[26] = {0}, total = 0;
            ak_chain(cipher, n, L, j, s, kind, variant, plain);
            for (int i = j; i < n; i += L) { counts[plain[i]]++; total++; }
            double score = ak_chi(counts, total);
            if (best_s < 0 || score < best) { best = score; best_s = s; }
        }
        primer_out[j] = (uint8_t)best_s;
    }
    for (int j = 0; j < L; j++) ak_chain(cipher, n, L, j, primer_out[j], kind, variant, plain);
    double score = n > 5 ? cct_fitness(plain, n, scores, size, weight, fixed_factor) : 0.0;
    /* 2. coordinate hill-climb over the primer letters */
    for (int round = 0; round < rounds; round++) {
        int improved = 0;
        for (int j = 0; j < L; j++) {
            int keep = primer_out[j];
            for (int s = 0; s < 26; s++) {
                if (s == keep) continue;
                for (int i = j; i < n; i += L) saved[i] = plain[i];
                ak_chain(cipher, n, L, j, s, kind, variant, plain);
                double trial = cct_fitness(plain, n, scores, size, weight, fixed_factor);
                if (trial > score + 1e-9) {
                    score = trial; keep = s; improved = 1;
                } else {
                    for (int i = j; i < n; i += L) plain[i] = saved[i];
                }
            }
            primer_out[j] = (uint8_t)keep;
        }
        if (!improved) break;
    }
    free(saved);
    return score;
}
