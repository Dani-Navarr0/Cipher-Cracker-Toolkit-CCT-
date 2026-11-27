/* Reference statistics for cipher_profile.py (the Unknown Cipher Analyzer,
 * and every tool that judges results against same-length references): column IoC against shuffled copies of the ciphertext and
 * English samples (periodicity), and the per-text statistics of the reference
 * samples (references). Definitions are those of cipher_profile.ioc,
 * chi_squared, adjacency, column_ioc and annealing.Fitness; integer counts, so
 * ioc, adjacency and column IoC equal the Python values exactly. */
#include "cct_common.h"

/* cipher_profile.column_ioc: IoC of every period-th letter, pooled. counts: period x 26 scratch. */
static double column_ioc(const uint8_t *t, int n, int period, int32_t *counts) {
    memset(counts, 0, sizeof(int32_t) * 26 * (size_t)period);
    for (int i = 0, col = 0; i < n; i++) {
        counts[col * 26 + (t[i] % 26)]++;
        if (++col == period) col = 0;
    }
    int64_t numerator = 0, denominator = 0;
    for (int col = 0; col < period; col++) {
        int64_t len = 0;
        for (int c = 0; c < 26; c++) {
            int64_t k = counts[col * 26 + c];
            numerator += k * (k - 1);
            len += k;
        }
        denominator += len * (len - 1);
    }
    return denominator ? (double)numerator / (double)denominator : 0.0;
}

/* Column IoC for periods 1..max_period of: the ciphertext (value_out[p - 1]);
 * `samples` successive Fisher-Yates shuffles of it per period (chance_out[(p - 1)
 * * samples + s], one generator seeded with `seed` runs through all periods);
 * and the `samples` English texts of n letters (english_out, same layout).
 * Returns 0, or -1 when memory runs out. */
EXPORT int32_t cct_screens_periodicity(const uint8_t *codes, int32_t n, int32_t max_period, int32_t samples,
                                       uint64_t seed, const uint8_t *english, double *value_out,
                                       double *chance_out, double *english_out) {
    int32_t *counts = malloc(sizeof(int32_t) * 26 * (size_t)(max_period > 0 ? max_period : 1));
    uint8_t *letters = malloc((size_t)(n > 0 ? n : 1));
    if (!counts || !letters) { free(counts); free(letters); return -1; }
    memcpy(letters, codes, (size_t)n);
    Rng rng;
    rng_seed(&rng, seed);
    for (int period = 1; period <= max_period; period++) {
        double *chance = chance_out + (size_t)(period - 1) * samples;
        double *eng = english_out + (size_t)(period - 1) * samples;
        for (int s = 0; s < samples; s++) {
            for (int i = n - 1; i > 0; i--) {
                int j = rng_below(&rng, i + 1);
                uint8_t x = letters[i]; letters[i] = letters[j]; letters[j] = x;
            }
            chance[s] = column_ioc(letters, n, period, counts);
            eng[s] = column_ioc(english + (size_t)s * n, n, period, counts);
        }
        value_out[period - 1] = column_ioc(codes, n, period, counts);
    }
    free(counts); free(letters);
    return 0;
}

/* cipher_profile.ioc on letter counts */
static double ioc_of(const int32_t *counts, int n) {
    if (n < 2) return 0.0;
    int64_t numerator = 0;
    for (int c = 0; c < 26; c++) numerator += (int64_t)counts[c] * (counts[c] - 1);
    return (double)numerator / ((double)n * (double)(n - 1));
}

/* Per text of `length` letter codes (count texts, packed): IoC, chi-squared
 * against `english_percent` (26 letter frequencies in percent, as
 * layered.ENGLISH_FREQUENCIES), adjacency and annealing.Fitness (entropy
 * recomputed, exponent `weight`). Any output pointer may be NULL. */
EXPORT void cct_screens_text_stats(const uint8_t *texts, int32_t count, int32_t length, const uint8_t *scores,
                                   int32_t size, double weight, const double *english_percent, double *ioc_out,
                                   double *chi_out, double *adjacency_out, double *fitness_out) {
    int32_t pairs_count[676];
    for (int t = 0; t < count; t++) {
        const uint8_t *text = texts + (size_t)t * length;
        int32_t counts[26] = {0};
        for (int i = 0; i < length; i++) counts[text[i] % 26]++;
        double letters_ioc = ioc_of(counts, length);
        if (ioc_out) ioc_out[t] = letters_ioc;
        if (chi_out) {
            double chi = 0.0;
            if (length) {
                for (int c = 0; c < 26; c++) {
                    double expected = english_percent[c] * (double)length / 100.0;
                    double d = (double)counts[c] - expected;
                    chi += d * d / expected;
                }
            }
            chi_out[t] = chi;
        }
        if (adjacency_out) {
            int pairs = length - 1;
            double value = 0.0;
            if (pairs >= 2 && letters_ioc > 0) {
                memset(pairs_count, 0, sizeof pairs_count);
                for (int i = 0; i + 1 < length; i++) pairs_count[(text[i] % 26) * 26 + text[i + 1] % 26]++;
                int64_t numerator = 0;
                for (int k = 0; k < 676; k++) numerator += (int64_t)pairs_count[k] * (pairs_count[k] - 1);
                double pair_ioc = (double)numerator / ((double)pairs * (double)(pairs - 1));
                value = pair_ioc / (letters_ioc * letters_ioc);
            }
            adjacency_out[t] = value;
        }
        if (fitness_out) fitness_out[t] = cct_fitness(text, length, scores, size, weight, -1.0);
    }
}

/* Reference samples: shuffled_out[t] = a Fisher-Yates shuffle of english[t];
 * uniform_out = count texts of uniformly random letters. One generator seeded
 * with `seed`, shuffles first. Either output may be NULL. */
EXPORT void cct_screens_reference_samples(const uint8_t *english, int32_t count, int32_t length, uint64_t seed,
                                          uint8_t *shuffled_out, uint8_t *uniform_out) {
    Rng rng;
    rng_seed(&rng, seed);
    if (shuffled_out) {
        for (int t = 0; t < count; t++) {
            uint8_t *out = shuffled_out + (size_t)t * length;
            memcpy(out, english + (size_t)t * length, (size_t)length);
            for (int i = length - 1; i > 0; i--) {
                int j = rng_below(&rng, i + 1);
                uint8_t x = out[i]; out[i] = out[j]; out[j] = x;
            }
        }
    }
    if (uniform_out)
        for (size_t i = 0; i < (size_t)count * length; i++) uniform_out[i] = (uint8_t)rng_below(&rng, 26);
}
