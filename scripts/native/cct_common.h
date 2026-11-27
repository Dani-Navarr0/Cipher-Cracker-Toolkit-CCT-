/* Shared helpers for the toolkit's C engines (header only: every engine file
 * includes it; all functions are static so each .c file gets its own copy).
 *
 * Fitness: identical to annealing.Fitness in Python,
 *   mean n-gram score (bytes 0-255 from the n-gram table) * letter_entropy^weight
 * with letter_entropy = -sum p log2 p over the 26 letter codes.
 * Annealing: geometric cooling from t_start to t_end over `iterations` moves,
 * accept if diff >= 0 or rand < exp(diff / T) (defaults in annealing.Schedule).
 */
#ifndef CCT_COMMON_H
#define CCT_COMMON_H

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

/* ---- random numbers: xoshiro256** (seeded from Python's random) */
typedef struct { uint64_t s[4]; } Rng;
static inline uint64_t cct_rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
static inline uint64_t rng_next(Rng *r) {
    uint64_t result = cct_rotl(r->s[1] * 5, 7) * 9, t = r->s[1] << 17;
    r->s[2] ^= r->s[0]; r->s[3] ^= r->s[1]; r->s[1] ^= r->s[2]; r->s[0] ^= r->s[3];
    r->s[2] ^= t; r->s[3] = cct_rotl(r->s[3], 45);
    return result;
}
static inline double rng_double(Rng *r) { return (double)(rng_next(r) >> 11) * (1.0 / 9007199254740992.0); }
static inline int rng_below(Rng *r, int n) { return (int)(rng_double(r) * n); }
/* Seed from one 64-bit value (splitmix64), so Python can pass random.getrandbits(64). */
static inline void rng_seed(Rng *r, uint64_t seed) {
    for (int i = 0; i < 4; i++) {
        uint64_t z = (seed += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        r->s[i] = z ^ (z >> 31);
    }
}

/* ---- n-gram scoring */
static inline int64_t cct_ngram_modulus(int size) {
    int64_t m = 1;
    for (int i = 0; i < size - 1; i++) m *= 26;
    return m;
}
/* ngram_scoring.ngram_total: sum of table scores of every overlapping n-gram (codes 0-25). */
static inline int64_t cct_total(const uint8_t *codes, int n, const uint8_t *scores, int size) {
    if (n < size) return 0;
    int64_t modulus = cct_ngram_modulus(size), index = 0, total = 0;
    for (int i = 0; i < size - 1; i++) index = index * 26 + codes[i];
    for (int i = size - 1; i < n; i++) { index = (index % modulus) * 26 + codes[i]; total += scores[index]; }
    return total;
}
/* letter_entropy(codes) ** weight (annealing.letter_entropy). */
static inline double cct_entropy_factor(const uint8_t *codes, int n, double weight) {
    if (n <= 0) return 0.0;
    int counts[26] = {0};
    for (int i = 0; i < n; i++) counts[codes[i]]++;
    double entropy = 0.0;
    for (int c = 0; c < 26; c++) if (counts[c]) { double p = (double)counts[c] / n; entropy -= p * log2(p); }
    return pow(entropy, weight);
}
/* annealing.Fitness: fixed_factor < 0 means "recompute the entropy factor". */
static inline double cct_fitness(const uint8_t *codes, int n, const uint8_t *scores, int size, double weight,
                                 double fixed_factor) {
    int count = n - size + 1;
    if (count <= 0) return -9999.0;
    double factor = fixed_factor >= 0 ? fixed_factor : cct_entropy_factor(codes, n, weight);
    return (double)cct_total(codes, n, scores, size) / count * factor;
}

/* ---- annealing schedule (annealing.Schedule) */
static inline double cct_cooling_ratio(double t_start, double t_end, int64_t iterations) {
    return pow(t_end / t_start, 1.0 / (double)(iterations > 0 ? iterations : 1));
}
static inline int cct_accept(Rng *rng, double diff, double temperature) {
    return diff >= 0 || rng_double(rng) < exp(diff / temperature);
}

#endif
