/* Gromark engines: gromark_solver.py */
#include "cct_common.h"

/* Gromark primer screen (straight plaintext alphabet, unknown mixed cipher
 * alphabet). Keystream: primer digits, then d[i] = (d[i-L] + d[i-L+1]) mod base.
 * c = CA[(p + sign*d) mod 26], so p = s(c) - sign*d with s unknown per cipher
 * letter: for the right primer, the plaintext letters under one cipher letter
 * lie in a window of `base` consecutive letters. Score = sum over cipher
 * letters of max over s of sum log P_english(s - sign*d). Higher = better.
 * Primers first..first+count-1 in base `base`, `plen` digits. */
EXPORT void cct_gromark_scores(const uint8_t *cipher, int32_t n, int32_t base, int32_t plen, int32_t sign,
                               const double *logp, int64_t first, int64_t count, double *out) {
    int32_t *digits = (int32_t *)malloc(sizeof(int32_t) * (size_t)n);
    for (int64_t q = 0; q < count; q++) {
        int64_t value = first + q;
        for (int i = plen - 1; i >= 0; i--) { digits[i < n ? i : 0] = (int32_t)(value % base); value /= base; }
        for (int i = plen; i < n; i++) digits[i] = (digits[i - plen] + digits[i - plen + 1]) % base;
        int32_t hist[26][32];
        memset(hist, 0, sizeof(hist));
        for (int i = 0; i < n; i++) hist[cipher[i]][digits[i]]++;
        double score = 0.0;
        for (int c = 0; c < 26; c++) {
            double best = -1e300;
            int any = 0;
            for (int d = 0; d < base; d++) if (hist[c][d]) { any = 1; break; }
            if (!any) continue;
            for (int s = 0; s < 26; s++) {
                double v = 0.0;
                for (int d = 0; d < base; d++) {
                    if (!hist[c][d]) continue;
                    int p = (s - sign * d) % 26; if (p < 0) p += 26;
                    v += hist[c][d] * logp[p];
                }
                if (v > best) best = v;
            }
            score += best;
        }
        out[q] = score;
    }
    free(digits);
}

