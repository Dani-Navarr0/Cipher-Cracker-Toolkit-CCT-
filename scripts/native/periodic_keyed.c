/* Keyed-alphabet (Quagmire) periodic fit: keyword_periodic.py */
#include "cct_common.h"

#define MAXP 128

/* Periodic key on keyed alphabets (Quagmire family), one total chi-squared per
 * alphabet: each column's shift is the one whose decryption best matches
 * English letter frequencies.
 *   decrypt (variant 0, Vigenere): p = PA[(CApos(c) - k) mod 26]
 *   decrypt (variant 1, Beaufort): p = PA[(k - CApos(c)) mod 26]
 * mode 3: PA = CA = alphabet; mode 1: PA = alphabet, CA = straight;
 * mode 2: PA = straight, CA = alphabet.
 * counts: period x 26 cipher-letter counts; alphabets: m x 26 letter codes. */
EXPORT void cct_keyed_periodic_chi(const int32_t *counts, int32_t period, const uint8_t *alphabets, int32_t m,
                                   int32_t mode, int32_t variant, const double *expected, double *chi_out) {
    int32_t total[MAXP];
    double inv_e[26];
    double sum_e = 0.0;
    for (int p = 0; p < 26; p++) { inv_e[p] = 1.0 / expected[p]; sum_e += expected[p]; }
    for (int col = 0; col < period; col++) {
        total[col] = 0;
        for (int c = 0; c < 26; c++) total[col] += counts[col * 26 + c];
    }
    for (int a = 0; a < m; a++) {
        const uint8_t *alpha = alphabets + a * 26;
        int32_t ct_pos[26], pt_letter[26];
        for (int i = 0; i < 26; i++) {
            if (mode == 2) pt_letter[i] = i; else pt_letter[i] = alpha[i];
            if (mode == 1) ct_pos[i] = i;
        }
        if (mode != 1) for (int i = 0; i < 26; i++) ct_pos[alpha[i]] = i;
        double chi_sum = 0.0;
        for (int col = 0; col < period; col++) {
            const int32_t *cnt = counts + col * 26;
            /* chi = sum(plain^2 / e) - 2 total + sum(e), with e = expected * total */
            double best = 1e300;
            for (int k = 0; k < 26; k++) {
                double s2 = 0.0;
                for (int c = 0; c < 26; c++) {
                    if (!cnt[c]) continue;
                    int pos = variant == 0 ? ct_pos[c] - k : k - ct_pos[c];
                    pos %= 26; if (pos < 0) pos += 26;
                    /* distinct cipher letters map to distinct plaintext letters */
                    int p = pt_letter[pos];
                    s2 += (double)cnt[c] * cnt[c] * inv_e[p];
                }
                if (s2 < best) best = s2;
            }
            chi_sum += best / total[col] - 2.0 * total[col] + sum_e * total[col];
        }
        chi_out[a] = chi_sum;
    }
}

