/* Keyed-alphabet (Quagmire) periodic fit: keyword_periodic.py */
#include "cct_common.h"

/* ct_pos[cipher letter] = its position in the cipher alphabet; pt_letter[position]
 * = the plaintext letter there (mode 1: PA keyed, CA straight; 2: PA straight,
 * CA keyed; 3: both keyed). */
static void tables(const uint8_t *alpha, int mode, int32_t *ct_pos, int32_t *pt_letter) {
    for (int i = 0; i < 26; i++) {
        if (mode == 2) pt_letter[i] = i; else pt_letter[i] = alpha[i];
        if (mode == 1) ct_pos[i] = i;
    }
    if (mode != 1) for (int i = 0; i < 26; i++) ct_pos[alpha[i]] = i;
}

static double best_shift(const int32_t *cnt, const int32_t *ct_pos, const int32_t *pt_letter, int variant,
                         const double *inv_e, int32_t *best_k);

/* Letters in each of the `period` columns (counts: period x 26), in a new
 * array (NULL when period < 1 or out of memory). */
static int32_t *column_totals(const int32_t *counts, int32_t period) {
    if (period < 1) return NULL;
    int32_t *total = malloc(sizeof(int32_t) * (size_t)period);
    if (!total) return NULL;
    for (int col = 0; col < period; col++) {
        total[col] = 0;
        for (int c = 0; c < 26; c++) total[col] += counts[(size_t)col * 26 + c];
    }
    return total;
}

/* Sum over the columns of the lowest chi-squared of each (empty columns add 0). */
static double alphabet_chi(const int32_t *counts, const int32_t *total, int32_t period, const int32_t *ct_pos,
                           const int32_t *pt_letter, int variant, const double *inv_e, double sum_e) {
    double chi_sum = 0.0;
    for (int col = 0; col < period; col++) {
        if (!total[col]) continue;
        int32_t k;
        double best = best_shift(counts + (size_t)col * 26, ct_pos, pt_letter, variant, inv_e, &k);
        chi_sum += best / total[col] - 2.0 * total[col] + sum_e * total[col];
    }
    return chi_sum;
}

/* Lowest sum(plain^2 / e) over the 26 shifts of one column (chi = that / total
 * - 2 total + sum(e) total, with e = expected * total); *best_k = first best shift. */
static double best_shift(const int32_t *cnt, const int32_t *ct_pos, const int32_t *pt_letter, int variant,
                         const double *inv_e, int32_t *best_k) {
    double best = 1e300;
    *best_k = 0;
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
        if (s2 < best) { best = s2; *best_k = k; }
    }
    return best;
}

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
    int32_t *total = column_totals(counts, period);
    if (!total) { for (int a = 0; a < m; a++) chi_out[a] = NAN; return; }
    double inv_e[26];
    double sum_e = 0.0;
    for (int p = 0; p < 26; p++) { inv_e[p] = 1.0 / expected[p]; sum_e += expected[p]; }
    for (int a = 0; a < m; a++) {
        int32_t ct_pos[26], pt_letter[26];
        tables(alphabets + (size_t)a * 26, mode, ct_pos, pt_letter);
        chi_out[a] = alphabet_chi(counts, total, period, ct_pos, pt_letter, variant, inv_e, sum_e);
    }
    free(total);
}

/* The shift chosen for every column (the first k with the lowest chi-squared):
 * keyword_periodic.solve_alphabet's key. shift_out: period values 0-25. */
EXPORT void cct_keyed_periodic_shifts(const int32_t *counts, int32_t period, const uint8_t *alphabet, int32_t mode,
                                      int32_t variant, const double *expected, int32_t *shift_out) {
    double inv_e[26];
    for (int p = 0; p < 26; p++) inv_e[p] = 1.0 / expected[p];
    int32_t ct_pos[26], pt_letter[26];
    tables(alphabet, mode, ct_pos, pt_letter);
    for (int col = 0; col < period; col++)
        best_shift(counts + (size_t)col * 26, ct_pos, pt_letter, variant, inv_e, &shift_out[col]);
}


/* As cct_keyed_periodic_chi (identical values), but only the `keep` lowest
 * totals are returned: best_chi / best_index sorted by (chi, index), index =
 * index_base + alphabet number. Returns the number kept (<= keep): 0 when
 * keep < 1 or period < 1, -1 when out of memory. Columns may be empty (they add
 * 0). */
EXPORT int32_t cct_keyed_periodic_best(const int32_t *counts, int32_t period, const uint8_t *alphabets, int32_t m,
                                       int32_t index_base, int32_t mode, int32_t variant, const double *expected,
                                       int32_t keep, double *best_chi, int32_t *best_index) {
    if (keep < 1 || period < 1 || m < 1) return 0;
    int32_t *total = column_totals(counts, period);
    if (!total) return -1;
    double inv_e[26];
    double sum_e = 0.0;
    int kept = 0;
    for (int p = 0; p < 26; p++) { inv_e[p] = 1.0 / expected[p]; sum_e += expected[p]; }
    for (int a = 0; a < m; a++) {
        int32_t ct_pos[26], pt_letter[26];
        tables(alphabets + (size_t)a * 26, mode, ct_pos, pt_letter);
        double chi_sum = alphabet_chi(counts, total, period, ct_pos, pt_letter, variant, inv_e, sum_e);
        if (kept < keep || chi_sum < best_chi[kept - 1]) {
            /* indexes rise, so an equal total never displaces an earlier one */
            int j = kept < keep ? kept++ : keep - 1;
            while (j > 0 && chi_sum < best_chi[j - 1]) { best_chi[j] = best_chi[j - 1]; best_index[j] = best_index[j - 1]; j--; }
            best_chi[j] = chi_sum; best_index[j] = index_base + a;
        }
    }
    free(total);
    return kept;
}
