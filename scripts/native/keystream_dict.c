/* Autokey word-list primer search: autoclave.py (dictionary_attack).
 *
 * Every word is tried as the primer for each requested autokey kind and
 * tableau (bit kind*2 + variant of `combos`: kind 0 = plaintext autokey,
 * 1 = ciphertext autokey; variant 0 = Vigenere p = c - k, 1 = Beaufort
 * p = k - c, mod 26). Each decryption is scored with annealing.Fitness
 * (cct_fitness) and checked for the known phrases (all must occur, as
 * attack_support.contains_all_phrases; no phrases = no match).
 *
 * The best `keep` candidates of words first..first+count-1 are returned,
 * ordered by (phrase match first, fitness descending, word index ascending,
 * combo ascending). Python merges the batches with the same order, so the
 * merged top `keep` is exact. */
#pragma STDC FP_CONTRACT OFF
#include "cct_common.h"

typedef struct { int64_t word; int32_t combo, phrase; double score; } AkdRow;

/* 1 when a ranks before b. */
static inline int akd_before(const AkdRow *a, const AkdRow *b) {
    if (a->phrase != b->phrase) return a->phrase > b->phrase;
    if (a->score != b->score) return a->score > b->score;
    if (a->word != b->word) return a->word < b->word;
    return a->combo < b->combo;
}

static void akd_decrypt(const uint8_t *cipher, int n, const uint8_t *primer, int L, int kind, int variant,
                        uint8_t *plain) {
    for (int i = 0; i < n; i++) {
        int k = i < L ? primer[i] : (kind == 0 ? plain[i - L] : cipher[i - L]);
        int p = (variant == 0 ? cipher[i] - k : k - cipher[i]) % 26;
        plain[i] = (uint8_t)(p < 0 ? p + 26 : p);
    }
}

static int akd_contains(const uint8_t *text, int n, const uint8_t *pattern, int m) {
    if (m == 0) return 1;
    for (int i = 0; i + m <= n; i++) {
        if (text[i] != pattern[0]) continue;
        int j = 1;
        while (j < m && text[i + j] == pattern[j]) j++;
        if (j == m) return 1;
    }
    return 0;
}

/* keys: the words' letter codes joined; offsets[w]..offsets[w+1] is word w.
 * phrases: letter codes joined (255 = a character that can never match);
 * phrase_offsets[p]..phrase_offsets[p+1] is phrase p.
 * Writes up to `keep` rows (sorted) and returns how many; -1 on bad input
 * (a code above 25, a bad combo mask) or when memory runs out. */
EXPORT int32_t cct_autokey_dict(const uint8_t *cipher, int32_t n, const uint8_t *keys, const int64_t *offsets,
                                int64_t first, int64_t count, int32_t combos, const uint8_t *scores, int32_t size,
                                double weight, double fixed_factor, const uint8_t *phrases,
                                const int32_t *phrase_offsets, int32_t nphrases, int32_t keep, int64_t *out_word,
                                int32_t *out_combo, double *out_score, int32_t *out_phrase) {
    if (n < 0 || keep < 0 || count < 0 || combos <= 0 || combos > 15) return -1;
    for (int i = 0; i < n; i++) if (cipher[i] > 25) return -1;
    if (keep == 0 || count == 0) return 0;
    uint8_t *plain = (uint8_t *)malloc((size_t)(n > 0 ? n : 1));
    AkdRow *rows = (AkdRow *)malloc(sizeof(AkdRow) * (size_t)keep);
    if (!plain || !rows) { free(plain); free(rows); return -1; }
    int32_t kept = 0, worst = 0;
    for (int64_t w = first; w < first + count; w++) {
        const uint8_t *primer = keys + offsets[w];
        int L = (int)(offsets[w + 1] - offsets[w]);
        if (L < 1) continue;
        int bad = 0;
        for (int j = 0; j < L; j++) if (primer[j] > 25) { bad = 1; break; }
        if (bad) continue;
        for (int combo = 0; combo < 4; combo++) {
            if (!(combos >> combo & 1)) continue;
            akd_decrypt(cipher, n, primer, L, combo >> 1, combo & 1, plain);
            AkdRow row = {w, combo, 0, cct_fitness(plain, n, scores, size, weight, fixed_factor)};
            if (nphrases > 0) {
                row.phrase = 1;
                for (int p = 0; p < nphrases && row.phrase; p++)
                    row.phrase = akd_contains(plain, n, phrases + phrase_offsets[p],
                                              phrase_offsets[p + 1] - phrase_offsets[p]);
            }
            if (kept < keep) {
                rows[kept++] = row;
                if (kept == keep) {
                    worst = 0;
                    for (int r = 1; r < kept; r++) if (akd_before(&rows[worst], &rows[r])) worst = r;
                }
            } else if (akd_before(&row, &rows[worst])) {
                rows[worst] = row;
                worst = 0;
                for (int r = 1; r < kept; r++) if (akd_before(&rows[worst], &rows[r])) worst = r;
            }
        }
    }
    for (int i = 1; i < kept; i++) {                 /* insertion sort: keep is small */
        AkdRow r = rows[i];
        int j = i - 1;
        while (j >= 0 && akd_before(&r, &rows[j])) { rows[j + 1] = rows[j]; j--; }
        rows[j + 1] = r;
    }
    for (int i = 0; i < kept; i++) {
        out_word[i] = rows[i].word; out_combo[i] = rows[i].combo;
        out_score[i] = rows[i].score; out_phrase[i] = rows[i].phrase;
    }
    free(rows);
    free(plain);
    return kept;
}
