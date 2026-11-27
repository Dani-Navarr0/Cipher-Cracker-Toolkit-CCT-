/* Fractionation (Bifid/Trifid) and Four-square engines */
#include "cct_common.h"

/* Fractionation (Bifid: dims 2, side 5; Trifid: dims 3, side 3) decryption.
 * cipher: symbol indices; cell_of[symbol] = cell (0..side^dims-1);
 * grid[cell] = symbol. Per block of `period` symbols (0 = whole text): the
 * cipher symbols' coordinates, in order, form dims rows of the block length;
 * plaintext symbol k has coordinates (row 0 [k], row 1 [k], ...). */
EXPORT void cct_fraction_decrypt(const uint8_t *cipher, int32_t n, int32_t period, int32_t dims, int32_t side,
                                 const uint8_t *cell_of, const uint8_t *grid, uint8_t *out) {
    uint8_t *seq = (uint8_t *)malloc((size_t)n * (size_t)dims + 1);
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
