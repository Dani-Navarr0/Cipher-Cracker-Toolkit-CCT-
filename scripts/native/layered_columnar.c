/* Columnar-transposition searches of tool 45 (columnar_transposition.py):
 *  - cct_columnar_topk: every column order after a fixed prefix (resumable), the
 *    k best by n-gram total (ties: the lexicographically earlier order), plus
 *    every order whose decryption contains all the required words;
 *  - cct_columnar_score_orders: the n-gram total of each order in a list (the
 *    dictionary attack), with the same required-word check;
 *  - cct_double_columnar: double columnar, every key2 x every key1 (key strings
 *    as permutations of '01..', in the order itertools.permutations gives them),
 *    keeping the best total; ties go to the earliest (key1 index, key2 index).
 * Decryption: plaintext position i reads ciphertext position start[col] + base,
 * rank[col] + base or partial_base + prank[col] (native.columnar_descriptors,
 * the permutation of transposition_core.make_permuter). */
#include "cct_common.h"

#define CMAXW 64

/* Same field layout as cct_native.c's Layout and native.Layout (ctypes). */
typedef struct {
    int32_t n;
    const uint8_t *cipher;
    int32_t width, read_rows, remainder, partial_base;
    const int32_t *col_len, *d_col, *d_base, *d_kind;
} Layout;

static void columnar_decrypt(const Layout *t, const uint8_t *key, const uint8_t *in, uint8_t *out) {
    int32_t start[CMAXW], rank[CMAXW], prank[CMAXW];
    int w = t->width, n = t->n;
    if (!t->read_rows) {
        int32_t s = 0;
        for (int j = 0; j < w; j++) { start[key[j]] = s; s += t->col_len[key[j]]; }
        for (int i = 0; i < n; i++) out[i] = in[start[t->d_col[i]] + t->d_base[i]];
    } else {
        int pr = 0;
        for (int j = 0; j < w; j++) { rank[key[j]] = j; if (key[j] < t->remainder) prank[key[j]] = pr++; }
        for (int i = 0; i < n; i++)
            out[i] = in[t->d_kind[i] == 2 ? t->partial_base + prank[t->d_col[i]] : rank[t->d_col[i]] + t->d_base[i]];
    }
}

static int next_perm(uint8_t *a, int n) {
    int i = n - 2;
    while (i >= 0 && a[i] >= a[i + 1]) i--;
    if (i < 0) return 0;
    int j = n - 1;
    while (a[j] <= a[i]) j--;
    uint8_t t = a[i]; a[i] = a[j]; a[j] = t;
    for (int l = i + 1, r = n - 1; l < r; l++, r--) { t = a[l]; a[l] = a[r]; a[r] = t; }
    return 1;
}

/* words: the required words' letter codes, concatenated; word_len: their lengths. */
static int contains_all(const uint8_t *text, int n, const uint8_t *words, const int32_t *word_len, int nwords) {
    const uint8_t *word = words;
    for (int w = 0; w < nwords; w++) {
        int len = word_len[w], found = len == 0;
        for (int i = 0; !found && i + len <= n; i++)
            if (text[i] == word[0] && memcmp(text + i, word, (size_t)len) == 0) found = 1;
        if (!found) return 0;
        word += len;
    }
    return 1;
}

/* heap order: a is worse than b (lower total, or equal total and later order) */
static int worse(int64_t ta, const uint8_t *ka, int64_t tb, const uint8_t *kb, int w) {
    if (ta != tb) return ta < tb;
    return memcmp(ka, kb, (size_t)w) > 0;
}

static void sift_down(int64_t *tot, uint8_t *keys, int count, int i, int w) {
    uint8_t tmp[CMAXW];
    for (;;) {
        int l = 2 * i + 1, r = l + 1, m = i;
        if (l < count && worse(tot[l], keys + (size_t)l * CMAXW, tot[m], keys + (size_t)m * CMAXW, w)) m = l;
        if (r < count && worse(tot[r], keys + (size_t)r * CMAXW, tot[m], keys + (size_t)m * CMAXW, w)) m = r;
        if (m == i) return;
        int64_t t = tot[i]; tot[i] = tot[m]; tot[m] = t;
        memcpy(tmp, keys + (size_t)i * CMAXW, CMAXW);
        memcpy(keys + (size_t)i * CMAXW, keys + (size_t)m * CMAXW, CMAXW);
        memcpy(keys + (size_t)m * CMAXW, tmp, CMAXW);
        i = m;
    }
}

static void sift_up(int64_t *tot, uint8_t *keys, int i, int w) {
    uint8_t tmp[CMAXW];
    while (i > 0) {
        int p = (i - 1) / 2;
        if (!worse(tot[i], keys + (size_t)i * CMAXW, tot[p], keys + (size_t)p * CMAXW, w)) return;
        int64_t t = tot[i]; tot[i] = tot[p]; tot[p] = t;
        memcpy(tmp, keys + (size_t)i * CMAXW, CMAXW);
        memcpy(keys + (size_t)i * CMAXW, keys + (size_t)p * CMAXW, CMAXW);
        memcpy(keys + (size_t)p * CMAXW, tmp, CMAXW);
        i = p;
    }
}

/* Every column order after prefix_len fixed columns, from `key` (resumable: it
 * is left at the next order to test), for at most max_orders orders.
 * heap_totals/heap_keys (k entries, keys CMAXW bytes each) hold the k best seen
 * so far as a min-heap (*nkept entries); the caller sorts them at the end.
 * With nwords > 0, every order whose decryption contains all the words is also
 * recorded in match_keys/match_totals (up to max_matches; *nmatch counts all).
 * Returns the orders processed; *done = 1 after the last order. */
EXPORT int64_t cct_columnar_topk(const Layout *t, const uint8_t *scores, int32_t size, int32_t prefix_len,
                                 uint8_t *key, int64_t max_orders, int32_t k, int64_t *heap_totals,
                                 uint8_t *heap_keys, int32_t *nkept, const uint8_t *words, const int32_t *word_len,
                                 int32_t nwords, uint8_t *match_keys, int64_t *match_totals, int32_t max_matches,
                                 int64_t *nmatch, int32_t *done) {
    int w = t->width, n = t->n;
    uint8_t *buf = malloc((size_t)n);
    if (!buf) return 0;
    int64_t processed = 0;
    *done = 0;
    while (processed < max_orders) {
        columnar_decrypt(t, key, t->cipher, buf);
        int64_t total = cct_total(buf, n, scores, size);
        if (*nkept < k) {
            heap_totals[*nkept] = total;
            memcpy(heap_keys + (size_t)*nkept * CMAXW, key, (size_t)w);
            sift_up(heap_totals, heap_keys, *nkept, w);
            (*nkept)++;
        } else if (k > 0 && worse(heap_totals[0], heap_keys, total, key, w)) {
            heap_totals[0] = total;
            memcpy(heap_keys, key, (size_t)w);
            sift_down(heap_totals, heap_keys, k, 0, w);
        }
        if (nwords > 0 && contains_all(buf, n, words, word_len, nwords)) {
            if (*nmatch < max_matches) {
                memcpy(match_keys + (size_t)*nmatch * CMAXW, key, (size_t)w);
                match_totals[*nmatch] = total;
            }
            (*nmatch)++;
        }
        processed++;
        if (!next_perm(key + prefix_len, w - prefix_len)) { *done = 1; break; }
    }
    free(buf);
    return processed;
}

/* The n-gram total of the decryption under each of `count` orders (width bytes
 * each, packed); match_out[i] = 1 when it contains all the required words. */
EXPORT void cct_columnar_score_orders(const Layout *t, const uint8_t *scores, int32_t size, const uint8_t *orders,
                                      int64_t count, const uint8_t *words, const int32_t *word_len, int32_t nwords,
                                      int64_t *totals_out, uint8_t *match_out) {
    int w = t->width, n = t->n;
    uint8_t *buf = malloc((size_t)n);
    if (!buf) return;
    for (int64_t i = 0; i < count; i++) {
        columnar_decrypt(t, orders + (size_t)i * w, t->cipher, buf);
        totals_out[i] = cct_total(buf, n, scores, size);
        match_out[i] = (uint8_t)(nwords > 0 && contains_all(buf, n, words, word_len, nwords));
    }
    free(buf);
}

/* Double columnar transposition. key strings are permutations of 0..w-1 (the
 * characters '0'..'7' of tool 45); a key string's read order is its inverse
 * (columns sorted by their character). outer: the second key's layout on the
 * ciphertext (width w2); inner: the first key's layout (width w1; its cipher
 * field is ignored: it reads the intermediate text).
 * key2 (resumable cursor) starts at index j_base and advances for at most
 * max_outer key2 strings; for each, every key1 string from 0123.. in order.
 * Keeps the best total; ties go to the smaller (i, j) (key1 index first).
 * best_*: in/out (best_total starts at -1). Returns key2 strings processed. */
EXPORT int64_t cct_double_columnar(const Layout *outer, const Layout *inner, const uint8_t *scores, int32_t size,
                                   uint8_t *key2, int64_t j_base, int64_t max_outer, int64_t *best_total,
                                   int64_t *best_i, int64_t *best_j, uint8_t *best_key1, uint8_t *best_key2,
                                   int32_t *done) {
    int n = outer->n, w1 = inner->width, w2 = outer->width;
    uint8_t *mid = malloc((size_t)n), *plain = malloc((size_t)n);
    if (!mid || !plain) { free(mid); free(plain); return 0; }
    uint8_t key1[CMAXW], order1[CMAXW], order2[CMAXW];
    int64_t processed = 0;
    *done = 0;
    while (processed < max_outer) {
        int64_t j = j_base + processed;
        for (int c = 0; c < w2; c++) order2[key2[c]] = (uint8_t)c;
        columnar_decrypt(outer, order2, outer->cipher, mid);
        for (int c = 0; c < w1; c++) key1[c] = (uint8_t)c;
        int64_t i = 0;
        do {
            for (int c = 0; c < w1; c++) order1[key1[c]] = (uint8_t)c;
            columnar_decrypt(inner, order1, mid, plain);
            int64_t total = cct_total(plain, n, scores, size);
            if (total > *best_total || (total == *best_total && (i < *best_i || (i == *best_i && j < *best_j)))) {
                *best_total = total; *best_i = i; *best_j = j;
                memcpy(best_key1, key1, (size_t)w1);
                memcpy(best_key2, key2, (size_t)w2);
            }
            i++;
        } while (next_perm(key1, w1));
        processed++;
        if (!next_perm(key2, w2)) { *done = 1; break; }
    }
    free(mid); free(plain);
    return processed;
}
