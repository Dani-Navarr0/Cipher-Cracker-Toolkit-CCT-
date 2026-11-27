/* Gromark engines: gromark_solver.py */
#pragma STDC FP_CONTRACT OFF   /* bit-exact annealing.Fitness: no fused multiply-add */
#include "cct_common.h"

#define GROMARK_MAX_BASE 32

/* Input guards (the Python wrappers raise ValueError first): cipher codes must
 * be 0-25, the base 2-32 (histogram width) and the primer at least 2 digits
 * (chain addition reads d[i-L+1]). Bad input returns early instead of
 * indexing outside the histograms. */
static int gm_codes_ok(const uint8_t *cipher, int32_t n) {
    if (n < 0) return 0;
    for (int i = 0; i < n; i++) if (cipher[i] > 25) return 0;
    return 1;
}
static int gm_params_ok(int32_t base, int32_t plen) {
    return base >= 2 && base <= GROMARK_MAX_BASE && plen >= 2;
}

/* Keystream of primer number `value` (plen digits in base `base`, most
 * significant first), extended by chain addition d[i] = (d[i-L] + d[i-L+1]) mod base. */
static void gromark_digits(int64_t value, int32_t n, int32_t base, int32_t plen, int32_t *digits) {
    for (int i = plen - 1; i >= 0; i--) { digits[i < n ? i : 0] = (int32_t)(value % base); value /= base; }
    for (int i = plen; i < n; i++) digits[i] = (digits[i - plen] + digits[i - plen + 1]) % base;
}

/* Window score of one keystream: sum over cipher letters of max over s of
 * sum log P_english(s - sign*d). */
static double gromark_score(const uint8_t *cipher, int32_t n, int32_t base, int32_t sign, const double *logp,
                            const int32_t *digits) {
    int32_t hist[26][GROMARK_MAX_BASE];
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
    return score;
}

/* Gromark primer screen (straight plaintext alphabet, unknown mixed cipher
 * alphabet). c = CA[(p + sign*d) mod 26], so p = s(c) - sign*d with s unknown per
 * cipher letter: for the right primer, the plaintext letters under one cipher
 * letter lie in a window of `base` consecutive letters. Higher = better.
 * Primers first..first+count-1 in base `base`, `plen` digits; base <= 32. */
EXPORT void cct_gromark_scores(const uint8_t *cipher, int32_t n, int32_t base, int32_t plen, int32_t sign,
                               const double *logp, int64_t first, int64_t count, double *out) {
    if (!gm_params_ok(base, plen) || !gm_codes_ok(cipher, n)) {
        for (int64_t q = 0; q < count; q++) out[q] = -INFINITY;
        return;
    }
    int32_t *digits = (int32_t *)malloc(sizeof(int32_t) * (size_t)(n > plen ? n : plen));
    for (int64_t q = 0; q < count; q++) {
        gromark_digits(first + q, n, base, plen, digits);
        out[q] = gromark_score(cipher, n, base, sign, logp, digits);
    }
    free(digits);
}

/* Top-K of (score, primer) pairs, compared as Python tuples: a min-heap whose
 * root is the smallest kept pair. */
static inline int gromark_less(double sa, int64_t pa, double sb, int64_t pb) {
    return sa < sb || (sa == sb && pa < pb);
}
static void gromark_sift_down(double *hs, int64_t *hp, int32_t size, int32_t i) {
    for (;;) {
        int32_t l = 2 * i + 1, r = l + 1, m = i;
        if (l < size && gromark_less(hs[l], hp[l], hs[m], hp[m])) m = l;
        if (r < size && gromark_less(hs[r], hp[r], hs[m], hp[m])) m = r;
        if (m == i) return;
        double ts = hs[i]; hs[i] = hs[m]; hs[m] = ts;
        int64_t tp = hp[i]; hp[i] = hp[m]; hp[m] = tp;
        i = m;
    }
}
static void gromark_sift_up(double *hs, int64_t *hp, int32_t i) {
    while (i > 0) {
        int32_t parent = (i - 1) / 2;
        if (!gromark_less(hs[i], hp[i], hs[parent], hp[parent])) return;
        double ts = hs[i]; hs[i] = hs[parent]; hs[parent] = ts;
        int64_t tp = hp[i]; hp[i] = hp[parent]; hp[parent] = tp;
        i = parent;
    }
}

/* Screen primers first..first+count-1 and keep the `keep` largest (score,
 * primer) pairs in a heap that persists between calls (heap_scores,
 * heap_primers, *heap_size), so Python can run the screen in chunks (progress
 * output, Ctrl+C). The kept set equals heapq.nlargest(keep, ...) over
 * (score, primer) tuples. */
EXPORT void cct_gromark_screen_top(const uint8_t *cipher, int32_t n, int32_t base, int32_t plen, int32_t sign,
                                   const double *logp, int64_t first, int64_t count, int32_t keep,
                                   double *heap_scores, int64_t *heap_primers, int32_t *heap_size) {
    if (!gm_params_ok(base, plen) || !gm_codes_ok(cipher, n)) return;
    int32_t *digits = (int32_t *)malloc(sizeof(int32_t) * (size_t)(n > plen ? n : plen));
    int32_t size = *heap_size;
    for (int64_t q = 0; q < count; q++) {
        int64_t primer = first + q;
        gromark_digits(primer, n, base, plen, digits);
        double score = gromark_score(cipher, n, base, sign, logp, digits);
        if (size < keep) {
            heap_scores[size] = score; heap_primers[size] = primer;
            gromark_sift_up(heap_scores, heap_primers, size);
            size++;
        } else if (keep > 0 && gromark_less(heap_scores[0], heap_primers[0], score, primer)) {
            heap_scores[0] = score; heap_primers[0] = primer;
            gromark_sift_down(heap_scores, heap_primers, size, 0);
        }
    }
    *heap_size = size;
    free(digits);
}

/* Python's sum() over floats (CPython 3.12+): the first term is added
 * plainly to the int 0, the rest with Neumaier compensation. */
typedef struct { double f, c; int started; } GmSum;
static inline void gm_sum_add(GmSum *s, double x) {
    if (!s->started) { s->f = x; s->started = 1; return; }
    double t = s->f + x;
    if (fabs(s->f) >= fabs(x)) s->c += (s->f - t) + x; else s->c += (x - t) + s->f;
    s->f = t;
}
static inline double gm_sum_value(const GmSum *s) {
    if (!s->started) return 0.0;
    return (s->c != 0.0 && isfinite(s->c)) ? s->f + s->c : s->f;
}

typedef struct { double value; int c, s; } GmOption;
static int gm_option_desc(const void *x, const void *y) {
    const GmOption *a = (const GmOption *)x, *b = (const GmOption *)y;
    if (a->value != b->value) return a->value < b->value ? 1 : -1;
    if (a->c != b->c) return a->c < b->c ? 1 : -1;
    return a->s < b->s ? 1 : (a->s > b->s ? -1 : 0);
}

/* gromark_solver.initial_s: a one-to-one assignment cipher letter -> s (its
 * position in the cipher alphabet) from the per-letter window fit: every
 * (value, c, s) sorted descending as Python tuples, then taken greedily. */
static void gromark_initial(const uint8_t *cipher, int32_t n, const int32_t *digits, int32_t base, int32_t sign,
                            const double *logp, uint8_t *s_out) {
    int32_t hist[26][GROMARK_MAX_BASE];
    memset(hist, 0, sizeof(hist));
    for (int i = 0; i < n; i++) hist[cipher[i]][digits[i]]++;
    GmOption options[26 * 26];
    int k = 0;
    for (int c = 0; c < 26; c++) {
        int any = 0;
        for (int d = 0; d < base; d++) if (hist[c][d]) { any = 1; break; }
        for (int s = 0; s < 26; s++) {
            double value = -1e9;
            if (any) {
                GmSum sum = {0.0, 0.0, 0};
                for (int d = 0; d < base; d++) {
                    if (!hist[c][d]) continue;
                    int p = (s - sign * d) % 26; if (p < 0) p += 26;
                    gm_sum_add(&sum, hist[c][d] * logp[p]);
                }
                value = gm_sum_value(&sum);
            }
            options[k].value = value; options[k].c = c; options[k].s = s; k++;
        }
    }
    qsort(options, 26 * 26, sizeof(GmOption), gm_option_desc);
    int assigned[26], used[26];
    for (int i = 0; i < 26; i++) { assigned[i] = 0; used[i] = 0; }
    for (int i = 0; i < 26 * 26; i++) {
        int c = options[i].c, s = options[i].s;
        if (!assigned[c] && !used[s]) { s_out[c] = (uint8_t)s; assigned[c] = 1; used[s] = 1; }
    }
}

static inline uint8_t gm_plain(int s, int sign, int d) {
    int p = (s - sign * d) % 26;
    return (uint8_t)(p < 0 ? p + 26 : p);
}

/* Scratch memory of gromark_refine for a text of n letters and n-gram size `size`. */
typedef struct {
    int32_t *positions, *start, *stamp, *windows, *wscore, *wnew, *saved;
    double *term;                                     /* term[k] = (k/n) log2(k/n) */
    void *block;
} GmWork;

static int gromark_work(GmWork *w, int32_t n, int32_t size) {
    size_t m = (size_t)(n > 0 ? n : 1), ws = m * (size_t)(size > 0 ? size : 1);
    size_t ints = m + 27 + m + ws + m + ws + m;
    w->block = malloc(sizeof(double) * (m + 1) + sizeof(int32_t) * ints);
    if (!w->block) return 0;
    w->term = (double *)w->block;
    w->positions = (int32_t *)(w->term + m + 1);
    w->start = w->positions + m;
    w->stamp = w->start + 27;
    w->windows = w->stamp + m;
    w->wscore = w->windows + ws;
    w->wnew = w->wscore + m;
    w->saved = w->wnew + ws;
    return 1;
}

/* letter_entropy(codes) ** weight from letter counts: the same terms, in the
 * same order, as annealing.letter_entropy (and cct_entropy_factor). */
static inline double gm_entropy_factor(const int *counts, const double *term, double weight) {
    double entropy = 0.0;
    for (int c = 0; c < 26; c++) if (counts[c]) entropy -= term[counts[c]];
    return pow(entropy, weight);
}

static inline int32_t gm_window(const uint8_t *plain, int w, const uint8_t *scores, int size) {
    int64_t index = 0;
    for (int t = 0; t < size; t++) index = index * 26 + plain[w + t];
    return scores[index];
}

/* gromark_solver.refine: hill-climb the cipher alphabet by swapping the
 * positions of two letters (a present in the ciphertext, b any other); keep a
 * swap when the fitness rises by more than 1e-9; at most `rounds` rounds.
 * Fitness = annealing.Fitness (fixed_factor < 0: entropy recomputed), kept
 * exactly by updating the n-gram total (per-window scores cached) and the
 * letter counts for the changed positions only. s: 26 positions (a permutation
 * of 0..25), updated in place; plain: n codes. Returns the fitness. */
static double gromark_refine(const uint8_t *cipher, int32_t n, const int32_t *digits, int32_t sign, uint8_t *s,
                             const uint8_t *scores, int32_t size, double weight, double fixed_factor, int32_t rounds,
                             uint8_t *plain, GmWork *wk) {
    for (int i = 0; i < n; i++) plain[i] = gm_plain(s[cipher[i]], sign, digits[i]);
    int count = n - size + 1;
    if (count <= 0) return -9999.0;
    int32_t *positions = wk->positions, *start = wk->start, *stamp = wk->stamp, *windows = wk->windows;
    int32_t *wscore = wk->wscore, *wnew = wk->wnew, *saved = wk->saved;
    double *term = wk->term;
    int32_t fill[26];
    int counts[26] = {0};
    for (int k = 1; k <= n; k++) { double p = (double)k / n; term[k] = p * log2(p); }
    for (int c = 0; c <= 26; c++) start[c] = 0;
    for (int i = 0; i < n; i++) start[cipher[i] + 1]++;
    for (int c = 0; c < 26; c++) start[c + 1] += start[c];
    for (int c = 0; c < 26; c++) fill[c] = start[c];
    for (int i = 0; i < n; i++) positions[fill[cipher[i]]++] = i;
    for (int i = 0; i < n; i++) counts[plain[i]]++;
    int64_t total = 0;
    for (int w = 0; w < count; w++) { stamp[w] = 0; wscore[w] = gm_window(plain, w, scores, size); total += wscore[w]; }
    double factor = fixed_factor >= 0 ? fixed_factor : gm_entropy_factor(counts, term, weight);
    double score = (double)total / count * factor;
    int32_t tick = 0;
    for (int round = 0; round < rounds; round++) {
        int improved = 0;
        for (int a = 0; a < 26; a++) {
            if (start[a] == start[a + 1]) continue;          /* a not present */
            for (int b = 0; b < 26; b++) {
                if (b == a) continue;
                uint8_t sa = s[a], sb = s[b];
                s[a] = sb; s[b] = sa;
                int nw = 0, nc = 0;
                tick++;
                for (int pass = 0; pass < 2; pass++) {
                    int letter = pass ? b : a;
                    for (int q = start[letter]; q < start[letter + 1]; q++) {
                        int i = positions[q];
                        int lo = i - size + 1 < 0 ? 0 : i - size + 1, hi = i < count - 1 ? i : count - 1;
                        for (int w = lo; w <= hi; w++) if (stamp[w] != tick) { stamp[w] = tick; windows[nw++] = w; }
                        saved[nc++] = plain[i];
                        counts[plain[i]]--;
                        plain[i] = gm_plain(s[letter], sign, digits[i]);
                        counts[plain[i]]++;
                    }
                }
                int64_t delta = 0;
                for (int k = 0; k < nw; k++) {
                    wnew[k] = gm_window(plain, windows[k], scores, size);
                    delta += wnew[k] - wscore[windows[k]];
                }
                int64_t trial_total = total + delta;
                double trial_factor = fixed_factor >= 0 ? fixed_factor : gm_entropy_factor(counts, term, weight);
                double trial = (double)trial_total / count * trial_factor;
                if (trial > score + 1e-9) {
                    score = trial; total = trial_total; improved = 1;
                    for (int k = 0; k < nw; k++) wscore[windows[k]] = wnew[k];
                } else {
                    s[a] = sa; s[b] = sb;
                    nc = 0;
                    for (int pass = 0; pass < 2; pass++) {
                        int letter = pass ? b : a;
                        for (int q = start[letter]; q < start[letter + 1]; q++) {
                            int i = positions[q];
                            counts[plain[i]]--;
                            plain[i] = (uint8_t)saved[nc++];
                            counts[plain[i]]++;
                        }
                    }
                }
            }
        }
        if (!improved) break;
    }
    return score;
}

/* gromark_solver.initial_s for one keystream (digits: n values 0..base-1,
 * base 2..32). Returns 0, or -1 (s_out untouched) on bad input. */
EXPORT int32_t cct_gromark_initial_s(const uint8_t *cipher, int32_t n, const int32_t *digits, int32_t base,
                                     int32_t sign, const double *logp, uint8_t *s_out) {
    if (base < 2 || base > GROMARK_MAX_BASE || !gm_codes_ok(cipher, n)) return -1;
    for (int i = 0; i < n; i++) if (digits[i] < 0 || digits[i] >= base) return -1;
    gromark_initial(cipher, n, digits, base, sign, logp, s_out);
    return 0;
}

/* gromark_solver.refine for one keystream; s_io updated in place. Returns the
 * fitness (-9999 when the text is shorter than one n-gram or memory runs out). */
EXPORT double cct_gromark_refine(const uint8_t *cipher, int32_t n, const int32_t *digits, int32_t sign,
                                 uint8_t *s_io, const uint8_t *scores, int32_t size, double weight,
                                 double fixed_factor, int32_t rounds, uint8_t *plain_out) {
    if (!gm_codes_ok(cipher, n)) return NAN;
    GmWork wk;
    if (!gromark_work(&wk, n, size)) return -9999.0;
    double score = gromark_refine(cipher, n, digits, sign, s_io, scores, size, weight, fixed_factor, rounds,
                                  plain_out, &wk);
    free(wk.block);
    return score;
}

/* Keystream + initial_s + refine for each of `m` primer numbers: writes 26
 * alphabet positions per primer (s_out, m x 26) and the fitness (fitness_out). */
EXPORT void cct_gromark_refine_primers(const uint8_t *cipher, int32_t n, int32_t base, int32_t plen, int32_t sign,
                                       const double *logp, const int64_t *primers, int32_t m,
                                       const uint8_t *scores, int32_t size, double weight, double fixed_factor,
                                       int32_t rounds, uint8_t *s_out, double *fitness_out) {
    if (!gm_params_ok(base, plen) || !gm_codes_ok(cipher, n)) {
        for (int32_t q = 0; q < m; q++) {
            for (int c = 0; c < 26; c++) s_out[(size_t)q * 26 + c] = (uint8_t)c;
            fitness_out[q] = NAN;
        }
        return;
    }
    int32_t *digits = (int32_t *)malloc(sizeof(int32_t) * (size_t)(n > plen ? n : plen));
    uint8_t *plain = (uint8_t *)malloc((size_t)(n > 0 ? n : 1));
    GmWork wk;
    int ok = digits && plain && gromark_work(&wk, n, size);
    for (int32_t q = 0; q < m; q++) {
        uint8_t *s = s_out + (size_t)q * 26;
        if (!ok) { for (int c = 0; c < 26; c++) s[c] = (uint8_t)c; fitness_out[q] = -9999.0; continue; }
        gromark_digits(primers[q], n, base, plen, digits);
        gromark_initial(cipher, n, digits, base, sign, logp, s);
        fitness_out[q] = gromark_refine(cipher, n, digits, sign, s, scores, size, weight, fixed_factor, rounds,
                                        plain, &wk);
    }
    if (ok) free(wk.block);
    free(plain);
    free(digits);
}
