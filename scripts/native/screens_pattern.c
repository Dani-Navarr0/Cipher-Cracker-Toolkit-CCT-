/* Word pattern isomorphism (tool 14, pattern_isomorphism.py): dictionary words
 * with the letter pattern of each cipher word (ATTACK = 0-1-1-0-2-3), ranked
 * by a 3-gram score, and a beam search for ONE one-to-one letter mapping that
 * turns every cipher word into a dictionary word at the same time.
 *
 * Dictionary: nwords words of letter codes 0-25, concatenated in `letters`;
 * word w is letters[offsets[w] .. offsets[w + 1]).
 *
 * Word score (pattern_isomorphism's ranking): the mean n-gram score of the
 * word, total / (len - size + 1); words shorter than `size` score 120 when
 * short_common marks them (a*27 + 26 for one letter a, a*27 + b for two
 * letters ab), else 60.
 *
 * Beam search (pattern_isomorphism.solve): cipher words with at least one
 * match, most constrained first (fewest candidates, then longest; ties keep
 * the given order). For every beam, the candidates are the dictionary words
 * of the pattern, best score first (ties: dictionary order), that agree with
 * the letters the beam already fixed, at most per_word of them; a candidate
 * that keeps the mapping one-to-one extends the beam with score
 * + word score x length. The best `beam` extensions (ties: beam order, then
 * candidate order) form the next beams; a word nothing fits is skipped.
 */
#include "cct_common.h"

/* score + word score x length must round like Python (no fused multiply-add) */
#pragma STDC FP_CONTRACT OFF

#define UNSET 255
#define ERR_MEMORY -4
#define ERR_INPUT -2

typedef struct { double score; int32_t index; } Ranked;
typedef struct { double score; int32_t beam, cand; int64_t seq; } Extension;

static int cmp_ranked(const void *a, const void *b) {
    const Ranked *x = a, *y = b;
    if (x->score != y->score) return x->score > y->score ? -1 : 1;
    return (x->index > y->index) - (x->index < y->index);
}

static int cmp_extension(const void *a, const void *b) {
    const Extension *x = a, *y = b;
    if (x->score != y->score) return x->score > y->score ? -1 : 1;
    return (x->seq > y->seq) - (x->seq < y->seq);
}

static double word_score(const uint8_t *w, int len, const uint8_t *scores, int size, const uint8_t *short_common) {
    if (len < size) {
        int key = len == 1 ? w[0] * 27 + 26 : len == 2 ? w[0] * 27 + w[1] : -1;
        return key >= 0 && short_common[key] ? 120.0 : 60.0;
    }
    return (double)cct_total(w, len, scores, size) / (double)(len - size + 1);
}

EXPORT void cct_pattern_word_scores(const uint8_t *letters, const int32_t *offsets, int32_t nwords,
                                    const uint8_t *scores, int32_t size, const uint8_t *short_common, double *out) {
    for (int32_t w = 0; w < nwords; w++)
        out[w] = word_score(letters + offsets[w], offsets[w + 1] - offsets[w], scores, size, short_common);
}

/* 1 when dictionary word d has the letter pattern of cipher word c (same length). */
static int same_pattern(const uint8_t *c, const uint8_t *d, int len) {
    uint8_t fw[26], bw[26];
    memset(fw, UNSET, 26); memset(bw, UNSET, 26);
    for (int i = 0; i < len; i++) {
        if (fw[c[i]] == UNSET) {
            if (bw[d[i]] != UNSET) return 0;
            fw[c[i]] = d[i]; bw[d[i]] = c[i];
        } else if (fw[c[i]] != d[i]) return 0;
    }
    return 1;
}

/* Every dictionary word with the pattern of `word`, best first, in a new array
 * (*count entries; NULL with *count = 0 when none, NULL with *count = -1 when
 * out of memory). */
static Ranked *matches_of(const uint8_t *letters, const int32_t *offsets, int32_t nwords, const double *word_scores,
                          const uint8_t *word, int len, int32_t *count) {
    int32_t n = 0, cap = 0;
    Ranked *out = NULL;
    for (int32_t w = 0; w < nwords; w++) {
        if (offsets[w + 1] - offsets[w] != len || !same_pattern(word, letters + offsets[w], len)) continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 256;
            Ranked *grown = realloc(out, sizeof(Ranked) * (size_t)cap);
            if (!grown) { free(out); *count = -1; return NULL; }
            out = grown;
        }
        out[n].score = word_scores[w]; out[n].index = w; n++;
    }
    if (n > 1) qsort(out, (size_t)n, sizeof(Ranked), cmp_ranked);
    *count = n;
    return out;
}

/* The dictionary words with the pattern of `word`: their number (or -4 when
 * out of memory); the best `limit` indexes into out_index. */
EXPORT int32_t cct_pattern_matches(const uint8_t *letters, const int32_t *offsets, int32_t nwords,
                                   const double *word_scores, const uint8_t *word, int32_t len, int32_t limit,
                                   int32_t *out_index) {
    int32_t count;
    for (int i = 0; i < len; i++) if (word[i] > 25) return ERR_INPUT;
    Ranked *found = matches_of(letters, offsets, nwords, word_scores, word, len, &count);
    if (count < 0) return ERR_MEMORY;
    for (int32_t k = 0; k < count && k < limit; k++) out_index[k] = found[k].index;
    free(found);
    return count;
}

/* Try candidate d (dictionary word) for cipher word c on the mapping fw/bw
 * (cipher->plain, plain->cipher; changed in place). Returns 1 when one-to-one. */
static int extend(const uint8_t *c, const uint8_t *d, int len, uint8_t *fw, uint8_t *bw) {
    for (int i = 0; i < len; i++) {
        uint8_t mapped = fw[c[i]];
        if (mapped != UNSET) { if (mapped != d[i]) return 0; continue; }
        uint8_t owner = bw[d[i]];
        if (owner != UNSET && owner != c[i]) return 0;
        fw[c[i]] = d[i]; bw[d[i]] = c[i];
    }
    return 1;
}

/* Beam search over the ncipher distinct cipher words (letter codes, word i =
 * cipher[cipher_offsets[i] .. cipher_offsets[i + 1])). out_forward: up to `beam`
 * mappings of 26 cipher letters (UNSET = 255 for a letter nothing fixed),
 * out_scores their scores, best first. Returns the number of mappings, or a
 * negative error code. */
EXPORT int32_t cct_pattern_solve(const uint8_t *letters, const int32_t *offsets, int32_t nwords,
                                 const double *word_scores, const uint8_t *cipher, const int32_t *cipher_offsets,
                                 int32_t ncipher, int32_t beam, int32_t per_word, uint8_t *out_forward,
                                 double *out_scores) {
    if (beam < 1 || per_word < 1 || ncipher < 0) return ERR_INPUT;
    for (int32_t i = 0; i < cipher_offsets[ncipher]; i++) if (cipher[i] > 25) return ERR_INPUT;
    int32_t result = ERR_MEMORY, nbeams = 1, maxlen = 1;
    int64_t ext_cap = 0;
    for (int32_t i = 0; i < ncipher; i++)
        if (cipher_offsets[i + 1] - cipher_offsets[i] > maxlen) maxlen = cipher_offsets[i + 1] - cipher_offsets[i];
    uint8_t *known = malloc((size_t)maxlen);
    Ranked **ranked = calloc((size_t)(ncipher ? ncipher : 1), sizeof(Ranked *));
    int32_t *nmatch = calloc((size_t)(ncipher ? ncipher : 1), sizeof(int32_t));
    int32_t *order = malloc(sizeof(int32_t) * (size_t)(ncipher ? ncipher : 1));
    uint8_t *fw = malloc((size_t)beam * 26), *bw = malloc((size_t)beam * 26);
    uint8_t *fw2 = malloc((size_t)beam * 26), *bw2 = malloc((size_t)beam * 26);
    double *score = malloc(sizeof(double) * (size_t)beam), *score2 = malloc(sizeof(double) * (size_t)beam);
    Extension *ext = NULL;
    if (!ranked || !nmatch || !order || !fw || !bw || !fw2 || !bw2 || !score || !score2 || !known) goto done;

    int32_t norder = 0;
    for (int32_t i = 0; i < ncipher; i++) {
        const uint8_t *word = cipher + cipher_offsets[i];
        int len = cipher_offsets[i + 1] - cipher_offsets[i];
        ranked[i] = matches_of(letters, offsets, nwords, word_scores, word, len, &nmatch[i]);
        if (nmatch[i] < 0) goto done;
        if (nmatch[i] == 0) continue;
        /* insertion by (candidates kept, -length); equal keys keep the given order */
        int32_t kept = nmatch[i] < per_word ? nmatch[i] : per_word, j = norder++;
        while (j > 0) {
            int32_t o = order[j - 1];
            int32_t okept = nmatch[o] < per_word ? nmatch[o] : per_word;
            int olen = cipher_offsets[o + 1] - cipher_offsets[o];
            if (okept < kept || (okept == kept && olen >= len)) break;
            order[j] = o; j--;
        }
        order[j] = i;
    }

    memset(fw, UNSET, 26); memset(bw, UNSET, 26);
    score[0] = 0.0;
    for (int32_t step = 0; step < norder; step++) {
        int32_t wi = order[step];
        const uint8_t *word = cipher + cipher_offsets[wi];
        int len = cipher_offsets[wi + 1] - cipher_offsets[wi];
        const Ranked *cands = ranked[wi];
        int64_t next = 0;
        for (int32_t b = 0; b < nbeams; b++) {
            const uint8_t *f = fw + (size_t)b * 26, *g = bw + (size_t)b * 26;
            int any_fixed = 0;
            for (int i = 0; i < len; i++) { known[i] = f[word[i]]; any_fixed |= known[i] != UNSET; }
            int32_t taken = 0;
            for (int32_t k = 0; k < nmatch[wi] && taken < per_word; k++) {
                const uint8_t *d = letters + offsets[cands[k].index];
                if (any_fixed) {
                    int fits = 1;
                    for (int i = 0; i < len && fits; i++) if (known[i] != UNSET && known[i] != d[i]) fits = 0;
                    if (!fits) continue;
                }
                taken++;
                uint8_t tf[26], tb[26];
                memcpy(tf, f, 26); memcpy(tb, g, 26);
                if (!extend(word, d, len, tf, tb)) continue;
                if (next == ext_cap) {
                    int64_t cap = ext_cap ? ext_cap * 2 : 4096;
                    Extension *grown = realloc(ext, sizeof(Extension) * (size_t)cap);
                    if (!grown) goto done;
                    ext = grown; ext_cap = cap;
                }
                ext[next].score = score[b] + word_scores[cands[k].index] * (double)len;
                ext[next].beam = b; ext[next].cand = cands[k].index; ext[next].seq = next;
                next++;
            }
        }
        if (!next) continue;                 /* a word nothing fits (a name?) is skipped */
        qsort(ext, (size_t)next, sizeof(Extension), cmp_extension);
        int32_t kept = next < beam ? (int32_t)next : beam;
        for (int32_t j = 0; j < kept; j++) {
            uint8_t *tf = fw2 + (size_t)j * 26, *tb = bw2 + (size_t)j * 26;
            memcpy(tf, fw + (size_t)ext[j].beam * 26, 26); memcpy(tb, bw + (size_t)ext[j].beam * 26, 26);
            extend(word, letters + offsets[ext[j].cand], len, tf, tb);
            score2[j] = ext[j].score;
        }
        uint8_t *t8; double *td;
        t8 = fw; fw = fw2; fw2 = t8;
        t8 = bw; bw = bw2; bw2 = t8;
        td = score; score = score2; score2 = td;
        nbeams = kept;
    }
    memcpy(out_forward, fw, (size_t)nbeams * 26);
    memcpy(out_scores, score, sizeof(double) * (size_t)nbeams);
    result = nbeams;
done:
    if (ranked) for (int32_t i = 0; i < ncipher; i++) free(ranked[i]);
    free(ranked); free(nmatch); free(order); free(fw); free(bw); free(fw2); free(bw2); free(score); free(score2);
    free(ext); free(known);
    return result;
}
