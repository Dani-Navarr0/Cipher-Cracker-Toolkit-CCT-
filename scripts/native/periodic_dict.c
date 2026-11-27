/* Dictionary and exhaustive key searches for the periodic-key tools:
 *   cct_periodic_dict        attack_support.run_batches (Vigenere, Beaufort,
 *                            Porta): every word as the key
 *   cct_periodic_exhaustive  Gronsfeld exhaustive search (every digit key)
 *   cct_xor_dict             xor.brute_force_with_ioc
 *   cct_modular_dict         modular_add_sub.brute_force_with_ioc
 *
 * Each candidate is decrypted and scored exactly as the Python tools score
 * their plaintext strings: n-gram cost = 255 - mean n-gram score over the A-Z
 * letters (ngram_scoring.score_text; +inf below the n-gram size) and the IoC of
 * utils.calculate_ioc (every alphabetic character after upper(), including
 * non-ASCII ones, which Python maps to bucket ids). The periodic searches take
 * any alphabet of 1-256 symbols. Only the rows the Python code kept are
 * returned; Python renders their text once.
 */
#include "cct_common.h"

/* ------------------------------------------------------------------ helpers */

/* ngram_scoring.ngram_total without a division per letter: the rolling index
 * drops the oldest letter by subtraction (same integer total as cct_total). */
static inline int64_t rolling_total(const uint8_t *codes, int n, const uint8_t *scores, int size) {
    if (n < size || size < 1) return 0;
    int64_t top = 1;                         /* 26^(size-1): weight of the oldest letter */
    for (int i = 0; i < size - 1; i++) top *= 26;
    int64_t index = 0, total = 0;
    for (int i = 0; i < size - 1; i++) index = index * 26 + codes[i];
    for (int i = size - 1; i < n; i++) {
        index = index * 26 + codes[i];
        total += scores[index];
        index -= codes[i - size + 1] * top;
    }
    return total;
}

static inline double cost_of(const uint8_t *codes, int n, const uint8_t *scores, int size) {
    if (n < size) return INFINITY;
    return 255.0 - (double)rolling_total(codes, n, scores, size) / (n - size + 1);
}

static inline double ioc_of(int64_t pairs, int64_t total) {
    if (total <= 1) return 0.0;
    return (double)pairs / ((double)total * (double)(total - 1));
}

/* Bounded set of the best `cap` rows by cost. prefer_later: on equal cost the
 * later row wins (heap of (-cost, index), push then pop: xor/modular); else
 * the earlier row wins (heapq.nsmallest: attack_support). */
typedef struct { int64_t index; double cost, ioc; } Row;

static void best_rows_add(Row *rows, int *count, int cap, int64_t index, double cost, double ioc, int prefer_later) {
    if (cap <= 0) return;
    if (*count < cap) { rows[(*count)++] = (Row){index, cost, ioc}; return; }
    int worst = 0;
    for (int i = 1; i < cap; i++) {
        if (rows[i].cost > rows[worst].cost ||
            (rows[i].cost == rows[worst].cost && (prefer_later ? rows[i].index < rows[worst].index
                                                               : rows[i].index > rows[worst].index)))
            worst = i;
    }
    if (cost < rows[worst].cost || (cost == rows[worst].cost && (prefer_later ? index > rows[worst].index
                                                                              : index < rows[worst].index)))
        rows[worst] = (Row){index, cost, ioc};
}

static void sort_rows(Row *rows, int count) {            /* by (cost, index); count is small */
    for (int i = 1; i < count; i++) {
        Row r = rows[i];
        int j = i - 1;
        while (j >= 0 && (rows[j].cost > r.cost || (rows[j].cost == r.cost && rows[j].index > r.index))) {
            rows[j + 1] = rows[j];
            j--;
        }
        rows[j + 1] = r;
    }
}

static int contains(const int32_t *text, int n, const int32_t *pattern, int m) {
    if (m == 0) return 1;
    for (int i = 0; i + m <= n; i++) {
        if (text[i] != pattern[0]) continue;
        int j = 1;
        while (j < m && text[i + j] == pattern[j]) j++;
        if (j == m) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ periodic text */

/* A ciphertext prepared for the word and exhaustive key searches, for an
 * alphabet of m symbols (1-256, any characters). Each plaintext symbol p is
 * shown as one piece of text (the decrypt functions' alphabet[p].lower());
 * Python describes that text once per symbol: the A-Z codes it adds to the
 * scored text (score_text), the alphabetic characters it adds to the IoC
 * (calculate_ioc, as bucket ids), and its characters in the phrase view. */
typedef struct {
    const uint8_t *sym;            /* key-consuming cipher symbols (alphabet indices 0..m-1) */
    int32_t nsym;
    const uint8_t *table;          /* rows x m: plaintext symbol for (key row, cipher symbol) */
    int32_t rows, m;
    const int32_t *code_offsets;   /* m + 1 */
    const uint8_t *codes;          /* A-Z letter codes each plaintext symbol adds to the scored text */
    int32_t single;                /* 1: every plaintext symbol adds exactly one code, codes[p] */
    const int32_t *bucket_offsets; /* m + 1 */
    const int32_t *buckets;        /* IoC characters each plaintext symbol adds (bucket ids) */
    int32_t nbuckets;
    const int32_t *fixed_buckets;  /* nbuckets: IoC characters of the text that is not decrypted */
    const int32_t *slot;           /* scored text: >= 0 symbol number (its codes), < 0 fixed code -(code + 1) */
    int32_t nslots, max_codes;     /* max_codes bounds the scored text length */
    const int32_t *stream;         /* phrase text: >= 0 code point, < 0 symbol number -(t + 1) */
    int32_t nstream, max_render;   /* max_render bounds the rendered phrase text */
    const int32_t *render_offsets; /* m + 1 */
    const int32_t *render;         /* phrase-view characters of each plaintext symbol */
    int32_t render_single;         /* 1: every plaintext symbol shows as exactly one character, render[p] */
    const int32_t *phrases, *phrase_offsets;
    int32_t nphrases, phrase_all;  /* all phrases must occur (1) or any one (0) */
    const uint8_t *scores;
    int32_t size;
} PeriodicText;

typedef struct { uint8_t *pidx, *codes; int32_t *render; int64_t *symcount, *counts; } TextWork;

static void text_free(TextWork *w) {
    free(w->pidx); free(w->codes); free(w->render); free(w->symcount); free(w->counts);
}

static int text_work(const PeriodicText *t, TextWork *w) {
    w->pidx = (uint8_t *)malloc(t->nsym + 1);
    w->codes = (uint8_t *)malloc(t->max_codes + 1);
    w->render = (int32_t *)malloc(sizeof(int32_t) * (t->max_render + 1));
    w->symcount = (int64_t *)malloc(sizeof(int64_t) * (t->m + 1));
    w->counts = (int64_t *)malloc(sizeof(int64_t) * (t->nbuckets + 1));
    if (!w->pidx || !w->codes || !w->render || !w->symcount || !w->counts) { text_free(w); return 0; }
    return 1;
}

static void decrypt_key(const PeriodicText *t, TextWork *w, const uint8_t *key, int klen) {
    for (int i = 0, j = 0; i < t->nsym; i++) {
        w->pidx[i] = t->table[key[j] * t->m + t->sym[i]];
        if (++j == klen) j = 0;
    }
}

static void text_metrics(const PeriodicText *t, TextWork *w, double *cost, double *ioc) {
    int64_t *symcount = w->symcount, *counts = w->counts;
    memset(symcount, 0, sizeof(int64_t) * t->m);
    for (int i = 0; i < t->nsym; i++) symcount[w->pidx[i]]++;
    for (int b = 0; b < t->nbuckets; b++) counts[b] = t->fixed_buckets[b];
    for (int p = 0; p < t->m; p++) {
        int64_t c = symcount[p];
        if (c) for (int32_t j = t->bucket_offsets[p]; j < t->bucket_offsets[p + 1]; j++) counts[t->buckets[j]] += c;
    }
    int64_t total = 0, pairs = 0;
    for (int b = 0; b < t->nbuckets; b++) { total += counts[b]; pairs += counts[b] * (counts[b] - 1); }
    *ioc = ioc_of(pairs, total);
    int letters = 0;
    if (t->single) {
        for (int j = 0; j < t->nslots; j++) {
            int32_t e = t->slot[j];
            w->codes[j] = e >= 0 ? t->codes[w->pidx[e]] : (uint8_t)(-e - 1);
        }
        letters = t->nslots;
    } else {
        for (int j = 0; j < t->nslots; j++) {
            int32_t e = t->slot[j];
            if (e < 0) { w->codes[letters++] = (uint8_t)(-e - 1); continue; }
            int p = w->pidx[e];
            for (int32_t k = t->code_offsets[p]; k < t->code_offsets[p + 1]; k++) w->codes[letters++] = t->codes[k];
        }
    }
    *cost = cost_of(w->codes, letters, t->scores, t->size);
}

static int text_phrases(const PeriodicText *t, TextWork *w) {
    if (t->nphrases <= 0) return 0;
    int len = 0;
    if (t->render_single) {
        for (int j = 0; j < t->nstream; j++) {
            int32_t e = t->stream[j];
            w->render[j] = e >= 0 ? e : t->render[w->pidx[-e - 1]];
        }
        len = t->nstream;
    } else {
        for (int j = 0; j < t->nstream; j++) {
            int32_t e = t->stream[j];
            if (e >= 0) { w->render[len++] = e; continue; }
            int p = w->pidx[-e - 1];
            for (int32_t k = t->render_offsets[p]; k < t->render_offsets[p + 1]; k++) w->render[len++] = t->render[k];
        }
    }
    for (int p = 0; p < t->nphrases; p++) {
        int found = contains(w->render, len, t->phrases + t->phrase_offsets[p],
                             t->phrase_offsets[p + 1] - t->phrase_offsets[p]);
        if (t->phrase_all && !found) return 0;
        if (!t->phrase_all && found) return 1;
    }
    return t->phrase_all;
}

/* Words first .. first+count-1 as keys (keys: key-row values, concatenated;
 * offsets: nwords + 1). One call = one attack_support batch: rows that match
 * the phrases or fall in the IoC window, in word order, then the top_k others
 * by cost (ties: earlier word), sorted by cost. Words with an empty key are
 * skipped. Returns the number of rows, or -1 on allocation failure. */
EXPORT int32_t cct_periodic_dict(const PeriodicText *t, const uint8_t *keys, const int64_t *offsets, int32_t first,
                                 int32_t count, double min_ioc, double max_ioc, int32_t top_k, int32_t *out_index,
                                 double *out_cost, double *out_ioc, uint8_t *out_phrase) {
    TextWork w;
    if (!text_work(t, &w)) return -1;
    Row *best = (Row *)malloc(sizeof(Row) * (top_k > 0 ? top_k : 1));
    if (!best) { text_free(&w); return -1; }
    int kept = 0, nbest = 0;
    for (int32_t word = first; word < first + count; word++) {
        int klen = (int)(offsets[word + 1] - offsets[word]);
        if (klen <= 0) continue;
        decrypt_key(t, &w, keys + offsets[word], klen);
        double cost, ioc;
        text_metrics(t, &w, &cost, &ioc);
        int phrase = text_phrases(t, &w);
        if (phrase || (min_ioc <= ioc && ioc <= max_ioc)) {
            out_index[kept] = word; out_cost[kept] = cost; out_ioc[kept] = ioc; out_phrase[kept] = (uint8_t)phrase;
            kept++;
        } else {
            best_rows_add(best, &nbest, top_k, word, cost, ioc, 0);
        }
    }
    sort_rows(best, nbest);
    for (int i = 0; i < nbest; i++, kept++) {
        out_index[kept] = (int32_t)best[i].index; out_cost[kept] = best[i].cost; out_ioc[kept] = best[i].ioc;
        out_phrase[kept] = 0;
    }
    free(best);
    text_free(&w);
    return kept;
}

/* Every key number first .. first+count-1, written as `period` base-`base`
 * digits (most significant first, zero-padded: str(number).zfill(period)),
 * each digit a key row. Phrase matches (any phrase) are all kept; of the
 * others the best top_k by cost with Gronsfeld.process_exhaustive_batch's
 * heap rule (a row replaces the worst kept row only when strictly cheaper; the
 * worst is the highest cost, then the smallest number), sorted by
 * (cost, number). Returns the kept count (and *n_match), -1 on failure. */
EXPORT int32_t cct_periodic_exhaustive(const PeriodicText *t, int32_t period, int32_t base, int64_t first,
                                       int64_t count, int32_t top_k, int64_t *match_number, double *match_cost,
                                       double *match_ioc, int64_t *n_match, int64_t *keep_number, double *keep_cost,
                                       double *keep_ioc) {
    *n_match = 0;
    if (period < 1 || base < 1 || count <= 0) return 0;
    TextWork w;
    if (!text_work(t, &w)) return -1;
    uint8_t *digits = (uint8_t *)malloc(period);
    Row *kept = (Row *)malloc(sizeof(Row) * (top_k > 0 ? top_k : 1));
    if (!digits || !kept) { free(digits); free(kept); text_free(&w); return -1; }
    int64_t value = first;
    for (int i = period - 1; i >= 0; i--) { digits[i] = (uint8_t)(value % base); value /= base; }
    decrypt_key(t, &w, digits, period);
    int nkept = 0, worst = -1;          /* worst kept row, found again only after it is replaced */
    for (int64_t k = 0; k < count; k++) {
        int64_t number = first + k;
        if (k > 0) {                    /* odometer: re-decrypt only the columns whose digit changed */
            int lo = period - 1;
            while (lo >= 0 && ++digits[lo] == base) { digits[lo] = 0; lo--; }
            if (lo < 0) lo = 0;
            for (int column = lo; column < period; column++) {
                const uint8_t *row = t->table + digits[column] * t->m;
                for (int i = column; i < t->nsym; i += period) w.pidx[i] = row[t->sym[i]];
            }
        }
        double cost, ioc;
        text_metrics(t, &w, &cost, &ioc);
        if (text_phrases(t, &w)) {
            match_number[*n_match] = number; match_cost[*n_match] = cost; match_ioc[*n_match] = ioc;
            (*n_match)++;
        } else if (nkept < top_k) {
            kept[nkept++] = (Row){number, cost, ioc};
        } else if (top_k > 0) {
            if (worst < 0) {
                worst = 0;
                for (int i = 1; i < nkept; i++)
                    if (kept[i].cost > kept[worst].cost ||
                        (kept[i].cost == kept[worst].cost && kept[i].index < kept[worst].index)) worst = i;
            }
            if (cost < kept[worst].cost) { kept[worst] = (Row){number, cost, ioc}; worst = -1; }
        }
    }
    sort_rows(kept, nkept);
    for (int i = 0; i < nkept; i++) {
        keep_number[i] = kept[i].index; keep_cost[i] = kept[i].cost; keep_ioc[i] = kept[i].ioc;
    }
    free(digits); free(kept); text_free(&w);
    return nkept;
}

/* ------------------------------------------------------------------ XOR and modular */

/* Common output: window rows (IoC in [min, max] and not blank) in word order,
 * plus the top_k other rows by cost, later word winning ties. */
typedef struct {
    double min_ioc, max_ioc;
    int32_t top_k;
    int32_t outside_needs_text;  /* xor: rows outside the window must not be blank */
    int32_t *win_index; double *win_cost, *win_ioc; int32_t n_win;
    int32_t *top_index; double *top_cost, *top_ioc; int32_t n_top;
} Selection;

static Row *selection_start(const Selection *s) { return (Row *)malloc(sizeof(Row) * (s->top_k > 0 ? s->top_k : 1)); }

static void selection_add(Selection *s, Row *best, int *nbest, int32_t word, double cost, double ioc, int blank) {
    if (s->min_ioc <= ioc && ioc <= s->max_ioc && !blank) {
        s->win_index[s->n_win] = word; s->win_cost[s->n_win] = cost; s->win_ioc[s->n_win] = ioc; s->n_win++;
    } else if (!(s->outside_needs_text && blank)) {
        best_rows_add(best, nbest, s->top_k, word, cost, ioc, 1);
    }
}

static void selection_end(Selection *s, Row *best, int nbest) {
    sort_rows(best, nbest);
    for (int i = 0; i < nbest; i++) {
        s->top_index[i] = (int32_t)best[i].index; s->top_cost[i] = best[i].cost; s->top_ioc[i] = best[i].ioc;
    }
    s->n_top = nbest;
    free(best);
}

/* xor.brute_force_with_ioc: msg values (0-127; anything else is passed as 255,
 * which no ASCII key byte turns printable), words = upper-case ASCII keys.
 * Text = the printable results (32-126); letters A-Z/a-z are scored and
 * counted. Returns 0, or -1 on allocation failure. */
EXPORT int32_t cct_xor_dict(const uint8_t *msg, int32_t n, const uint8_t *words, const int64_t *offsets,
                            int32_t first, int32_t count, const uint8_t *scores, int32_t size, Selection *s) {
    uint8_t *codes = (uint8_t *)malloc(n > 0 ? n : 1);
    Row *best = selection_start(s);
    if (!codes || !best) { free(codes); free(best); return -1; }
    int nbest = 0;
    s->n_win = 0;
    for (int32_t word = first; word < first + count; word++) {
        const uint8_t *key = words + offsets[word];
        int klen = (int)(offsets[word + 1] - offsets[word]);
        if (klen <= 0) continue;
        int64_t counts[26] = {0};
        int letters = 0, blank = 1;
        for (int i = 0, j = 0; i < n; i++) {
            int r = msg[i] ^ key[j];
            if (++j == klen) j = 0;
            if (r < 32 || r > 126) continue;
            if (r != 32) blank = 0;
            int code = (r >= 'A' && r <= 'Z') ? r - 'A' : (r >= 'a' && r <= 'z') ? r - 'a' : -1;
            if (code >= 0) { codes[letters++] = (uint8_t)code; counts[code]++; }
        }
        int64_t pairs = 0;
        for (int c = 0; c < 26; c++) pairs += counts[c] * (counts[c] - 1);
        selection_add(s, best, &nbest, word, cost_of(codes, letters, scores, size), ioc_of(pairs, letters), blank);
    }
    selection_end(s, best, nbest);
    free(codes);
    return 0;
}

typedef struct {
    int32_t modulus, subtract;
    const int32_t *keymap;          /* 128: ASCII key character -> key value; -1 = not a key symbol, -2 = skip word */
    const int32_t *code_offsets;    /* modulus + 1 */
    const uint8_t *codes;           /* per result value: the A-Z letter codes it adds to the scored text */
    const int32_t *bucket_offsets;  /* modulus + 1 */
    const int32_t *buckets;         /* per result value: its alphabetic characters (IoC buckets) */
    int32_t nbuckets;
    const uint8_t *blank;           /* per result value: 1 if its character is whitespace */
    int32_t identity_valid;         /* words with no key letters leave the message as it is: */
    int32_t identity_blank;         /* precomputed by Python for that one text */
    double identity_cost, identity_ioc;
} ModularSpec;

/* modular_add_sub.brute_force_with_ioc: msg = values already reduced modulo
 * the modulus, -1 = a gap (shown as a space, the key does not advance). */
EXPORT int32_t cct_modular_dict(const int32_t *msg, int32_t n, const ModularSpec *spec, const uint8_t *words,
                                const int64_t *offsets, int32_t first, int32_t count, const uint8_t *scores,
                                int32_t size, Selection *s) {
    int32_t longest = 0;                       /* the longest rendering of any value bounds the text */
    for (int v = 0; v < spec->modulus; v++) {
        int32_t len = spec->code_offsets[v + 1] - spec->code_offsets[v];
        if (len > longest) longest = len;
    }
    int64_t maxcodes = (int64_t)n * longest;
    uint8_t *codes = (uint8_t *)malloc(maxcodes > 0 ? maxcodes : 1);
    int32_t *key = (int32_t *)malloc(sizeof(int32_t) * 64);
    int64_t *counts = (int64_t *)calloc(spec->nbuckets > 0 ? spec->nbuckets : 1, sizeof(int64_t));
    int32_t *touched = (int32_t *)malloc(sizeof(int32_t) * (spec->nbuckets > 0 ? spec->nbuckets : 1));
    Row *best = selection_start(s);
    int keycap = 64;
    if (!codes || !key || !counts || !touched || !best) {
        free(codes); free(key); free(counts); free(touched); free(best); return -1;
    }
    int nbest = 0;
    s->n_win = 0;
    for (int32_t word = first; word < first + count; word++) {
        int64_t start = offsets[word], end = offsets[word + 1];
        int klen = 0, skip = 0;
        for (int64_t i = start; i < end; i++) {
            int32_t value = spec->keymap[words[i] & 127];
            if (value == -2) { skip = 1; break; }
            if (value < 0) continue;
            if (klen == keycap) {
                int32_t *grown = (int32_t *)realloc(key, sizeof(int32_t) * keycap * 2);
                if (!grown) { skip = 1; break; }
                key = grown; keycap *= 2;
            }
            key[klen++] = value;
        }
        if (skip) continue;
        if (klen == 0) {
            if (spec->identity_valid)
                selection_add(s, best, &nbest, word, spec->identity_cost, spec->identity_ioc, spec->identity_blank);
            continue;
        }
        int letters = 0, blank = 1, ntouched = 0;
        int64_t total = 0, pairs = 0;
        for (int j = 0; j < klen; j++) key[j] %= spec->modulus;   /* key values are >= 0 */
        for (int i = 0, position = 0; i < n; i++) {
            int32_t m = msg[i];
            if (m < 0) continue;                       /* a gap renders as a space */
            int32_t k = key[position];
            if (++position == klen) position = 0;
            int32_t v = spec->subtract ? m - k : m + k;   /* m, k in [0, modulus) */
            if (v < 0) v += spec->modulus;
            else if (v >= spec->modulus) v -= spec->modulus;
            if (!spec->blank[v]) blank = 0;
            for (int32_t j = spec->code_offsets[v]; j < spec->code_offsets[v + 1]; j++) codes[letters++] = spec->codes[j];
            for (int32_t j = spec->bucket_offsets[v]; j < spec->bucket_offsets[v + 1]; j++) {
                int32_t b = spec->buckets[j];
                if (counts[b] == 0) touched[ntouched++] = b;
                counts[b]++;
                total++;
            }
        }
        for (int i = 0; i < ntouched; i++) { int64_t c = counts[touched[i]]; pairs += c * (c - 1); counts[touched[i]] = 0; }
        selection_add(s, best, &nbest, word, cost_of(codes, letters, scores, size), ioc_of(pairs, total), blank);
    }
    selection_end(s, best, nbest);
    free(codes); free(key); free(counts); free(touched);
    return 0;
}
