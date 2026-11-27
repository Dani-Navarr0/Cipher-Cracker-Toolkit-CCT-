/* Periodic-key annealer (periodic_solver.solve_periodic): Vigenere, Beaufort,
 * Variant, Porta, Gronsfeld; keyed and other alphabets of 1-256 symbols. Any
 * cipher whose key symbol k turns cipher symbol c into plaintext
 * tables[k * m + c].
 *
 * Simple form (slot == NULL): every cipher symbol becomes one scored letter,
 * so tables hold letter codes and the letter counts are updated per changed
 * column (entropy and IoC cost O(26) per move). General form: tables hold
 * plaintext symbols; the scored text is rebuilt from the slot layout on each
 * move (a symbol may add no letter or several, and undecrypted letters are
 * scored where they stand).
 *
 * One restart = cct_periodic_start (random key), cct_periodic_anneal called in
 * chunks (resumable state, so Python can print progress and stop on Ctrl+C),
 * then cct_periodic_polish (hill climb over every single-symbol change).
 *
 * Moves, schedule and acceptance (cct_common.h): change one key
 * column to a different symbol, geometric cooling from t_start to t_end over
 * `iterations` moves, accept if diff >= 0 or rand < exp(diff / T). The n-gram
 * total is recomputed over the whole text on each move.
 *
 * Scoring modes (solve_periodic's scoring_mode):
 *   1: annealing.Fitness = mean n-gram score * letter_entropy ^ weight
 *   2: -penalty * 1000            (IoC target only)
 *   3: Fitness * max(0.05, 1 - 20 * penalty)
 * penalty = 0 inside [min_ioc, max_ioc], else the distance to the nearer bound.
 */
#include "cct_common.h"

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

typedef struct {
    const uint8_t *sym;      /* n cipher symbols, alphabet indices 0..m-1 */
    int32_t n, period;
    const uint8_t *tables;   /* nsym x m: simple form, the plaintext letter code; general form, the
                                plaintext symbol, for (key symbol, cipher symbol) */
    int32_t nsym;
    const uint8_t *scores;
    int32_t size;
    double weight;
    int32_t mode;
    double min_ioc, max_ioc;
    int32_t m;               /* cipher alphabet size (table row length), 1-256 */
    /* General form (slot != NULL): the scored text is not one letter per symbol
     * (an alphabet symbol shown as no A-Z letter or several, or letters that
     * pass through undecrypted). */
    const int32_t *slot;     /* scored text: >= 0 position (its symbol's codes), < 0 fixed code -(code + 1) */
    int32_t nslots, max_codes;
    const int32_t *code_offsets;  /* m + 1 */
    const uint8_t *codes;         /* A-Z codes each plaintext symbol adds */
} PeriodicProblem;

typedef struct {
    double current, best, temp, ratio;
    int64_t step, iterations;
    uint64_t rng[4];
} PeriodicAnneal;

typedef struct {
    uint8_t *plain;          /* simple: letter code per position; general: plaintext symbol per position */
    double *term;            /* simple form: term[c] = (c/n) log2 (c/n), as letter_entropy computes it */
    int counts[26];          /* simple form: letter counts */
    int *symcount;           /* general form: plaintext symbol counts (m) */
    int fixed[26];           /* general form: counts of the fixed letters */
    uint8_t *text;           /* general form: the scored letter codes */
} Work;

static void work_free(Work *w) { free(w->plain); free(w->term); free(w->symcount); free(w->text); }

static int work_init(const PeriodicProblem *p, const uint8_t *key, Work *w) {
    int n = p->n;
    memset(w, 0, sizeof *w);
    w->plain = (uint8_t *)malloc(n > 0 ? n : 1);
    if (!w->plain) return 0;
    if (!p->slot) {
        w->term = (double *)malloc(sizeof(double) * (n + 1));
        if (!w->term) { work_free(w); return 0; }
        w->term[0] = 0.0;
        for (int c = 1; c <= n; c++) { double q = (double)c / n; w->term[c] = q * log2(q); }
    } else {
        w->symcount = (int *)calloc(p->m > 0 ? p->m : 1, sizeof(int));
        w->text = (uint8_t *)malloc(p->max_codes > 0 ? p->max_codes : 1);
        if (!w->symcount || !w->text) { work_free(w); return 0; }
        for (int j = 0; j < p->nslots; j++) if (p->slot[j] < 0) w->fixed[-p->slot[j] - 1]++;
    }
    for (int i = 0; i < n; i++) {
        uint8_t value = p->tables[key[i % p->period] * p->m + p->sym[i]];
        w->plain[i] = value;
        if (p->slot) w->symcount[value]++; else w->counts[value]++;
    }
    return 1;
}

static inline void set_column(const PeriodicProblem *p, Work *w, int column, int symbol) {
    const uint8_t *table = p->tables + symbol * p->m;
    int *counts = p->slot ? w->symcount : w->counts;
    for (int i = column; i < p->n; i += p->period) {
        counts[w->plain[i]]--;
        uint8_t value = table[p->sym[i]];
        w->plain[i] = value;
        counts[value]++;
    }
}

/* General form: the scored letter codes into w->text (returns their count)
 * and the letter counts. */
static int general_text(const PeriodicProblem *p, Work *w, int64_t counts[26]) {
    for (int c = 0; c < 26; c++) counts[c] = w->fixed[c];
    for (int s = 0; s < p->m; s++) {
        int c = w->symcount[s];
        if (c) for (int32_t k = p->code_offsets[s]; k < p->code_offsets[s + 1]; k++) counts[p->codes[k]] += c;
    }
    int len = 0;
    for (int j = 0; j < p->nslots; j++) {
        int32_t e = p->slot[j];
        if (e < 0) { w->text[len++] = (uint8_t)(-e - 1); continue; }
        int s = w->plain[e];
        for (int32_t k = p->code_offsets[s]; k < p->code_offsets[s + 1]; k++) w->text[len++] = p->codes[k];
    }
    return len;
}

/* Modes 2 and 3: distance of the IoC (pairs over n letters) from the target window. */
static double ioc_penalty(const PeriodicProblem *p, int n, int64_t pairs) {
    if (n >= 2) {
        double ioc = (double)pairs / ((double)n * (n - 1));
        if (!(p->min_ioc <= ioc && ioc <= p->max_ioc)) {
            double a = fabs(ioc - p->min_ioc), b = fabs(ioc - p->max_ioc);
            return a < b ? a : b;
        }
    } else if (!(p->min_ioc <= 0.0 && 0.0 <= p->max_ioc)) {
        double a = fabs(p->min_ioc), b = fabs(p->max_ioc);
        return a < b ? a : b;
    }
    return 0.0;
}

static double mode_score(const PeriodicProblem *p, double base, double penalty) {
    if (p->mode == 2) return -penalty * 1000.0;
    double factor = 1.0 - penalty * 20.0;
    return base * (factor > 0.05 ? factor : 0.05);
}

/* General form: the scored text is rebuilt; letter_entropy computed as Python does
 * (q = count / total; entropy -= q * log2(q)). */
static double score_general(const PeriodicProblem *p, Work *w) {
    int64_t counts[26];
    int n = general_text(p, w, counts);
    double base = 0.0;
    if (p->mode != 2) {
        int count = n - p->size + 1;
        if (count <= 0) base = -9999.0;
        else {
            double entropy = 0.0;
            for (int c = 0; c < 26; c++)
                if (counts[c]) { double q = (double)counts[c] / n; entropy -= q * log2(q); }
            base = (double)rolling_total(w->text, n, p->scores, p->size) / count * pow(entropy, p->weight);
        }
        if (p->mode != 3) return base;
    }
    int64_t pairs = 0;
    for (int c = 0; c < 26; c++) pairs += counts[c] * (counts[c] - 1);
    return mode_score(p, base, ioc_penalty(p, n, pairs));
}

static double score(const PeriodicProblem *p, Work *w) {
    if (p->slot) return score_general(p, w);
    int n = p->n;
    double base = 0.0;
    if (p->mode != 2) {
        int count = n - p->size + 1;
        if (count <= 0) base = -9999.0;
        else {
            double entropy = 0.0;
            for (int c = 0; c < 26; c++) if (w->counts[c]) entropy -= w->term[w->counts[c]];
            base = (double)rolling_total(w->plain, n, p->scores, p->size) / count * pow(entropy, p->weight);
        }
        if (p->mode != 3) return base;
    }
    int64_t pairs = 0;
    for (int c = 0; c < 26; c++) pairs += (int64_t)w->counts[c] * (w->counts[c] - 1);
    return mode_score(p, base, ioc_penalty(p, n, pairs));
}

/* Random starting key, its score, and the schedule. Returns 0 on bad input. */
EXPORT int32_t cct_periodic_start(const PeriodicProblem *p, uint64_t seed, int64_t iterations, double t_start,
                                  double t_end, PeriodicAnneal *st, uint8_t *key, uint8_t *best_key) {
    if (p->n < 1 || p->period < 1 || p->nsym < 1 || p->m < 1 || p->m > 256) return 0;
    Rng rng;
    rng_seed(&rng, seed);
    for (int c = 0; c < p->period; c++) key[c] = (uint8_t)rng_below(&rng, p->nsym);
    Work w;
    if (!work_init(p, key, &w)) return 0;
    st->current = st->best = score(p, &w);
    work_free(&w);
    memcpy(best_key, key, p->period);
    st->iterations = iterations > 0 ? iterations : 1;
    st->temp = t_start;
    st->ratio = cct_cooling_ratio(t_start, t_end, st->iterations);
    st->step = 0;
    memcpy(st->rng, rng.s, sizeof rng.s);
    return 1;
}

/* Up to max_steps annealing moves from the saved state. Returns the moves made
 * (0 when the schedule is finished), -1 on allocation failure. */
EXPORT int64_t cct_periodic_anneal(const PeriodicProblem *p, int64_t max_steps, PeriodicAnneal *st, uint8_t *key,
                                   uint8_t *best_key) {
    if (p->nsym < 2) { st->step = st->iterations; return 0; }   /* one symbol: nothing to change */
    Work w;
    if (!work_init(p, key, &w)) return -1;
    Rng rng;
    memcpy(rng.s, st->rng, sizeof rng.s);
    double current = st->current, best = st->best, temp = st->temp, ratio = st->ratio;
    int64_t done = 0, step = st->step;
    while (done < max_steps && step < st->iterations) {
        int column = rng_below(&rng, p->period);
        int old = key[column];
        int symbol = rng_below(&rng, p->nsym - 1);
        symbol += symbol >= old;
        set_column(p, &w, column, symbol);
        double s = score(p, &w);
        if (cct_accept(&rng, s - current, temp)) {
            key[column] = (uint8_t)symbol;
            current = s;
            if (s > best) { best = s; memcpy(best_key, key, p->period); }
        } else {
            set_column(p, &w, column, old);
        }
        temp *= ratio;
        step++;
        done++;
    }
    st->current = current; st->best = best; st->temp = temp; st->step = step;
    memcpy(st->rng, rng.s, sizeof rng.s);
    work_free(&w);
    return done;
}

/* Hill-climb over every (column, symbol) move, in that order, at most
 * max_rounds full passes. Updates key; writes the scored plaintext letter codes
 * (n of them in the simple form, at most max_codes in the general form) and
 * their count; returns the score (or -1e300 on allocation failure). */
EXPORT double cct_periodic_polish(const PeriodicProblem *p, int32_t max_rounds, uint8_t *key, uint8_t *plain_out,
                                  int32_t *plain_len) {
    Work w;
    if (!work_init(p, key, &w)) return -1e300;
    double current = score(p, &w);
    for (int round = 0; round < max_rounds; round++) {
        int improved = 0;
        for (int column = 0; column < p->period; column++) {
            for (int symbol = 0; symbol < p->nsym; symbol++) {
                int old = key[column];
                set_column(p, &w, column, symbol);
                double s = score(p, &w);
                if (s > current + 1e-12) { current = s; key[column] = (uint8_t)symbol; improved = 1; }
                else set_column(p, &w, column, old);
            }
        }
        if (!improved) break;
    }
    if (p->slot) {
        int64_t counts[26];
        *plain_len = general_text(p, &w, counts);
        memcpy(plain_out, w.text, *plain_len);
    } else {
        *plain_len = p->n;
        memcpy(plain_out, w.plain, p->n);
    }
    work_free(&w);
    return current;
}

/* Score of one key (the same function the annealer maximises); for tests. */
EXPORT double cct_periodic_score(const PeriodicProblem *p, const uint8_t *key) {
    Work w;
    if (!work_init(p, key, &w)) return -1e300;
    double s = score(p, &w);
    work_free(&w);
    return s;
}
