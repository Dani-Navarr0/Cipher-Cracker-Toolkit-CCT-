/* Multi-layer annealer: layered.LayeredSolver (two_layer.py, tool 61; the
 * analyzer's hill-climb; tool 45's annealing; tool 13's substitution search).
 *
 * A stack of 1-4 layers is given in DECRYPTION order (layer 0 is applied to
 * the ciphertext first). Layer kinds and keys:
 *   0 substitution  key[26]: key[c] = plaintext letter of cipher letter c
 *   1 transposition key[width]: column read order; the permutation of
 *                   transposition_core.make_permuter, given as the position
 *                   descriptors of native.columnar_descriptors (Layout)
 *   2 periodic      key[period]: shifts; variant 0 Vigenere p = c - k,
 *                   1 Beaufort p = k - c, 2 Variant Beaufort p = c + k (mod 26)
 * Fitness = annealing.Fitness: n-gram total / count * entropy factor, with the
 * factor fixed (fixed_factor >= 0) when every layer keeps letter counts.
 *
 * Moves (layered.py before the port): one layer per step, chosen by cumulative
 * weight; substitution swaps the plaintext of a cipher letter that occurs with
 * any other letter; transposition 60% swap two columns, 20% reverse a block
 * (inclusive), 20% move one column; periodic changes one shift to another value.
 * Annealing (cct_common.h): geometric cooling from t_start to t_end over the
 * step budget, accept if diff >= 0 or rand < exp(diff / T). Polish
 * (LayeredSolver.polish): hill-climb over every single move of every layer.
 *
 * Every intermediate text is cached per layer (cur); a move in layer k
 * re-decrypts layers k.. into the spare buffers (alt) and swaps them in, so
 * the swap is also the undo. The state is a heap object (opaque handle);
 * cct_layered_anneal runs a bounded number of steps per call so the Python
 * side can print progress and honour Ctrl+C between calls.
 */
#include "cct_common.h"

#define LMAXL 4
#define LMAXW 64
#define LMAXP 128
#define LKEY 128

/* Same field layout as cct_native.c's Layout and native.Layout (ctypes). */
typedef struct {
    int32_t n;
    const uint8_t *cipher;
    int32_t width, read_rows, remainder, partial_base;
    const int32_t *col_len, *d_col, *d_base, *d_kind;
} Layout;

typedef struct {
    int kind, len, variant;
    /* transposition descriptors (copied) */
    int read_rows, remainder, partial_base;
    int32_t col_len[LMAXW];
    int32_t *d_col, *d_base, *d_kind;
    /* substitution: cipher letters that occur in this layer's input */
    int npresent;
    uint8_t present[26], is_present[26];
    uint8_t key[LKEY], best[LKEY];
} Layer;

typedef struct {
    int n, nlayers, size;
    uint8_t *cipher;
    uint8_t *cur[LMAXL], *alt[LMAXL];
    Layer layer[LMAXL];
    double cum[LMAXL];
    const uint8_t *scores;
    double weight, fixed;
    Rng rng;
    double current, best_score, temp, ratio;
    int64_t step, iterations;
    int last;                 /* layer changed by the last move (for undo) */
    uint8_t saved[LKEY];
    double saved_score;
    /* n-gram score of every window of the plaintext (cur/alt like the texts) and
     * their totals: a move only looks up the windows whose letters changed */
    uint8_t *wcur, *walt;
    int64_t tcur, talt;
    int windows_ready;
} Stack;

/* ------------------------------------------------------------ decryption */

static void decrypt_layer(const Layer *L, const uint8_t *in, uint8_t *out, int n) {
    if (L->kind == 0) {
        for (int i = 0; i < n; i++) out[i] = L->key[in[i]];
    } else if (L->kind == 2) {
        int p = L->len;
        for (int col = 0; col < p && col < n; col++) {
            int k = L->key[col];
            for (int i = col; i < n; i += p) {
                int c = in[i], v = L->variant == 0 ? c - k : L->variant == 1 ? k - c : c + k;
                v %= 26; if (v < 0) v += 26;
                out[i] = (uint8_t)v;
            }
        }
    } else {
        int32_t start[LMAXW], rank[LMAXW], prank[LMAXW];
        int w = L->len;
        if (!L->read_rows) {
            int32_t s = 0;
            for (int j = 0; j < w; j++) { start[L->key[j]] = s; s += L->col_len[L->key[j]]; }
            for (int i = 0; i < n; i++) out[i] = in[start[L->d_col[i]] + L->d_base[i]];
        } else {
            int pr = 0;
            for (int j = 0; j < w; j++) { rank[L->key[j]] = j; if (L->key[j] < L->remainder) prank[L->key[j]] = pr++; }
            for (int i = 0; i < n; i++)
                out[i] = in[L->d_kind[i] == 2 ? L->partial_base + prank[L->d_col[i]] : rank[L->d_col[i]] + L->d_base[i]];
        }
    }
}

/* annealing.Fitness of the new plaintext (alt[last]) given the old one (cur[last]):
 * the windows that contain a changed letter are looked up again, the others keep
 * their cached scores. The total is the exact n-gram total (ngram_total). */
static double score_new_plaintext(Stack *S) {
    const uint8_t *now = S->alt[S->nlayers - 1], *old = S->cur[S->nlayers - 1];
    int n = S->n, size = S->size, nw = n - size + 1;
    if (nw <= 0) { S->talt = 0; return -9999.0; }
    int64_t modulus = cct_ngram_modulus(size), index = 0, total;
    const uint8_t *scores = S->scores;
    uint8_t *win = S->walt;
    if (!S->windows_ready) {
        total = 0;
        for (int i = 0; i < size - 1; i++) index = index * 26 + now[i];
        for (int i = size - 1; i < n; i++) {
            index = (index % modulus) * 26 + now[i];
            win[i - size + 1] = scores[index];
            total += scores[index];
        }
        S->windows_ready = 1;
    } else {
        memcpy(win, S->wcur, (size_t)nw);
        total = S->tcur;
        int last_change = -size;
        for (int i = 0; i < size - 1; i++) { index = index * 26 + now[i]; if (now[i] != old[i]) last_change = i; }
        for (int i = size - 1; i < n; i++) {
            index = (index % modulus) * 26 + now[i];
            if (now[i] != old[i]) last_change = i;
            if (last_change > i - size) {
                int w = i - size + 1;
                uint8_t value = scores[index];
                total += (int64_t)value - win[w];
                win[w] = value;
            }
        }
    }
    S->talt = total;
    double factor = S->fixed >= 0 ? S->fixed : cct_entropy_factor(now, n, S->weight);
    return (double)total / nw * factor;
}

static void swap_windows(Stack *S) {
    uint8_t *t = S->wcur; S->wcur = S->walt; S->walt = t;
    int64_t x = S->tcur; S->tcur = S->talt; S->talt = x;
}

/* Re-decrypt layers from..nlayers-1 into alt, swap them in; returns the new fitness. */
static double recompute(Stack *S, int from) {
    const uint8_t *text = from == 0 ? S->cipher : S->cur[from - 1];
    for (int j = from; j < S->nlayers; j++) {
        decrypt_layer(&S->layer[j], text, S->alt[j], S->n);
        text = S->alt[j];
    }
    double score = score_new_plaintext(S);
    for (int j = from; j < S->nlayers; j++) { uint8_t *t = S->cur[j]; S->cur[j] = S->alt[j]; S->alt[j] = t; }
    swap_windows(S);
    return score;
}

static void swap_back(Stack *S, int from) {
    for (int j = from; j < S->nlayers; j++) { uint8_t *t = S->cur[j]; S->cur[j] = S->alt[j]; S->alt[j] = t; }
    swap_windows(S);
}

/* ------------------------------------------------------------ moves */

static void random_key(Stack *S, Layer *L) {
    if (L->kind == 2) {
        for (int i = 0; i < L->len; i++) L->key[i] = (uint8_t)rng_below(&S->rng, 26);
        return;
    }
    for (int i = 0; i < L->len; i++) L->key[i] = (uint8_t)i;
    for (int i = L->len - 1; i > 0; i--) {
        int j = rng_below(&S->rng, i + 1);
        uint8_t t = L->key[i]; L->key[i] = L->key[j]; L->key[j] = t;
    }
}

static void move_column(uint8_t *key, int i, int j) {   /* key.insert(j, key.pop(i)) */
    uint8_t x = key[i];
    if (i < j) memmove(key + i, key + i + 1, (size_t)(j - i));
    else if (i > j) memmove(key + j + 1, key + j, (size_t)(i - j));
    key[j] = x;
}

static void random_move(Stack *S, Layer *L) {
    uint8_t *key = L->key;
    if (L->kind == 0) {
        int a = L->present[rng_below(&S->rng, L->npresent)];
        int b = rng_below(&S->rng, 25);
        if (b >= a) b++;
        uint8_t t = key[a]; key[a] = key[b]; key[b] = t;
    } else if (L->kind == 1) {
        int w = L->len;
        double roll = rng_double(&S->rng);
        int i = rng_below(&S->rng, w), j = rng_below(&S->rng, w - 1);
        if (j >= i) j++;
        if (roll < 0.6) {
            uint8_t t = key[i]; key[i] = key[j]; key[j] = t;
        } else if (roll < 0.8) {
            if (i > j) { int t = i; i = j; j = t; }
            for (; i < j; i++, j--) { uint8_t t = key[i]; key[i] = key[j]; key[j] = t; }
        } else {
            move_column(key, i, j);
        }
    } else {
        int col = rng_below(&S->rng, L->len);
        int old = key[col], v = rng_below(&S->rng, 25);
        key[col] = (uint8_t)(v + (v >= old));
    }
}

static int choose_layer(Stack *S) {
    double roll = rng_double(&S->rng);
    for (int i = 0; i < S->nlayers; i++) if (roll < S->cum[i]) return i;
    return S->nlayers - 1;
}

static double propose_in(Stack *S, int k) {
    Layer *L = &S->layer[k];
    memcpy(S->saved, L->key, (size_t)L->len);
    S->saved_score = S->current;
    S->last = k;
    random_move(S, L);
    S->current = recompute(S, k);
    return S->current;
}

static void undo(Stack *S) {
    Layer *L = &S->layer[S->last];
    memcpy(L->key, S->saved, (size_t)L->len);
    swap_back(S, S->last);
    S->current = S->saved_score;
}

static void save_best(Stack *S) {
    S->best_score = S->current;
    for (int j = 0; j < S->nlayers; j++) memcpy(S->layer[j].best, S->layer[j].key, (size_t)S->layer[j].len);
}

/* ------------------------------------------------------------ API */

EXPORT void cct_layered_free(Stack *S) {
    if (!S) return;
    for (int j = 0; j < S->nlayers; j++) {
        free(S->cur[j]); free(S->alt[j]);
        free(S->layer[j].d_col); free(S->layer[j].d_base); free(S->layer[j].d_kind);
    }
    free(S->cipher); free(S->wcur); free(S->walt);
    free(S);
}

/* kinds/params/variants: per layer (param = width or period; 26 for substitution).
 * layouts: one Layout per layer (only read for transposition layers).
 * weights: relative move weights per layer. scores: the n-gram table (not copied:
 * the caller keeps it alive). Keys start as the identity / zero shifts; set them
 * with cct_layered_set_key or cct_layered_randomize. Returns NULL on bad input. */
EXPORT Stack *cct_layered_new(const uint8_t *cipher, int32_t n, int32_t nlayers, const int32_t *kinds,
                              const int32_t *params, const int32_t *variants, const Layout *layouts,
                              const double *weights, const uint8_t *scores, int32_t size, double weight,
                              double fixed_factor, uint64_t seed) {
    if (n <= 0 || nlayers < 1 || nlayers > LMAXL) return NULL;
    Stack *S = calloc(1, sizeof(Stack));
    if (!S) return NULL;
    S->n = n; S->nlayers = nlayers; S->size = size; S->scores = scores;
    S->weight = weight; S->fixed = fixed_factor;
    rng_seed(&S->rng, seed);
    S->cipher = malloc((size_t)n);
    S->wcur = malloc((size_t)n); S->walt = malloc((size_t)n);
    if (!S->cipher || !S->wcur || !S->walt) { free(S->cipher); free(S->wcur); free(S->walt); free(S); return NULL; }
    memcpy(S->cipher, cipher, (size_t)n);
    double total_weight = 0.0, running = 0.0;
    for (int j = 0; j < nlayers; j++) total_weight += weights[j];
    int ok = total_weight > 0;
    for (int j = 0; j < nlayers && ok; j++) {
        Layer *L = &S->layer[j];
        running += weights[j] / total_weight;
        S->cum[j] = running;
        L->kind = kinds[j]; L->variant = variants[j];
        S->cur[j] = malloc((size_t)n); S->alt[j] = malloc((size_t)n);
        if (!S->cur[j] || !S->alt[j]) { ok = 0; break; }
        if (L->kind == 0) {
            L->len = 26;
        } else if (L->kind == 1) {
            const Layout *t = &layouts[j];
            L->len = params[j];
            if (L->len < 2 || L->len > LMAXW || t->n != n || t->width != L->len) { ok = 0; break; }
            L->read_rows = t->read_rows; L->remainder = t->remainder; L->partial_base = t->partial_base;
            memcpy(L->col_len, t->col_len, sizeof(int32_t) * (size_t)L->len);
            L->d_col = malloc(sizeof(int32_t) * (size_t)n);
            L->d_base = malloc(sizeof(int32_t) * (size_t)n);
            L->d_kind = malloc(sizeof(int32_t) * (size_t)n);
            if (!L->d_col || !L->d_base || !L->d_kind) { ok = 0; break; }
            memcpy(L->d_col, t->d_col, sizeof(int32_t) * (size_t)n);
            memcpy(L->d_base, t->d_base, sizeof(int32_t) * (size_t)n);
            memcpy(L->d_kind, t->d_kind, sizeof(int32_t) * (size_t)n);
        } else if (L->kind == 2) {
            L->len = params[j];
            if (L->len < 1 || L->len > LMAXP || L->variant < 0 || L->variant > 2) { ok = 0; break; }
        } else { ok = 0; break; }
        for (int i = 0; i < L->len; i++) L->key[i] = L->kind == 2 ? 0 : (uint8_t)i;
        /* substitution moves pick a cipher letter that occurs in the layer's input;
         * the input's letter set is fixed only when every earlier layer is a
         * transposition (otherwise all 26 letters are candidates) */
        if (L->kind == 0) {
            int fixed_set = 1;
            for (int e = 0; e < j; e++) if (S->layer[e].kind != 1) fixed_set = 0;
            memset(L->is_present, 0, 26);
            if (fixed_set) for (int i = 0; i < n; i++) L->is_present[cipher[i] % 26] = 1;
            L->npresent = 0;
            for (int c = 0; c < 26; c++) if (L->is_present[c]) L->present[L->npresent++] = (uint8_t)c;
            if (L->npresent < 2) {
                L->npresent = 26;
                for (int c = 0; c < 26; c++) { L->present[c] = (uint8_t)c; L->is_present[c] = 1; }
            }
        }
    }
    if (!ok) { S->nlayers = nlayers; cct_layered_free(S); return NULL; }
    S->cum[nlayers - 1] = 1.0;
    S->current = recompute(S, 0);
    save_best(S);
    S->temp = 0.0; S->ratio = 1.0; S->step = S->iterations = 0;
    return S;
}

/* Key of one layer: which 0 = current, 1 = best of the last annealing run. Returns its length. */
EXPORT int32_t cct_layered_get_key(const Stack *S, int32_t layer, int32_t which, uint8_t *out) {
    const Layer *L = &S->layer[layer];
    memcpy(out, which ? L->best : L->key, (size_t)L->len);
    return L->len;
}

/* Sets one layer's key (validated by the caller) and re-decrypts; returns the fitness. */
EXPORT double cct_layered_set_key(Stack *S, int32_t layer, const uint8_t *key) {
    memcpy(S->layer[layer].key, key, (size_t)S->layer[layer].len);
    S->current = recompute(S, layer);
    return S->current;
}

/* Random keys for every layer (the engine's generator); returns the fitness. */
EXPORT double cct_layered_randomize(Stack *S) {
    for (int j = 0; j < S->nlayers; j++) random_key(S, &S->layer[j]);
    S->current = recompute(S, 0);
    return S->current;
}

EXPORT void cct_layered_plaintext(const Stack *S, uint8_t *out) {
    memcpy(out, S->cur[S->nlayers - 1], (size_t)S->n);
}

EXPORT double cct_layered_score(const Stack *S) { return S->current; }

/* One random move (layer chosen by weight) and its fitness; cct_layered_undo reverts it. */
EXPORT double cct_layered_propose(Stack *S) { return propose_in(S, choose_layer(S)); }
EXPORT void cct_layered_undo(Stack *S) { undo(S); }

/* Starts an annealing run: geometric cooling t_start -> t_end over `iterations`
 * steps; the best state so far is the current one. */
EXPORT void cct_layered_schedule(Stack *S, int64_t iterations, double t_start, double t_end) {
    S->iterations = iterations > 0 ? iterations : 1;
    S->temp = t_start;
    S->ratio = cct_cooling_ratio(t_start, t_end, S->iterations);
    S->step = 0;
    save_best(S);
}

/* Runs at most max_steps of the scheduled run; returns the steps run (0 when finished). */
EXPORT int64_t cct_layered_anneal(Stack *S, int64_t max_steps) {
    int64_t run = 0;
    while (run < max_steps && S->step < S->iterations) {
        double score = propose_in(S, choose_layer(S));
        if (cct_accept(&S->rng, score - S->saved_score, S->temp)) {
            if (score > S->best_score) save_best(S);
        } else {
            undo(S);
        }
        S->temp *= S->ratio;
        S->step++;
        run++;
    }
    return run;
}

/* status: current, best, temperature; returns the step count of the run. */
EXPORT int64_t cct_layered_status(const Stack *S, double *out) {
    out[0] = S->current; out[1] = S->best_score; out[2] = S->temp;
    return S->step;
}

/* Makes the best keys of the run current; returns the fitness. */
EXPORT double cct_layered_restore_best(Stack *S) {
    for (int j = 0; j < S->nlayers; j++) memcpy(S->layer[j].key, S->layer[j].best, (size_t)S->layer[j].len);
    S->current = recompute(S, 0);
    return S->current;
}

/* ------------------------------------------------------------ polish */

typedef struct { uint8_t type, a, b; } Move;   /* type 0 swap a,b; 1 move column a -> b; 2 key[a] = b */
#define MAXMOVES (LMAXW * LMAXW + LMAXP * 26)

/* The single moves of one layer, in the order of layered.py's all_moves before
 * the port: substitution (a, b) with a present, b != a and (b absent or b > a);
 * transposition every swap i < j, then every move i -> j with |i - j| > 1;
 * periodic every (column, shift). */
static int layer_moves(const Layer *L, Move *moves) {
    int count = 0;
    if (L->kind == 0) {
        for (int ai = 0; ai < L->npresent; ai++) {
            int a = L->present[ai];
            for (int b = 0; b < 26; b++)
                if (b != a && !(L->is_present[b] && b < a)) moves[count++] = (Move){0, (uint8_t)a, (uint8_t)b};
        }
    } else if (L->kind == 1) {
        int w = L->len;
        for (int i = 0; i < w; i++)
            for (int j = i + 1; j < w; j++) moves[count++] = (Move){0, (uint8_t)i, (uint8_t)j};
        for (int i = 0; i < w; i++)
            for (int j = 0; j < w; j++)
                if (abs(i - j) > 1) moves[count++] = (Move){1, (uint8_t)i, (uint8_t)j};
    } else {
        for (int col = 0; col < L->len; col++)
            for (int shift = 0; shift < 26; shift++) moves[count++] = (Move){2, (uint8_t)col, (uint8_t)shift};
    }
    return count;
}

/* Hill climb: every single move of every layer, keeping improvements, for up to
 * max_rounds rounds or until a round improves nothing. Returns the fitness. */
EXPORT double cct_layered_polish(Stack *S, int32_t max_rounds) {
    Move *moves = malloc(sizeof(Move) * MAXMOVES);
    if (!moves) return S->current;
    double score = S->current;
    for (int round = 0; round < max_rounds; round++) {
        double before = score;
        for (int k = 0; k < S->nlayers; k++) {
            Layer *L = &S->layer[k];
            int count = layer_moves(L, moves);
            for (int m = 0; m < count; m++) {
                Move mv = moves[m];
                memcpy(S->saved, L->key, (size_t)L->len);
                S->saved_score = S->current;
                S->last = k;
                if (mv.type == 0) { uint8_t t = L->key[mv.a]; L->key[mv.a] = L->key[mv.b]; L->key[mv.b] = t; }
                else if (mv.type == 1) move_column(L->key, mv.a, mv.b);
                else L->key[mv.a] = mv.b;
                S->current = recompute(S, k);
                if (S->current > score + 1e-12) score = S->current;
                else undo(S);
            }
        }
        if (score <= before + 1e-12) break;
    }
    free(moves);
    return S->current;
}
