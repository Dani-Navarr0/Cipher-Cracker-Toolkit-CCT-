/* OpenCL kernels for the toolkit's columnar searches (see native/gpu.py).
 *
 * Column order index = lexicographic permutation number of the columns after a
 * fixed prefix (the order the CPU code enumerates). Each work-item unranks its
 * first order and steps through PER_ITEM orders with next_permutation.
 *
 * perm_score:   n-gram total of each decryption; every work-item reports its best
 *               (highest total, lowest index), the host takes the overall best.
 * crib_periodic: columnar + periodic key consistent with known plaintext letters
 *               (hits through an atomic counter; the host sorts them into CPU
 *               order and redoes on the CPU any launch that overflows).
 * Sizes are set per build with -D MAXW=, -D MAXCRIB=, -D MAXP=.
 */
#ifndef MAXW
#define MAXW 32
#endif
#ifndef MAXCRIB
#define MAXCRIB 64
#endif
#ifndef MAXP
#define MAXP 64
#endif

static void unrank(ulong idx, int prefix_len, __constant uchar *prefix, int tail_len, __constant uchar *rest,
                   __constant ulong *fact, uchar *key) {
    uchar avail[MAXW];
    for (int j = 0; j < prefix_len; j++) key[j] = prefix[j];
    for (int j = 0; j < tail_len; j++) avail[j] = rest[j];
    ulong r = idx;
    for (int j = 0; j < tail_len; j++) {
        ulong f = fact[tail_len - 1 - j];
        int d = (int)(r / f);
        r -= (ulong)d * f;
        key[prefix_len + j] = avail[d];
        for (int q = d; q < tail_len - 1 - j; q++) avail[q] = avail[q + 1];
    }
}

static int next_perm(uchar *key, int prefix_len, int tail_len) {
    int i = tail_len - 2;
    while (i >= 0 && key[prefix_len + i] >= key[prefix_len + i + 1]) i--;
    if (i < 0) return 0;
    int j = tail_len - 1;
    while (key[prefix_len + j] <= key[prefix_len + i]) j--;
    uchar t = key[prefix_len + i]; key[prefix_len + i] = key[prefix_len + j]; key[prefix_len + j] = t;
    for (int l = i + 1, h = tail_len - 1; l < h; l++, h--) {
        t = key[prefix_len + l]; key[prefix_len + l] = key[prefix_len + h]; key[prefix_len + h] = t;
    }
    return 1;
}

static void key_tables(const uchar *key, int width, int read_rows, int remainder, __global const int *col_len,
                       int *start, int *rank, int *prank) {
    if (!read_rows) {
        int s = 0;
        for (int j = 0; j < width; j++) { start[key[j]] = s; s += col_len[key[j]]; }
    } else {
        int pr = 0;
        for (int j = 0; j < width; j++) { rank[key[j]] = j; if (key[j] < remainder) prank[key[j]] = pr++; }
    }
}

__kernel void perm_score(
        __global const uchar *cipher, int n, int width, int read_rows, __global const int *col_len, int remainder,
        int partial_base, __global const int *d_col, __global const int *d_base, __global const int *d_kind,
        int prefix_len, __constant uchar *prefix, int tail_len, __constant uchar *rest, __constant ulong *fact,
        ulong base_index, ulong count, int per_item,
        __global const uchar *scores, int size, long modulus,
        __global long *best_total, __global ulong *best_index) {
    ulong g = get_global_id(0), offset = g * (ulong)per_item;
    if (offset >= count) return;
    ulong todo = count - offset < (ulong)per_item ? count - offset : (ulong)per_item;
    ulong idx = base_index + offset;
    uchar key[MAXW];
    unrank(idx, prefix_len, prefix, tail_len, rest, fact, key);
    long my_total = -1;
    ulong my_index = 0;
    for (ulong t = 0; t < todo; t++, idx++) {
        int start[MAXW], rank[MAXW], prank[MAXW];
        key_tables(key, width, read_rows, remainder, col_len, start, rank, prank);
        long index = 0, total = 0;
        for (int i = 0; i < n; i++) {
            int s = !read_rows ? start[d_col[i]] + d_base[i]
                  : d_kind[i] == 2 ? partial_base + prank[d_col[i]] : rank[d_col[i]] + d_base[i];
            index = (i < size - 1) ? index * 26 + cipher[s] : (index % modulus) * 26 + cipher[s];
            if (i >= size - 1) total += scores[index];
        }
        if (total > my_total) { my_total = total; my_index = idx; }
        if (!next_perm(key, prefix_len, tail_len)) break;
    }
    best_total[g] = my_total;
    best_index[g] = my_index;
}

__kernel void crib_periodic(
        __global const uchar *cipher, int ncrib, __constant int *crib_pos,
        int width, int read_rows, __global const int *col_len, int remainder, int partial_base,
        __constant int *d_col, __constant int *d_base, __constant int *d_kind,
        int prefix_len, __constant uchar *prefix, int tail_len, __constant uchar *rest, __constant ulong *fact,
        ulong base_index, ulong count, int per_item,
        int ncombo, __global const uchar *valtab,
        int nperiod, __constant int *periods, int min_checks,
        __constant uchar *fixed_a, __constant uchar *fixed_b, __constant int *fixed_n,
        __global volatile int *nhits, int max_hits, __global ulong *hit_index, __global int *hit_info) {
    ulong g = get_global_id(0), offset = g * (ulong)per_item;
    if (offset >= count) return;
    ulong todo = count - offset < (ulong)per_item ? count - offset : (ulong)per_item;
    ulong idx = base_index + offset;
    uchar key[MAXW];
    unrank(idx, prefix_len, prefix, tail_len, rest, fact, key);
    for (ulong t = 0; t < todo; t++, idx++) {
        int start[MAXW], rank[MAXW], prank[MAXW];
        int src[MAXCRIB];
        uchar letters[MAXCRIB];
        key_tables(key, width, read_rows, remainder, col_len, start, rank, prank);
        for (int k = 0; k < ncrib; k++) {
            src[k] = !read_rows ? start[d_col[k]] + d_base[k]
                   : d_kind[k] == 2 ? partial_base + prank[d_col[k]] : rank[d_col[k]] + d_base[k];
            letters[k] = cipher[src[k]];
        }
        uchar ma[MAXCRIB], mb[MAXCRIB];
        int last[MAXP];
        for (int p = 0; p < nperiod; p++) {
            int period = periods[p], mn = 0;
            for (int q = 0; q < period; q++) last[q] = -1;
            for (int k = 0; k < ncrib; k++) {
                int res = src[k] % period;
                if (last[res] >= 0) { ma[mn] = (uchar)last[res]; mb[mn] = (uchar)k; mn++; }
                last[res] = k;
            }
            int fn = fixed_n[p];
            for (int c = 0; c < ncombo; c++) {
                __global const uchar *table = valtab + c * ncrib * 26;
                for (int order = 0; order < 2; order++) {
                    int m = order ? mn : fn;
                    if (m < min_checks) continue;
                    int ok = 1;
                    for (int q = 0; q < m && ok; q++) {
                        int a = order ? ma[q] : fixed_a[p * MAXCRIB + q];
                        int b = order ? mb[q] : fixed_b[p * MAXCRIB + q];
                        if (table[a * 26 + letters[a]] != table[b * 26 + letters[b]]) ok = 0;
                    }
                    if (!ok) continue;
                    int slot = atomic_inc(nhits);
                    if (slot < max_hits) {
                        hit_index[slot] = idx;
                        hit_info[slot * 4] = c; hit_info[slot * 4 + 1] = order;
                        hit_info[slot * 4 + 2] = p; hit_info[slot * 4 + 3] = m;
                    }
                }
            }
        }
        if (!next_perm(key, prefix_len, tail_len)) break;
    }
}
