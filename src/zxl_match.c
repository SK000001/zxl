/*
 * ZXL - Match Engine Implementation
 */
#include "zxl_match.h"

#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Hash functions                                                       */
/* ------------------------------------------------------------------ */

/* Exact: hash the raw 4-byte value at p */
static inline uint32_t hash_exact(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return ((v * 2654435761u) >> (32 - ZXL_HASH_BITS)) & ZXL_HASH_MASK;
}

/*
 * XOR-diff: hash the first-differences under XOR.
 *   diff[0] = p[0]^p[1],  diff[1] = p[1]^p[2],  diff[2] = p[2]^p[3]
 * Two sequences with the same XOR-diff sequence are XOR-related by
 * the constant  delta = seq_a[0] ^ seq_b[0].
 */
static inline uint32_t hash_xdiff(const uint8_t *p)
{
    uint32_t d = ((uint32_t)(p[0] ^ p[1]) << 16)
               | ((uint32_t)(p[1] ^ p[2]) <<  8)
               |  (uint32_t)(p[2] ^ p[3]);
    return ((d * 2246822519u) >> (32 - ZXL_HASH_BITS)) & ZXL_HASH_MASK;
}

/*
 * Add-diff: hash the first-differences under subtraction (mod 256).
 *   diff[0] = (p[1]-p[0])&0xFF, etc.
 * Two sequences with the same add-diff are additively related by
 *   delta = (seq_a[0] - seq_b[0]) & 0xFF.
 */
static inline uint32_t hash_adiff(const uint8_t *p)
{
    uint32_t d = ((uint32_t)((p[1] - p[0]) & 0xFF) << 16)
               | ((uint32_t)((p[2] - p[1]) & 0xFF) <<  8)
               |  (uint32_t)((p[3] - p[2]) & 0xFF);
    return ((d * 2246822519u) >> (32 - ZXL_HASH_BITS)) & ZXL_HASH_MASK;
}

/* ------------------------------------------------------------------ */
/* Match extension (with SIMD where available)                         */
/* ------------------------------------------------------------------ */

#if defined(__SSE2__)
#  include <emmintrin.h>
#  define HAS_SSE2 1
#endif
#if defined(__AVX2__)
#  include <immintrin.h>
#  define HAS_AVX2 1
#endif

/* Extend byte-identical match between a[0..] and b[0..], up to max bytes */
static uint32_t extend_exact(const uint8_t *a, const uint8_t *b, uint32_t max)
{
    uint32_t n = 0;

#if defined(HAS_AVX2)
    while (n + 32 <= max) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + n));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + n));
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(va, vb));
        if (mask != 0xFFFFFFFFu) {
            n += (uint32_t)__builtin_ctz(~mask);
            return n;
        }
        n += 32;
    }
#elif defined(HAS_SSE2)
    while (n + 16 <= max) {
        __m128i va = _mm_loadu_si128((const __m128i *)(a + n));
        __m128i vb = _mm_loadu_si128((const __m128i *)(b + n));
        uint32_t mask = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(va, vb));
        if (mask != 0xFFFFu) {
            n += (uint32_t)__builtin_ctz(~mask);
            return n;
        }
        n += 16;
    }
#endif
    while (n < max && a[n] == b[n]) n++;
    return n;
}

/* Extend XOR-delta match: a[i] == b[i] ^ delta */
static uint32_t extend_xor(const uint8_t *a, const uint8_t *b,
                            uint8_t delta, uint32_t max)
{
    uint32_t n = 0;

#if defined(HAS_AVX2)
    __m256i vd = _mm256_set1_epi8((char)delta);
    while (n + 32 <= max) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + n));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + n));
        __m256i xb = _mm256_xor_si256(vb, vd);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(va, xb));
        if (mask != 0xFFFFFFFFu) {
            n += (uint32_t)__builtin_ctz(~mask);
            return n;
        }
        n += 32;
    }
#elif defined(HAS_SSE2)
    __m128i vd = _mm_set1_epi8((char)delta);
    while (n + 16 <= max) {
        __m128i va = _mm_loadu_si128((const __m128i *)(a + n));
        __m128i vb = _mm_loadu_si128((const __m128i *)(b + n));
        __m128i xb = _mm_xor_si128(vb, vd);
        uint32_t mask = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(va, xb));
        if (mask != 0xFFFFu) {
            n += (uint32_t)__builtin_ctz(~mask);
            return n;
        }
        n += 16;
    }
#endif
    while (n < max && a[n] == (uint8_t)(b[n] ^ delta)) n++;
    return n;
}

/* Extend add-delta match: a[i] == (b[i] + delta) & 0xFF */
static uint32_t extend_add(const uint8_t *a, const uint8_t *b,
                            uint8_t delta, uint32_t max)
{
    uint32_t n = 0;

#if defined(HAS_AVX2)
    __m256i vd = _mm256_set1_epi8((char)delta);
    while (n + 32 <= max) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + n));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + n));
        /* _mm256_add_epi8 wraps mod 256 — exactly what we need */
        __m256i ab = _mm256_add_epi8(vb, vd);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(va, ab));
        if (mask != 0xFFFFFFFFu) {
            n += (uint32_t)__builtin_ctz(~mask);
            return n;
        }
        n += 32;
    }
#elif defined(HAS_SSE2)
    __m128i vd = _mm_set1_epi8((char)delta);
    while (n + 16 <= max) {
        __m128i va = _mm_loadu_si128((const __m128i *)(a + n));
        __m128i vb = _mm_loadu_si128((const __m128i *)(b + n));
        __m128i ab = _mm_add_epi8(vb, vd);
        uint32_t mask = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(va, ab));
        if (mask != 0xFFFFu) {
            n += (uint32_t)__builtin_ctz(~mask);
            return n;
        }
        n += 16;
    }
#endif
    while (n < max && a[n] == (uint8_t)(b[n] + delta)) n++;
    return n;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void match_ctx_init(MatchCtx *ctx)
{
    memset(ctx, 0xFF, sizeof(*ctx));  /* 0xFFFFFFFF = "no entry" sentinel */
}

/*
 * Walk one hash chain, updating best match found so far.
 * 'head' is the first candidate position from the head table.
 * 'next' is the array of chain pointers.
 * Returns the best savings seen (updates best_* in place).
 */
#define WALK_CHAIN(head, next_arr, MTYPE, extend_fn, delta_expr)          \
do {                                                                       \
    uint32_t _ref = (head);                                                \
    for (int _d = 0; _d < ZXL_CHAIN_DEPTH && _ref != 0xFFFFFFFFu; _d++) { \
        if (pos > _ref) {                                                   \
            uint32_t _off = pos - _ref;                                    \
            if (_off > ZXL_MAX_OFFSET) break;  /* chain is oldest-first */ \
            uint8_t  _delta = (delta_expr);                                \
            uint32_t _len   = extend_fn(cur, src + _ref, _delta, max_len);\
            if (_len >= ZXL_MIN_MATCH) {                                   \
                int32_t _sav = match_savings(_len, (MTYPE));               \
                if (_sav > best_savings) {                                  \
                    best_savings  = _sav;                                   \
                    best.offset   = _off;                                   \
                    best.length   = _len;                                   \
                    best.mtype    = (MTYPE);                                \
                    best.delta    = _delta;                                 \
                }                                                           \
                /* Track shortest viable match for the second DP candidate */ \
                if (_sav > 0 &&                                             \
                    (short_best.length == 0 || _len < short_best.length)) { \
                    short_best.offset = _off;                               \
                    short_best.length = _len;                               \
                    short_best.mtype  = (MTYPE);                            \
                    short_best.delta  = _delta;                             \
                }                                                           \
                /* Track best small-offset match (fits EXACT1/DELTA1 class) */ \
                if (_sav > 0 && _off < 256u &&                             \
                    (_len - ZXL_MIN_MATCH) < 256u &&                       \
                    _sav > best_e1_savings) {                               \
                    best_e1_savings  = _sav;                                \
                    best_e1.offset   = _off;                                \
                    best_e1.length   = _len;                                \
                    best_e1.mtype    = (MTYPE);                             \
                    best_e1.delta    = _delta;                              \
                }                                                           \
                if (_len == max_len) break;                                 \
            }                                                               \
        }                                                                   \
        _ref = (next_arr)[_ref & (ZXL_WINDOW - 1u)];                      \
    }                                                                       \
} while (0)

/* Wrappers so WALK_CHAIN can call extend_exact (which takes no delta) */
static inline uint32_t extend_exact_wrap(const uint8_t *a, const uint8_t *b,
                                          uint8_t delta, uint32_t max)
{
    (void)delta;
    return extend_exact(a, b, max);
}

int match_find(MatchCtx *ctx,
               const uint8_t *src, size_t src_len,
               uint32_t pos, Match out[3])
{
    if (pos + ZXL_MIN_MATCH > src_len) return 0;

    uint32_t max_len = (uint32_t)(src_len - pos);
    if (max_len > ZXL_MAX_MATCH) max_len = ZXL_MAX_MATCH;

    const uint8_t *cur = src + pos;

    int32_t best_savings = 0;   /* must beat 0 to be worth encoding */
    Match   best;
    best.length = 0;

    /* Shortest viable match: lets DP try "short here → better match after" */
    Match   short_best;
    short_best.length = 0;

    /* Best small-offset match (off<256, lm<256): fits EXACT1/DELTA1 class.
     * The DP can choose this when the global best is a high-overhead EXACT2/EXACT. */
    int32_t best_e1_savings = 0;
    Match   best_e1;
    best_e1.length = 0;

    /* --- 1. Exact chain -------------------------------------------- */
    WALK_CHAIN(ctx->exact_ht[hash_exact(cur)], ctx->exact_next,
               MTYPE_EXACT, extend_exact_wrap, 0u);

    /* --- 2. XOR-delta chain ---------------------------------------- */
    if (pos + 4 <= src_len)
        WALK_CHAIN(ctx->xdiff_ht[hash_xdiff(cur)], ctx->xdiff_next,
                   MTYPE_XOR, extend_xor, (uint8_t)(cur[0] ^ src[_ref]));

    /* --- 3. Additive-delta chain ----------------------------------- */
    if (pos + 4 <= src_len)
        WALK_CHAIN(ctx->adiff_ht[hash_adiff(cur)], ctx->adiff_next,
                   MTYPE_ADD, extend_add, (uint8_t)(cur[0] - src[_ref]));

    if (best.length == 0) return 0;
    out[0] = best;
    int n = 1;

    /* Second candidate: shortest viable match (different length from best). */
    if (short_best.length > 0 && short_best.length != best.length) {
        out[n++] = short_best;
    }

    /* Third candidate: best small-offset match (off<256, lm<256).
     * Include only when it is not already covered by out[0] or out[1].
     * Two candidates at the same (offset, length) yield identical DP choices. */
    if (best_e1.length > 0) {
        int dup = (best_e1.offset == out[0].offset && best_e1.length == out[0].length);
        if (!dup && n >= 2)
            dup = (best_e1.offset == out[1].offset && best_e1.length == out[1].length);
        if (!dup) out[n++] = best_e1;
    }

    return n;
}

void match_update(MatchCtx *ctx, const uint8_t *src, uint32_t pos)
{
    const uint8_t *p = src + pos;
    uint32_t slot = pos & (ZXL_WINDOW - 1u);
    uint32_t h;

    h = hash_exact(p);
    ctx->exact_next[slot] = ctx->exact_ht[h];
    ctx->exact_ht[h] = pos;

    h = hash_xdiff(p);
    ctx->xdiff_next[slot] = ctx->xdiff_ht[h];
    ctx->xdiff_ht[h] = pos;

    h = hash_adiff(p);
    ctx->adiff_next[slot] = ctx->adiff_ht[h];
    ctx->adiff_ht[h] = pos;
}
