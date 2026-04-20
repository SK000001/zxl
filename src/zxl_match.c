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

/* Short: hash the raw 3-byte value at p for 3-byte exact-match lookups. */
static inline uint32_t hash_short(const uint8_t *p)
{
    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
    return ((v * 506832829u) >> (32 - ZXL_HASH_BITS)) & ZXL_HASH_MASK;
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
                /* Track best mid-offset match (fits EXACT2/DELTA2 class) */ \
                if (_sav > 0 && _off >= 256u && _off < 65536u &&           \
                    (_len - ZXL_MIN_MATCH) < 256u &&                       \
                    _sav > best_e2_savings) {                               \
                    best_e2_savings  = _sav;                                \
                    best_e2.offset   = _off;                                \
                    best_e2.length   = _len;                                \
                    best_e2.mtype    = (MTYPE);                             \
                    best_e2.delta    = _delta;                              \
                }                                                           \
                /* Track longest match of any type */                       \
                if (_sav > 0 && _len > longest.length) {                   \
                    longest.offset   = _off;                                \
                    longest.length   = _len;                                \
                    longest.mtype    = (MTYPE);                             \
                    longest.delta    = _delta;                              \
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
               uint32_t pos, Match out[ZXL_MAX_CANDIDATES])
{
    if (pos + 3u > src_len) return 0;

    uint32_t max_len = (uint32_t)(src_len - pos);
    if (max_len > ZXL_MAX_MATCH) max_len = ZXL_MAX_MATCH;

    const uint8_t *cur = src + pos;

    int32_t best_savings = 0;   /* must beat 0 to be worth encoding */
    Match   best;
    best.length = 0;

    /* Shortest viable match: lets DP try "short here → better match after" */
    Match   short_best;
    short_best.length = 0;

    /* Best small-offset match (off<256, lm<256): fits EXACT1/DELTA1 class */
    int32_t best_e1_savings = 0;
    Match   best_e1;
    best_e1.length = 0;

    /* Best mid-offset match (256<=off<65536, lm<256): fits EXACT2/DELTA2 */
    int32_t best_e2_savings = 0;
    Match   best_e2;
    best_e2.length = 0;

    /* Longest match of any type */
    Match   longest;
    longest.length = 0;

    /* Best 3-byte exact match with offset < 256 (fits TOK_EXACT0).
     * Chosen independently of 4-byte matches — even a 3-byte match
     * with offset 255 beats 3 literals (~16 bits vs ~24). */
    Match   short3;
    short3.length = 0;
    uint32_t short3_best_off = 0xFFFFFFFFu;  /* smaller offset preferred */

    /* Only walk 4+byte chains when enough input remains for a 4-byte match. */
    if (pos + ZXL_MIN_MATCH <= src_len) {
        /* --- 1. Exact chain -------------------------------------------- */
        WALK_CHAIN(ctx->exact_ht[hash_exact(cur)], ctx->exact_next,
                   MTYPE_EXACT, extend_exact_wrap, 0u);

        /* --- 2. XOR-delta chain ---------------------------------------- */
        WALK_CHAIN(ctx->xdiff_ht[hash_xdiff(cur)], ctx->xdiff_next,
                   MTYPE_XOR, extend_xor, (uint8_t)(cur[0] ^ src[_ref]));

        /* --- 3. Additive-delta chain ----------------------------------- */
        WALK_CHAIN(ctx->adiff_ht[hash_adiff(cur)], ctx->adiff_next,
                   MTYPE_ADD, extend_add, (uint8_t)(cur[0] - src[_ref]));
    }

    /* --- 4. Short (3-byte) chain, only for offset < 256 ------------ */
    /* Walk up to a limited number of entries looking for a 3-byte match.
     * Requires offset < 256 to use TOK_EXACT0 (1-byte offset). */
    if (pos + 3u <= src_len) {
        uint32_t ref = ctx->short_ht[hash_short(cur)];
        int walked = 0;
        /* Short chain is cheap — bound by a smaller depth than full chain */
        const int SHORT_DEPTH = 64;
        while (ref != 0xFFFFFFFFu && walked < SHORT_DEPTH) {
            if (pos > ref) {
                uint32_t off = pos - ref;
                if (off >= 256u) break;  /* chain is oldest-first; no smaller offset ahead */
                /* Verify 3-byte match (hash is not a guarantee) */
                const uint8_t *refp = src + ref;
                if (refp[0] == cur[0] && refp[1] == cur[1] && refp[2] == cur[2]) {
                    /* Prefer smallest offset (better 1-byte offset encoding distribution) */
                    if (off < short3_best_off) {
                        short3_best_off   = off;
                        short3.offset     = off;
                        short3.length     = 3u;
                        short3.mtype      = MTYPE_EXACT;
                        short3.delta      = 0;
                    }
                }
            }
            ref = ctx->short_next[ref & (ZXL_WINDOW - 1u)];
            walked++;
        }
    }

    if (best.length == 0 && short3.length == 0) return 0;
    int n = 0;
    if (best.length > 0) out[n++] = best;

    /* Helper: check if match is duplicate of existing candidates */
    #define CHECK_AND_ADD(cand) do { \
        if ((cand).length > 0) { \
            int _dup = 0; \
            for (int _k = 0; _k < n; _k++) \
                if ((cand).offset == out[_k].offset && (cand).length == out[_k].length) \
                    { _dup = 1; break; } \
            if (!_dup && n < ZXL_MAX_CANDIDATES) out[n++] = (cand); \
        } \
    } while (0)

    CHECK_AND_ADD(short_best);
    CHECK_AND_ADD(best_e1);
    CHECK_AND_ADD(best_e2);
    CHECK_AND_ADD(longest);
    CHECK_AND_ADD(short3);

    #undef CHECK_AND_ADD

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

    h = hash_short(p);
    ctx->short_next[slot] = ctx->short_ht[h];
    ctx->short_ht[h] = pos;
}
