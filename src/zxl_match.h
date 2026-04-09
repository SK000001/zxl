/*
 * ZXL - Match Engine
 *
 * Novel: three simultaneous hash chains for exact, XOR-delta, and
 * additive-delta matching. Binary data is full of sequences that are
 * "almost identical" (relocated addresses, counters, bit-shifted data)
 * that standard LZ engines completely miss.
 *
 *   Exact match:    out[i]  == ref[i]
 *   XOR-delta:      out[i]  == ref[i] ^ delta
 *   Add-delta:      out[i]  == (ref[i] + delta) & 0xFF
 *
 * Each hash table is a chained hash map: the head table maps hash →
 * most-recent position; the next array maps position → previous position
 * with the same hash (singly-linked list, newest first).
 * match_find walks up to ZXL_CHAIN_DEPTH entries per chain and keeps
 * the candidate with the best entropy-weighted savings.
 */
#ifndef ZXL_MATCH_H
#define ZXL_MATCH_H

#include <stdint.h>
#include <stddef.h>

#define ZXL_HASH_BITS   19
#define ZXL_HASH_SIZE   (1u << ZXL_HASH_BITS)   /* 512 K buckets         */
#define ZXL_HASH_MASK   (ZXL_HASH_SIZE - 1u)

#define ZXL_CHAIN_DEPTH 256         /* candidates checked per chain per match type */
#define ZXL_WINDOW      (1u << 21)  /* sliding window: 2 MB                       */

#define ZXL_MIN_MATCH   4
#define ZXL_MAX_MATCH   65535
#define ZXL_MAX_OFFSET  (1u << 21)   /* 2 MB lookback */

/* Match types */
#define MTYPE_EXACT  0
#define MTYPE_XOR    1
#define MTYPE_ADD    2

typedef struct {
    uint32_t offset;  /* distance back from current position */
    uint32_t length;  /* number of bytes matched             */
    uint8_t  mtype;   /* MTYPE_EXACT / MTYPE_XOR / MTYPE_ADD */
    uint8_t  delta;   /* XOR or additive constant             */
} Match;

/*
 * MatchCtx: three chained hash tables.
 *
 * Memory: 6 arrays × 64 K entries × 4 B = 1.5 MB  (was 12 MB with 1M slots)
 *
 * head[h]   = most-recent absolute position whose hash equals h,
 *             or 0xFFFFFFFF if the bucket is empty.
 * next[pos] = the position that was in head[h] when pos was inserted,
 *             forming a singly-linked chain; 0xFFFFFFFF = end-of-chain.
 */
typedef struct {
    uint32_t exact_ht  [ZXL_HASH_SIZE];
    uint32_t xdiff_ht  [ZXL_HASH_SIZE];
    uint32_t adiff_ht  [ZXL_HASH_SIZE];

    uint32_t exact_next[ZXL_WINDOW];
    uint32_t xdiff_next[ZXL_WINDOW];
    uint32_t adiff_next[ZXL_WINDOW];
} MatchCtx;

/*
 * Estimate bit savings from encoding a match of given length and type,
 * relative to encoding each byte as a literal (~9 bits each).
 * Returns a positive value when the match is worth emitting.
 */
/*
 * Overhead constants (bits): estimated real rANS cost of encoding one match
 * token + its parameters in the token stream.
 *   Exact: TOK_EXACT (rANS) + 3B offset + 2B length  ≈ 40 bits
 *   Delta: TOK_DELTA (rANS) + mtype + delta + 3B off + 2B len ≈ 56 bits
 * Using accurate overhead stops the parser from taking short matches that
 * cost more to encode than they save.
 */
#define ZXL_OVERHEAD_EXACT 24   /* match_find filter; DP uses per-block estimate */
#define ZXL_OVERHEAD_DELTA 32

static inline int32_t match_savings(uint32_t length, uint8_t mtype)
{
    int32_t overhead = (mtype == MTYPE_EXACT) ? ZXL_OVERHEAD_EXACT : ZXL_OVERHEAD_DELTA;
    return (int32_t)(length * 9u) - overhead;
}

void match_ctx_init(MatchCtx *ctx);

/*
 * Find up to 3 matches at src[pos]:
 *   out[0] = best-savings match (highest estimated bit savings)
 *   out[1] = shortest viable match (fewest bytes, if different from out[0])
 *   out[2] = best small-offset match (off<256 && lm<256, fits EXACT1/DELTA1)
 *            — only included when distinct from out[0] and out[1].
 * Returns 0 (none), 1, 2, or 3 (three distinct matches).
 * Having the shortest match lets the DP consider "short here → long after".
 * Having the best small-offset match lets the DP pick cheap EXACT1/DELTA1
 * even when the global best is a large-offset EXACT2/EXACT match.
 */
int match_find(MatchCtx *ctx,
               const uint8_t *src, size_t src_len,
               uint32_t pos, Match out[3]);

/* Insert position pos into all three chains. */
void match_update(MatchCtx *ctx, const uint8_t *src, uint32_t pos);

#endif /* ZXL_MATCH_H */
