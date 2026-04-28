/*
 * ZXL - Block Codec
 *
 * Block format (per 64 KB block):
 *
 *   [4]  uncompressed block size
 *   [4]  compressed token stream size  (0 = uncompressed fallback)
 *   [4]  compressed literal stream size
 *   [4]  decoded token stream length
 *   [4]  decoded literal stream length
 *   [256*2] rANS frequency table for tokens    (uint16_t[256])
 *   [256*2] rANS frequency table for literals  (uint16_t[256])
 *   [N]  compressed token stream (rANS)
 *   [M]  compressed literal stream (rANS)
 *
 * Token stream encodes the sequence of operations:
 *   0x00..0xFD  literal run length - 1  (up to 254 literals)
 *   0xFE        exact LZ match follows
 *   0xFF        delta match follows
 *
 * After an exact match token:
 *   [3] offset (24-bit little-endian)
 *   [2] length - ZXL_MIN_MATCH (16-bit little-endian)
 *
 * After a delta match token:
 *   [1] match type (MTYPE_XOR=1, MTYPE_ADD=2)
 *   [1] delta byte
 *   [3] offset (24-bit little-endian)
 *   [2] length - ZXL_MIN_MATCH (16-bit little-endian)
 *
 * File header:
 *   [4]  magic "ZXL1"
 *   [8]  original total size (uint64_t LE)
 *   then blocks follow until EOF
 */
#include "zxl.h"
#include "zxl_match.h"
#include "zxl_rans.h"
#include "zxl_ac.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#define ZXL_MAGIC      0x424C585Au   /* "ZXLB"  */
#define ZXL_BLOCK_SIZE (1u << 22)    /* 4 MB - amortizes per-block header overhead */

/*
 * Number of context-conditioned literal models.
 * Context = prev_output_byte >> (8 - N_LIT_CTX_BITS).
 * 8 contexts (3 bits) balances literal entropy reduction
 * vs. per-block freq-table header overhead.
 */
#define N_LIT_CTX       16
#define N_LIT_CTX_SHIFT 4    /* prev_byte >> 4 → 16 contexts (4-bit context) */

/* File-level flags stored in the 4-byte flags field of the header */
#define ZXL_FLAG_BCJ   0x01u  /* x86 BCJ (E8/E9) filter was applied */
#define ZXL_FLAG_BCJ64 0x02u  /* x64 RIP-relative BCJ filter was applied */
#define ZXL_FLAG_IAT   0x04u  /* C2 64-bit IAT delta filter was applied */

/*
 * Token byte values (ZXLC):
 *   0x00..0xF3  literal run (run = tok+1, max 244 bytes)
 *   0xF4        TOK_EXACT0:  [1] offset   (3-byte exact match, implicit length 3)
 *   0xF5        TOK_REP3:    [1] len-MIN_MATCH  (reuse 4th-last offset)
 *   0xF6        TOK_REP4:    [1] len-MIN_MATCH  (reuse 5th-last offset)
 *   0xF7        TOK_EXACT1:  [1] offset,         [1] len-MIN_MATCH
 *   0xF8        TOK_EXACT2:  [2] offset,          [1] len-MIN_MATCH
 *   0xF9        TOK_DELTA1:  [1]mtype,[1]delta,[1]offset,[1]len-MIN_MATCH
 *   0xFA        TOK_DELTA2:  [1]mtype,[1]delta,[2]offset,[1]len-MIN_MATCH
 *   0xFB        TOK_REP0:    [1] len-MIN_MATCH  (reuse last-used offset)
 *   0xFC        TOK_REP1:    [1] len-MIN_MATCH  (reuse 2nd-last offset)
 *   0xFD        TOK_REP2:    [1] len-MIN_MATCH  (reuse 3rd-last offset)
 *   0xFE        TOK_EXACT:   [3] offset,         [2] len-MIN_MATCH  (large off or long match)
 *   0xFF        TOK_DELTA:   [1]mtype,[1]delta,[3]offset,[2]len-MIN_MATCH
 *
 * Variable-length offset/length: EXACT0 is a dedicated 3-byte short match
 * (offset 1-255, implicit length 3, no length byte, no rep-cache update).
 * EXACT1/DELTA1 cover offsets 1-255 with len-4 0-255;
 * EXACT2/DELTA2 cover offsets 256-65535 with len-4 0-255.  TOK_EXACT/DELTA handle
 * anything larger (offset >= 65536 or len-4 >= 256).
 * REP uses 1-byte length (LRU-5 cache); if a REP match would need 2-byte length it
 * falls through to TOK_EXACT with the REP offset (still updates rep cache).
 */
#define TOK_EXACT0  0xF4u   /* 3-byte exact match, implicit len, 1-byte offset */
#define TOK_REP3    0xF5u
#define TOK_REP4    0xF6u
#define TOK_EXACT1  0xF7u
#define TOK_EXACT2  0xF8u
#define TOK_DELTA1  0xF9u
#define TOK_DELTA2  0xFAu
#define TOK_REP0    0xFBu
#define TOK_REP1    0xFCu
#define TOK_REP2    0xFDu
#define TOK_EXACT   0xFEu
#define TOK_DELTA   0xFFu
#define N_REP       5     /* LRU REP cache size */
#define MAX_LIT_RUN 244   /* max literal bytes per run token (token 0x00..0xF3) */

/* ------------------------------------------------------------------ */
/* D1: Compact rANS frequency-table codec (bitmap + varint)           */
/* ------------------------------------------------------------------ */
/*
 * Raw layout was 256 × u16 = 512 B / table. Freq tables are sparse
 * (many zero entries) and most nonzero values are small. Compact layout:
 *   [32 B] bitmap — bit i = 1 iff freq[i] != 0
 *   For each set bit, varint-encoded freq:
 *     f in [1,127]   → 1 byte: f (high bit 0)
 *     f in [128,16383] → 2 bytes: (0x80 | (f>>8)), (f & 0xFF)
 * RANS_SCALE is 16384 so freqs fit in 14 bits.
 * Worst case: 32 + 256*2 = 544 B (vs 512 raw). Typical: 100-250 B.
 */
#define ZXL_COMPACT_FREQ_MAX 544

static size_t write_compact_freqs(uint8_t *dst, const RansSym syms[256])
{
    uint8_t *p = dst;
    uint8_t *bitmap = p;
    memset(bitmap, 0, 32);
    p += 32;
    for (int i = 0; i < 256; i++) {
        uint16_t f = syms[i].freq;
        if (f == 0) continue;
        bitmap[i >> 3] |= (uint8_t)(1u << (i & 7));
        if (f < 128u) {
            *p++ = (uint8_t)f;
        } else {
            *p++ = (uint8_t)(0x80u | (f >> 8));
            *p++ = (uint8_t)(f & 0xFFu);
        }
    }
    return (size_t)(p - dst);
}

/* Returns bytes consumed, or 0 on error. Fills cnt[] with freqs. */
static size_t read_compact_freqs(const uint8_t *src, size_t avail, uint32_t cnt[256])
{
    if (avail < 32) return 0;
    const uint8_t *p = src;
    const uint8_t *bitmap = p;
    p += 32;
    const uint8_t *end = src + avail;
    for (int i = 0; i < 256; i++) {
        if ((bitmap[i >> 3] >> (i & 7)) & 1u) {
            if (p >= end) return 0;
            uint8_t b = *p++;
            uint32_t f;
            if ((b & 0x80u) == 0) {
                f = b;
            } else {
                if (p >= end) return 0;
                f = ((uint32_t)(b & 0x7Fu) << 8) | (uint32_t)(*p++);
            }
            cnt[i] = f;
        } else {
            cnt[i] = 0;
        }
    }
    return (size_t)(p - src);
}

/* ------------------------------------------------------------------ */
/* D1.5: Rank-1 factored freq-table codec                             */
/* ------------------------------------------------------------------ */
/*
 * Observation: a 256-bin byte-frequency distribution is often close to
 * separable in high-nibble × low-nibble coordinates. If freq[hi*16 + lo]
 * factors approximately as R[hi] * C[lo] / S, we only need to ship the
 * 16 row-marginals and 16 column-marginals (~32 bytes as varints)
 * instead of the full table (~100-250 bytes under D1-dense).
 *
 * This is a per-table choice. The encoder computes both the dense bit
 * cost and the rank-1 bit cost analytically from actual symbol counts,
 * plus the header sizes of each, and picks the smaller. A leading mode
 * byte per table (0 = dense, 1 = rank-1) tells the decoder which path
 * to follow.
 *
 * When rank-1 wins, the encoder's rANS model is built from the
 * *reconstructed* frequencies — not the original — so that what the
 * encoder used to compress matches what the decoder will reconstruct.
 * rank1_reconstruct() is deterministic and shared, so both sides agree.
 *
 * Worst case rank-1 header: 1 (mode) + 32 * 2 = 65 bytes.
 * Typical rank-1 header: 1 + 40 = 41 bytes.
 * Dense header ranges 1 + 100 to 1 + 250 bytes depending on sparsity.
 */
#define ZXL_FREQ_MODE_DENSE  0
#define ZXL_FREQ_MODE_RANK1  1
#define ZXL_RANK1_HDR_MAX    (1u + 32u * 2u)   /* mode byte + 32 varints worst case */

static inline size_t varint_write_u16(uint8_t *dst, uint32_t v)
{
    if (v < 128u) { dst[0] = (uint8_t)v; return 1; }
    dst[0] = (uint8_t)(0x80u | (v >> 8));
    dst[1] = (uint8_t)(v & 0xFFu);
    return 2;
}

static inline int varint_read_u16(const uint8_t **pp, const uint8_t *end, uint32_t *out)
{
    if (*pp >= end) return 0;
    uint8_t b = *(*pp)++;
    if ((b & 0x80u) == 0) { *out = b; return 1; }
    if (*pp >= end) return 0;
    *out = ((uint32_t)(b & 0x7Fu) << 8) | (uint32_t)(*(*pp)++);
    return 1;
}

/* Reconstruct 256-bin counts from row and col marginals under the
 * rank-1 outer-product assumption freq[hi*16+lo] = R[hi] * C[lo] / S
 * where S = sum(R) = sum(C). Renormalizes the result to exactly
 * RANS_SCALE via largest-remainder so rans_build_tables receives a
 * valid distribution. Deterministic: the encoder must call this with
 * the same row/col it will ship in the header, and the decoder calls
 * it with the values just parsed from the stream. */
static void rank1_reconstruct(const uint32_t row[16], const uint32_t col[16],
                               uint32_t cnt[256])
{
    uint32_t s = 0;
    for (int i = 0; i < 16; i++) s += row[i];
    if (s == 0) { for (int i = 0; i < 256; i++) cnt[i] = 0; return; }

    int64_t remainder[256];
    int64_t total = 0;
    for (int hi = 0; hi < 16; hi++) {
        for (int lo = 0; lo < 16; lo++) {
            int64_t prod = (int64_t)row[hi] * (int64_t)col[lo];
            uint32_t q = (uint32_t)(prod / s);
            cnt[hi * 16 + lo] = q;
            remainder[hi * 16 + lo] = prod - (int64_t)q * (int64_t)s;
            total += q;
        }
    }

    int32_t diff = (int32_t)RANS_SCALE - (int32_t)total;
    while (diff > 0) {
        int best = 0;
        int64_t best_r = remainder[0];
        for (int i = 1; i < 256; i++) if (remainder[i] > best_r) { best_r = remainder[i]; best = i; }
        cnt[best]++;
        remainder[best] = -1;
        diff--;
    }
    while (diff < 0) {
        int best = -1;
        int64_t best_r = (int64_t)1 << 62;
        for (int i = 0; i < 256; i++) {
            if (cnt[i] > 0 && remainder[i] < best_r) { best_r = remainder[i]; best = i; }
        }
        if (best < 0) break;
        cnt[best]--;
        remainder[best] = (int64_t)1 << 62;
        diff++;
    }
}

/* Given raw (possibly un-normalized) stream counts, decide whether the
 * dense or rank-1 format encodes fewer total bytes (header + bit cost),
 * run rans_build_tables with whichever counts will actually be encoded,
 * and populate row/col for the header writer. Returns the mode byte. */
static int build_freqs_auto(const uint32_t cnt[256],
                             RansSym syms[256], RansSlot slots[RANS_SCALE],
                             uint32_t row[16], uint32_t col[16])
{
    /* First build dense tables so we have normalized freqs (summing to
     * RANS_SCALE) to compute marginals against. */
    rans_build_tables(cnt, syms, slots);

    /* Row / col marginals from the normalized dense freqs. */
    for (int i = 0; i < 16; i++) { row[i] = 0; col[i] = 0; }
    for (int i = 0; i < 256; i++) {
        row[i >> 4] += syms[i].freq;
        col[i & 15] += syms[i].freq;
    }

    /* Reconstruct rank-1 counts. */
    uint32_t rcnt[256];
    rank1_reconstruct(row, col, rcnt);

    /* Analytical bit cost for each model using actual counts in the stream.
     * (The cost is the sum of -log2(p) weighted by count; the log2(RANS_SCALE)
     * constant cancels in the comparison but we include it for clarity.) */
    double dense_bits = 0.0, rank1_bits = 0.0;
    double scale_log = 14.0;  /* log2(RANS_SCALE) == log2(16384) */
    for (int i = 0; i < 256; i++) {
        if (cnt[i] == 0) continue;
        double d = (syms[i].freq > 0) ? (scale_log - log2((double)syms[i].freq))
                                       : 30.0;
        double r = (rcnt[i]       > 0) ? (scale_log - log2((double)rcnt[i]))
                                       : 30.0;
        dense_bits += (double)cnt[i] * d;
        rank1_bits += (double)cnt[i] * r;
    }

    /* Header sizes (excluding leading mode byte, which both pay equally). */
    size_t dense_hdr = 32;
    for (int i = 0; i < 256; i++) if (syms[i].freq > 0)
        dense_hdr += (syms[i].freq < 128u) ? 1u : 2u;
    size_t rank1_hdr = 0;
    for (int i = 0; i < 16; i++) rank1_hdr += (row[i] < 128u) ? 1u : 2u;
    for (int i = 0; i < 16; i++) rank1_hdr += (col[i] < 128u) ? 1u : 2u;

    double dense_total = dense_bits / 8.0 + (double)dense_hdr;
    double rank1_total = rank1_bits / 8.0 + (double)rank1_hdr;

    if (rank1_total + 1.0 < dense_total) {
        /* Rebuild tables using reconstructed counts — what the decoder will
         * also use after reading row/col from the header. */
        rans_build_tables(rcnt, syms, slots);
        return ZXL_FREQ_MODE_RANK1;
    }
    return ZXL_FREQ_MODE_DENSE;
}

/* Write one freq table in the chosen mode. Emits [mode byte][payload]. */
static size_t write_freqs_tagged(uint8_t *dst, int mode,
                                  const RansSym syms[256],
                                  const uint32_t row[16], const uint32_t col[16])
{
    uint8_t *p = dst;
    *p++ = (uint8_t)mode;
    if (mode == ZXL_FREQ_MODE_RANK1) {
        for (int i = 0; i < 16; i++) p += varint_write_u16(p, row[i]);
        for (int i = 0; i < 16; i++) p += varint_write_u16(p, col[i]);
    } else {
        p += write_compact_freqs(p, syms);
    }
    return (size_t)(p - dst);
}

/* Decode one freq table. Reads [mode byte][payload], fills cnt[]. */
static size_t read_freqs_tagged(const uint8_t *src, size_t avail, uint32_t cnt[256])
{
    if (avail < 1) return 0;
    const uint8_t *p = src;
    const uint8_t *end = src + avail;
    uint8_t mode = *p++;
    if (mode == ZXL_FREQ_MODE_RANK1) {
        uint32_t row[16], col[16];
        for (int i = 0; i < 16; i++) if (!varint_read_u16(&p, end, &row[i])) return 0;
        for (int i = 0; i < 16; i++) if (!varint_read_u16(&p, end, &col[i])) return 0;
        rank1_reconstruct(row, col, cnt);
        return (size_t)(p - src);
    }
    if (mode == ZXL_FREQ_MODE_DENSE) {
        size_t consumed = read_compact_freqs(p, (size_t)(end - p), cnt);
        if (consumed == 0) return 0;
        return 1u + consumed;
    }
    return 0;  /* unknown mode */
}

/* ------------------------------------------------------------------ */
/* x64 RIP-relative BCJ filter                                        */
/* ------------------------------------------------------------------ */

/*
 * x64 RIP-relative filter: convert RIP-relative displacements to absolute.
 *
 * In 64-bit code, data references use RIP-relative addressing:
 *   MOV reg, [RIP+disp32]  /  LEA reg, [RIP+disp32]  /  CMP [RIP+disp32], imm
 *
 * The key is the ModRM byte: when (modrm & 0xC7) == 0x05, the instruction
 * uses [RIP+disp32] addressing. The disp32 starts right after the ModRM byte
 * (possibly after a SIB byte, but RIP-relative never has SIB).
 *
 * We handle the most common patterns:
 *   1. REX.W (0x48..0x4F) + opcode + ModRM  (2-byte prefix before disp32)
 *      Opcodes: 0x8B (MOV r,m), 0x8D (LEA r,m), 0x89 (MOV m,r), 0x3B (CMP r,m),
 *               0x39 (CMP m,r), 0x03 (ADD r,m), 0x01 (ADD m,r), 0x2B (SUB r,m),
 *               0x33 (XOR r,m), 0x31 (XOR m,r), 0x0B (OR r,m), 0x23 (AND r,m),
 *               0x85 (TEST r,m), 0x63 (MOVSXD r,m)
 *   2. Non-REX: opcode + ModRM with (modrm & 0xC7)==0x05
 *      Same opcodes without REX prefix (32-bit operand size in 64-bit mode)
 *   3. 0x0F + 2-byte opcode + ModRM: SSE/AVX instructions
 *      0x0F 0x10/0x11 (MOVUPS), 0x0F 0x28/0x29 (MOVAPS),
 *      0x0F 0x6F/0x7F (MOVDQA/MOVDQU with 66 prefix)
 *
 * The disp32 is at offset [prefix_len + 1(opcode) + 1(modrm)] from start,
 * or [prefix_len + 2(opcode) + 1(modrm)] for 0F-prefixed opcodes.
 * IP points to the next instruction = pos + total_insn_len.
 */

/* Check if a byte is a common opcode that uses ModRM with memory operand */
static inline int is_rip_opcode(uint8_t op)
{
    switch (op) {
        case 0x8B: case 0x8D: case 0x89: case 0x3B: case 0x39:
        case 0x03: case 0x01: case 0x2B: case 0x33: case 0x31:
        case 0x0B: case 0x23: case 0x85: case 0x63:
        case 0x29: /* SUB m,r */
        case 0x83: /* immediate group: CMP/ADD/SUB [rip+disp32], imm8 */
        case 0xC7: /* MOV [rip+disp32], imm32 */
        case 0xF7: /* TEST/NOT/NEG/MUL/DIV [rip+disp32] */
            return 1;
        default: return 0;
    }
}

static void bcj_x64_forward(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i + 7 <= len; ) {
        uint8_t b0 = buf[i];
        int has_rex = (b0 >= 0x40 && b0 <= 0x4F);  /* any REX prefix */
        int has_66  = (b0 == 0x66);                 /* operand size override */
        int prefix_len = (has_rex || has_66) ? 1 : 0;
        size_t op_pos = i + prefix_len;

        if (op_pos + 6 > len) { i++; continue; }

        uint8_t op = buf[op_pos];

        /* Case 1: regular opcode + ModRM */
        if (is_rip_opcode(op)) {
            uint8_t modrm = buf[op_pos + 1];
            if ((modrm & 0xC7) == 0x05) {
                /* disp32 starts at op_pos + 2 */
                size_t disp_pos = op_pos + 2;
                /* Determine instruction length to compute RIP value.
                 * For most opcodes: insn = prefix + opcode(1) + modrm(1) + disp32(4) = prefix+6
                 * For 0x83: + imm8 = prefix+7
                 * For 0xC7: + imm32 = prefix+10 (but we only need next-IP for the transform)
                 * For 0xF7: depends on reg field, but commonly +imm32 for TEST */
                uint32_t next_ip;
                if (op == 0x83) {
                    if (disp_pos + 5 > len) { i++; continue; }
                    next_ip = (uint32_t)(disp_pos + 5); /* disp32 + imm8 */
                } else if (op == 0xC7) {
                    if (disp_pos + 8 > len) { i++; continue; }
                    next_ip = (uint32_t)(disp_pos + 8); /* disp32 + imm32 */
                } else {
                    if (disp_pos + 4 > len) { i++; continue; }
                    next_ip = (uint32_t)(disp_pos + 4); /* disp32 only */
                }
                uint32_t rel = (uint32_t)buf[disp_pos]
                             | ((uint32_t)buf[disp_pos+1] << 8)
                             | ((uint32_t)buf[disp_pos+2] << 16)
                             | ((uint32_t)buf[disp_pos+3] << 24);
                uint32_t abs_addr = rel + next_ip;
                buf[disp_pos]   = (uint8_t)(abs_addr);
                buf[disp_pos+1] = (uint8_t)(abs_addr >> 8);
                buf[disp_pos+2] = (uint8_t)(abs_addr >> 16);
                buf[disp_pos+3] = (uint8_t)(abs_addr >> 24);
                i = disp_pos + 4; /* skip past disp32 */
                continue;
            }
        }

        /* Case 2: 0F-prefixed opcodes (SSE/conditional moves) */
        if (op == 0x0F && op_pos + 7 <= len) {
            uint8_t op2 = buf[op_pos + 1];
            /* MOVUPS/MOVAPS/MOVDQA and similar SSE with memory operand */
            int is_sse_mem = (op2 == 0x10 || op2 == 0x11 ||  /* MOVUPS */
                              op2 == 0x28 || op2 == 0x29 ||  /* MOVAPS */
                              op2 == 0x6F || op2 == 0x7F ||  /* MOVDQ* */
                              op2 == 0x6E || op2 == 0x7E ||  /* MOVD/MOVQ */
                              op2 == 0x2E || op2 == 0x2F ||  /* UCOMISD/COMISD */
                              op2 == 0xB6 || op2 == 0xB7 ||  /* MOVZX */
                              op2 == 0xBE || op2 == 0xBF ||  /* MOVSX */
                              (op2 >= 0x40 && op2 <= 0x4F)); /* CMOVcc */
            if (is_sse_mem) {
                uint8_t modrm = buf[op_pos + 2];
                if ((modrm & 0xC7) == 0x05) {
                    size_t disp_pos = op_pos + 3;
                    if (disp_pos + 4 > len) { i++; continue; }
                    uint32_t next_ip = (uint32_t)(disp_pos + 4);
                    uint32_t rel = (uint32_t)buf[disp_pos]
                                 | ((uint32_t)buf[disp_pos+1] << 8)
                                 | ((uint32_t)buf[disp_pos+2] << 16)
                                 | ((uint32_t)buf[disp_pos+3] << 24);
                    uint32_t abs_addr = rel + next_ip;
                    buf[disp_pos]   = (uint8_t)(abs_addr);
                    buf[disp_pos+1] = (uint8_t)(abs_addr >> 8);
                    buf[disp_pos+2] = (uint8_t)(abs_addr >> 16);
                    buf[disp_pos+3] = (uint8_t)(abs_addr >> 24);
                    i = disp_pos + 4;
                    continue;
                }
            }
        }

        i++;
    }
}

static void bcj_x64_inverse(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i + 7 <= len; ) {
        uint8_t b0 = buf[i];
        int has_rex = (b0 >= 0x40 && b0 <= 0x4F);
        int has_66  = (b0 == 0x66);
        int prefix_len = (has_rex || has_66) ? 1 : 0;
        size_t op_pos = i + prefix_len;

        if (op_pos + 6 > len) { i++; continue; }

        uint8_t op = buf[op_pos];

        if (is_rip_opcode(op)) {
            uint8_t modrm = buf[op_pos + 1];
            if ((modrm & 0xC7) == 0x05) {
                size_t disp_pos = op_pos + 2;
                uint32_t next_ip;
                if (op == 0x83) {
                    if (disp_pos + 5 > len) { i++; continue; }
                    next_ip = (uint32_t)(disp_pos + 5);
                } else if (op == 0xC7) {
                    if (disp_pos + 8 > len) { i++; continue; }
                    next_ip = (uint32_t)(disp_pos + 8);
                } else {
                    if (disp_pos + 4 > len) { i++; continue; }
                    next_ip = (uint32_t)(disp_pos + 4);
                }
                uint32_t abs_addr = (uint32_t)buf[disp_pos]
                                  | ((uint32_t)buf[disp_pos+1] << 8)
                                  | ((uint32_t)buf[disp_pos+2] << 16)
                                  | ((uint32_t)buf[disp_pos+3] << 24);
                uint32_t rel = abs_addr - next_ip;
                buf[disp_pos]   = (uint8_t)(rel);
                buf[disp_pos+1] = (uint8_t)(rel >> 8);
                buf[disp_pos+2] = (uint8_t)(rel >> 16);
                buf[disp_pos+3] = (uint8_t)(rel >> 24);
                i = disp_pos + 4;
                continue;
            }
        }

        if (op == 0x0F && op_pos + 7 <= len) {
            uint8_t op2 = buf[op_pos + 1];
            int is_sse_mem = (op2 == 0x10 || op2 == 0x11 ||
                              op2 == 0x28 || op2 == 0x29 ||
                              op2 == 0x6F || op2 == 0x7F ||
                              op2 == 0x6E || op2 == 0x7E ||
                              op2 == 0x2E || op2 == 0x2F ||
                              op2 == 0xB6 || op2 == 0xB7 ||
                              op2 == 0xBE || op2 == 0xBF ||
                              (op2 >= 0x40 && op2 <= 0x4F));
            if (is_sse_mem) {
                uint8_t modrm = buf[op_pos + 2];
                if ((modrm & 0xC7) == 0x05) {
                    size_t disp_pos = op_pos + 3;
                    if (disp_pos + 4 > len) { i++; continue; }
                    uint32_t next_ip = (uint32_t)(disp_pos + 4);
                    uint32_t abs_addr = (uint32_t)buf[disp_pos]
                                      | ((uint32_t)buf[disp_pos+1] << 8)
                                      | ((uint32_t)buf[disp_pos+2] << 16)
                                      | ((uint32_t)buf[disp_pos+3] << 24);
                    uint32_t rel = abs_addr - next_ip;
                    buf[disp_pos]   = (uint8_t)(rel);
                    buf[disp_pos+1] = (uint8_t)(rel >> 8);
                    buf[disp_pos+2] = (uint8_t)(rel >> 16);
                    buf[disp_pos+3] = (uint8_t)(rel >> 24);
                    i = disp_pos + 4;
                    continue;
                }
            }
        }

        i++;
    }
}

/* ------------------------------------------------------------------ */
/* BCJ (Branch Conversion Jump) x86 filter                           */
/* ------------------------------------------------------------------ */

/*
 * BCJ forward transform: convert E8/E9 (CALL/JMP rel32) relative addresses
 * to absolute.  All call sites to the same function now share identical
 * 4-byte absolute addresses, giving the LZ matcher many more exact hits.
 *
 * The transform skips the 4 address bytes after each opcode so accidental
 * E8/E9 values inside parameter bytes are never treated as opcodes —
 * making the forward and inverse perfectly symmetric.
 */
static void bcj_x86_forward(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i + 5 <= len; i++) {
        if (buf[i] == 0xE8u || buf[i] == 0xE9u) {
            /* CALL rel32 / JMP rel32: 1-byte opcode + 4-byte offset */
            uint32_t rel = (uint32_t) buf[i+1]
                         | ((uint32_t)buf[i+2] <<  8)
                         | ((uint32_t)buf[i+3] << 16)
                         | ((uint32_t)buf[i+4] << 24);
            uint32_t abs_addr = rel + (uint32_t)(i + 5);
            buf[i+1] = (uint8_t) abs_addr;
            buf[i+2] = (uint8_t)(abs_addr >>  8);
            buf[i+3] = (uint8_t)(abs_addr >> 16);
            buf[i+4] = (uint8_t)(abs_addr >> 24);
            i += 4;
        } else if (buf[i] == 0x0Fu && i + 6 <= len &&
                   (buf[i+1] & 0xF0u) == 0x80u) {
            /* Jcc near (0F 80..8F): 2-byte opcode + 4-byte offset */
            uint32_t rel = (uint32_t) buf[i+2]
                         | ((uint32_t)buf[i+3] <<  8)
                         | ((uint32_t)buf[i+4] << 16)
                         | ((uint32_t)buf[i+5] << 24);
            uint32_t abs_addr = rel + (uint32_t)(i + 6);
            buf[i+2] = (uint8_t) abs_addr;
            buf[i+3] = (uint8_t)(abs_addr >>  8);
            buf[i+4] = (uint8_t)(abs_addr >> 16);
            buf[i+5] = (uint8_t)(abs_addr >> 24);
            i += 5;
        }
    }
}

static void bcj_x86_inverse(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i + 5 <= len; i++) {
        if (buf[i] == 0xE8u || buf[i] == 0xE9u) {
            uint32_t abs_addr = (uint32_t) buf[i+1]
                              | ((uint32_t)buf[i+2] <<  8)
                              | ((uint32_t)buf[i+3] << 16)
                              | ((uint32_t)buf[i+4] << 24);
            uint32_t rel = abs_addr - (uint32_t)(i + 5);
            buf[i+1] = (uint8_t) rel;
            buf[i+2] = (uint8_t)(rel >>  8);
            buf[i+3] = (uint8_t)(rel >> 16);
            buf[i+4] = (uint8_t)(rel >> 24);
            i += 4;
        } else if (buf[i] == 0x0Fu && i + 6 <= len &&
                   (buf[i+1] & 0xF0u) == 0x80u) {
            uint32_t abs_addr = (uint32_t) buf[i+2]
                              | ((uint32_t)buf[i+3] <<  8)
                              | ((uint32_t)buf[i+4] << 16)
                              | ((uint32_t)buf[i+5] << 24);
            uint32_t rel = abs_addr - (uint32_t)(i + 6);
            buf[i+2] = (uint8_t) rel;
            buf[i+3] = (uint8_t)(rel >>  8);
            buf[i+4] = (uint8_t)(rel >> 16);
            buf[i+5] = (uint8_t)(rel >> 24);
            i += 5;
        }
    }
}

/* ------------------------------------------------------------------ */
/* C2: 64-bit IAT delta filter                                        */
/* ------------------------------------------------------------------ */
/*
 * 64-bit PE import/jump tables and vtables are long runs of 8-byte
 * absolute pointers clustered in a narrow address range (same DLL or
 * same module), so most entries share the top 5+ bytes and only the
 * low bytes vary.
 *
 * Detection is self-consistent: we match 8-byte-aligned entries where
 * the top 3 bytes look like a user-mode 64-bit pointer
 * (byte[7] == 0 && byte[6] == 0 && byte[5] <= 0x7F). This pattern is
 * preserved by XOR of two values both in the same pattern (0^0 = 0,
 * and [0..0x7F] XOR [0..0x7F] stays in [0..0x7F]), so the encoder can
 * scan original data and the decoder can scan the same run boundaries
 * on the transformed data without a side-channel flag.
 *
 * Transform: XOR only the low 5 bytes (indices 0..4). Top 3 bytes
 * (indices 5..7) are untouched, preserving the detection signature.
 *
 * The stricter 3-byte pattern sharply reduces false positives over a
 * bare byte[7]==0 check, which collided with BCJ-transformed absolute
 * addresses whose 4-byte result frequently has byte[7]==0 at random
 * 8-byte boundaries.
 *
 * Encode XORs right-to-left (referencing still-original neighbors);
 * decode XORs left-to-right (each predecessor has already been
 * restored when used).
 */
#define IAT_RUN_MIN 80
#define IAT_MATCH(p) ((p)[7] == 0 && (p)[6] == 0 && (p)[5] <= 0x7Fu)

static void iat_filter_scan(uint8_t *buf, size_t len, int encode)
{
    size_t i = 0;
    while (i + 8 <= len) {
        if (!IAT_MATCH(buf + i)) { i += 8; continue; }
        size_t run_start = i;
        size_t run_count = 0;
        while (i + 8 <= len && IAT_MATCH(buf + i)) { run_count++; i += 8; }
        if (run_count < IAT_RUN_MIN) continue;

        if (encode) {
            for (size_t j = run_count - 1; j >= 1; j--) {
                uint8_t *a = buf + run_start + j * 8;
                const uint8_t *b = a - 8;
                a[0] ^= b[0]; a[1] ^= b[1]; a[2] ^= b[2]; a[3] ^= b[3]; a[4] ^= b[4];
            }
        } else {
            for (size_t j = 1; j < run_count; j++) {
                uint8_t *a = buf + run_start + j * 8;
                const uint8_t *b = a - 8;
                a[0] ^= b[0]; a[1] ^= b[1]; a[2] ^= b[2]; a[3] ^= b[3]; a[4] ^= b[4];
            }
        }
    }
}

static inline void iat_forward(uint8_t *buf, size_t len) { iat_filter_scan(buf, len, 1); }
static inline void iat_inverse(uint8_t *buf, size_t len) { iat_filter_scan(buf, len, 0); }

/* ------------------------------------------------------------------ */
/* B5: PE section-boundary block splits                               */
/* ------------------------------------------------------------------ */
/*
 * Parse a 64-bit PE file's section table and return the set of file
 * offsets at which each section's raw data begins. The compressor then
 * forces a block split at each returned offset (subject to a minimum
 * block-size guard) so each block's rANS freq tables specialize to one
 * section's byte statistics (.text vs .rdata vs .data vs .rsrc, ...)
 * rather than averaging across mismatched regimes.
 *
 * The function is tolerant of malformed PE data: any out-of-range read
 * or nonsensical field size causes it to return 0 splits, leaving the
 * compressor on its fixed-block-size path. Non-PE input (no "MZ" at
 * offset 0) trivially returns 0.
 *
 * Returns number of splits written to out[] (0..max_splits). Splits
 * are sorted ascending, deduplicated, and always strictly within
 * (0, src_len).
 */
static size_t pe_section_splits(const uint8_t *src, size_t src_len,
                                size_t *out, size_t max_splits)
{
    if (src_len < 0x40u) return 0;
    if (src[0] != 0x4Du || src[1] != 0x5Au) return 0;  /* no "MZ" */

    /* e_lfanew at offset 0x3C */
    uint32_t pe_off = (uint32_t)src[0x3C]
                    | ((uint32_t)src[0x3D] << 8)
                    | ((uint32_t)src[0x3E] << 16)
                    | ((uint32_t)src[0x3F] << 24);
    if ((size_t)pe_off + 24u > src_len) return 0;
    if (src[pe_off] != 'P' || src[pe_off+1] != 'E'
        || src[pe_off+2] != 0 || src[pe_off+3] != 0) return 0;

    const uint8_t *coff = src + pe_off + 4;         /* COFF file header */
    uint16_t n_sections = (uint16_t)coff[2] | ((uint16_t)coff[3] << 8);
    uint16_t opt_size   = (uint16_t)coff[16] | ((uint16_t)coff[17] << 8);
    if (n_sections == 0 || n_sections > 96) return 0;  /* sanity */

    size_t sec_off = (size_t)pe_off + 4u + 20u + (size_t)opt_size;
    if (sec_off + (size_t)n_sections * 40u > src_len) return 0;

    size_t count = 0;
    for (uint16_t i = 0; i < n_sections && count < max_splits; i++) {
        const uint8_t *hdr = src + sec_off + (size_t)i * 40u;
        /* PointerToRawData at offset 20 inside section header (little-endian u32) */
        uint32_t raw_ptr = (uint32_t)hdr[20]
                         | ((uint32_t)hdr[21] << 8)
                         | ((uint32_t)hdr[22] << 16)
                         | ((uint32_t)hdr[23] << 24);
        if (raw_ptr == 0 || (size_t)raw_ptr >= src_len) continue;  /* skip BSS-like */
        out[count++] = (size_t)raw_ptr;
    }

    /* Insertion sort (n_sections is small, <= 96). */
    for (size_t i = 1; i < count; i++) {
        size_t v = out[i];
        size_t j = i;
        while (j > 0 && out[j-1] > v) { out[j] = out[j-1]; j--; }
        out[j] = v;
    }
    /* Dedup in place. */
    size_t w = 0;
    for (size_t i = 0; i < count; i++) {
        if (w == 0 || out[w-1] != out[i]) out[w++] = out[i];
    }
    return w;
}

/* ------------------------------------------------------------------ */
/* Helpers: little-endian I/O                                         */
/* ------------------------------------------------------------------ */

static inline void write_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
}
static inline void write_u24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v>>8); p[2] = (uint8_t)(v>>16);
}
static inline void write_u32(uint8_t *p, uint32_t v)
{
    p[0]=(uint8_t)(v); p[1]=(uint8_t)(v>>8);
    p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static inline void write_u64(uint8_t *p, uint64_t v)
{
    for (int i=0;i<8;i++,v>>=8) p[i]=(uint8_t)v;
}
static inline uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1]<<8);
}
static inline uint32_t read_u24(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16);
}
static inline uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|
           ((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static inline uint64_t read_u64(const uint8_t *p)
{
    uint64_t v=0; for(int i=7;i>=0;i--) v=(v<<8)|p[i]; return v;
}

/* ------------------------------------------------------------------ */
/* Public: bound                                                       */
/* ------------------------------------------------------------------ */

size_t zxl_bound(size_t src_len)
{
    /* Worst case: incompressible → slight expansion from headers */
    return src_len + (src_len / 8) + 256 + 64;
}

/* ------------------------------------------------------------------ */
/* Block compress                                                      */
/* ------------------------------------------------------------------ */

/*
 * Compress src[block_start..block_end) into dst using the persistent ctx.
 * Positions passed to match_find/match_update are absolute (relative to
 * src[0]), so the 1 MB sliding window spans across block boundaries.
 * Match lengths are capped at block_end so tokens stay within this block.
 * Returns bytes written into dst, or 0 on failure.
 */
/* Context-weighted opcode entropy cost for the 2-context opcode model.
 * Contexts: am=after-match (REP/exact/delta), al=after-literal.
 * cost(T) = P(am|T)*(-log2(P(T|am))) + P(al|T)*(-log2(P(T|al)))
 * ftok = grand total tokens (fallback when token unseen in all contexts). */
static float _ovhd_ctx(float cam, float cal, float ftok_am, float ftok_al, float ftok)
{
    float tot = cam + cal;
    float c = 0.0f;
    if (cam > 0.0f && ftok_am > 0.0f) c += (cam / tot) * (-log2f(cam / ftok_am));
    if (cal > 0.0f && ftok_al > 0.0f) c += (cal / tot) * (-log2f(cal / ftok_al));
    return (tot > 0.0f) ? c : -log2f(1.0f / ftok);
}

static size_t compress_block(MatchCtx *ctx,
                              const uint8_t *src,
                              size_t block_start, size_t block_end,
                              uint8_t *dst, size_t dst_cap)
{
    size_t block_len = block_end - block_start;

    /* Temporary buffers:
     *   opcode_buf  — one byte per LZ/literal event (token opcodes only)
     *   param_buf   — offset/mtype/delta bytes for each match
     *   lbuf        — length bytes (lm fields) for each match, separate stream
     *   lit_buf     — literal payload bytes
     *   lit_ctx_buf — N_LIT_CTX-context tag per literal
     *
     * param_buf and lbuf are kept separate because length values (lm = length-4,
     * typically 0–20) have very different entropy from offset/delta bytes.
     * Coding them independently allows each rANS model to fit its own distribution.
     */
    uint8_t *opcode_buf  = (uint8_t *)malloc(block_len + 64);
    uint8_t *off_lo_buf  = (uint8_t *)malloc(block_len + 64);    /* offset low bytes  */
    uint8_t *off_hi_buf  = (uint8_t *)malloc(block_len * 2 + 64); /* offset high+top bytes */
    uint8_t *delta_buf   = (uint8_t *)malloc(block_len * 2 + 64);  /* mtype+delta bytes only */
    uint8_t *lbuf        = (uint8_t *)malloc(block_len + 64);
    uint8_t *lit_buf     = (uint8_t *)malloc(block_len + 64);
    uint8_t *lit_ctx_buf = (uint8_t *)malloc(block_len + 8);
    if (!opcode_buf || !off_lo_buf || !off_hi_buf || !delta_buf || !lbuf || !lit_buf || !lit_ctx_buf) {
        free(opcode_buf); free(off_lo_buf); free(off_hi_buf); free(delta_buf); free(lbuf); free(lit_buf); free(lit_ctx_buf); return 0;
    }

    /* Build per-symbol entropy cost table and cumulative prefix sum.
     * sym_cost[b] = -log2(freq[b]/total) bits for one occurrence of byte b.
     * cum_cost[i] = sum of sym_cost for src[block_start .. block_start+i).
     * Cost of src[block_start+a .. block_start+a+len) = cum_cost[a+len] - cum_cost[a].
     * This gives the lazy comparator a real entropy estimate instead of 9 bits/byte. */
    uint32_t blk_freq[256] = {0};
    for (size_t _i = block_start; _i < block_end; _i++) blk_freq[src[_i]]++;
    float sym_cost[256];
    {
        float ftotal = 0.0f;
        for (int _i = 0; _i < 256; _i++) ftotal += (float)(blk_freq[_i] ? blk_freq[_i] : 1u);
        for (int _i = 0; _i < 256; _i++) {
            uint32_t f = blk_freq[_i] ? blk_freq[_i] : 1u;
            sym_cost[_i] = -log2f((float)f / ftotal);
        }
    }
    size_t opcode_len  = 0;  /* bytes written to opcode_buf */
    size_t off_lo_len  = 0;  /* low bytes of offsets  */
    size_t off_hi_len  = 0;  /* high+top bytes of offsets */
    size_t delta_len  = 0;  /* bytes written to delta_buf (mtype + delta bytes only) */
    size_t lbuf_size  = 0;  /* bytes written to lbuf (match length bytes) */
    size_t lit_len = 0;

    uint32_t end_pos = (uint32_t)block_end;
    uint32_t lit_run = 0;  /* pending literal count */

    /* Flush pending literals as a token + raw bytes.
     * Max run = 244 (token 0xF3); tokens 0xF4..0xFF are reserved for
     * EXACT0/REP3/REP4/EXACT1/EXACT2/DELTA1/DELTA2/REP0/REP1/REP2/EXACT/DELTA.
     * Literal run tokens are opcodes only — no params. */
    #define FLUSH_LITS() do { \
        while (lit_run > 0) { \
            uint32_t run = lit_run < MAX_LIT_RUN ? lit_run : MAX_LIT_RUN; \
            opcode_buf[opcode_len++] = (uint8_t)(run - 1); \
            lit_run -= run; \
        } \
    } while(0)

    /*
     * Optimal parse via dynamic programming.
     *
     * Forward pass: insert every position into all three hash tables and
     * record the best match found (if any).  Inserting every position —
     * rather than skipping interiors of matches — keeps the hash tables
     * accurate for the next block's cross-block back-references.
     *
     * DP backward pass: dp[i] = minimum bit cost to encode
     *   src[block_start+i .. block_end).
     *   Literal option:  dp[i] = sym_cost[src[i]] + dp[i+1]
     *   Match option:    dp[i] = overhead           + dp[i+len]
     *
     * Forward trace: walk from i=0, emitting the DP-chosen parse.
     */
    /* match_all: flat array of ZXL_MAX_CANDIDATES matches per position.
     * match_all[i * ZXL_MAX_CANDIDATES + c] = candidate c at position i. */
    Match   *match_all  = (Match *)   malloc(block_len * ZXL_MAX_CANDIDATES * sizeof(Match));
    Match   *rep_match  = (Match *)   calloc(block_len,  sizeof(Match));
    uint8_t *found_arr  = (uint8_t *) malloc(block_len);
    float    *dp         = (float *)   malloc((block_len + 1) * sizeof(float));
    uint8_t  *choice     = (uint8_t *) malloc(block_len);
    uint32_t *choice_len = (uint32_t *)malloc(block_len * sizeof(uint32_t));

    if (!match_all || !rep_match || !found_arr || !dp || !choice || !choice_len) {
        free(match_all); free(rep_match);
        free(found_arr); free(dp); free(choice); free(choice_len);
        free(opcode_buf); free(off_lo_buf); free(off_hi_buf); free(delta_buf); free(lbuf); free(lit_buf); free(lit_ctx_buf);
        return 0;
    }

    /* Forward pass: find up to ZXL_MAX_CANDIDATES matches per position.
     * We update the 4-byte chains only when 4 bytes remain; short 3-byte
     * chain can be updated/searched whenever 3 bytes remain. */
    for (uint32_t i = 0; i < (uint32_t)block_len; i++) {
        uint32_t p = (uint32_t)block_start + i;
        if (p + ZXL_MIN_MATCH <= end_pos) {
            match_update(ctx, src, (size_t)end_pos, p);
            Match tmp[ZXL_MAX_CANDIDATES];
            int n = match_find(ctx, src, (size_t)end_pos, p, tmp);

            /* B1: binary-tree find + insert. Walks the per-hash-bucket
             * suffix tree and returns the best-length exact match on the
             * descent path. Added as an extra candidate only if it beats
             * every match the hash chains found. */
            uint32_t bt_off = 0, bt_len = 0;
            if (bt_insert_and_find(ctx, src, (size_t)end_pos, p, &bt_off, &bt_len)) {
                uint32_t best_chain_len = 0;
                int      weakest_idx    = 0;
                uint32_t weakest_len    = 0xFFFFFFFFu;
                for (int c = 0; c < n; c++) {
                    if (tmp[c].length > best_chain_len) best_chain_len = tmp[c].length;
                    if (tmp[c].length < weakest_len) { weakest_len = tmp[c].length; weakest_idx = c; }
                }
                if (bt_len > best_chain_len) {
                    if (n < ZXL_MAX_CANDIDATES) {
                        tmp[n].offset = bt_off; tmp[n].length = bt_len;
                        tmp[n].mtype  = MTYPE_EXACT; tmp[n].delta = 0;
                        n++;
                    } else {
                        tmp[weakest_idx].offset = bt_off; tmp[weakest_idx].length = bt_len;
                        tmp[weakest_idx].mtype  = MTYPE_EXACT; tmp[weakest_idx].delta = 0;
                    }
                }
            }

            found_arr[i] = (uint8_t)n;
            for (int c = 0; c < n; c++)
                match_all[i * ZXL_MAX_CANDIDATES + c] = tmp[c];
        } else {
            found_arr[i] = 0;
        }
    }

    /*
     * Greedy REP pre-pass: forward simulation to estimate the rep[3] LRU
     * cache state at each position.  The DP doesn't track rep[] state, so
     * this gives it a per-position "is a REP match available here, and how
     * long?" answer.  Stored in rep_match[i] (length==0 → not REP-eligible).
     *
     * We advance greedily (take best match if savings > 0, else literal) to
     * keep rep[] reasonably accurate.  The DP's actual choices may diverge,
     * so the forward trace re-checks rep[] and falls back to EXACT if needed.
     */
    {
        uint32_t rep[5] = {0u, 0u, 0u, 0u, 0u};
        uint32_t i = 0;
        while (i < (uint32_t)block_len) {
            /* Check all candidates for a REP-eligible match at this position */
            for (int c = 0; c < (int)found_arr[i]; c++) {
                Match *m = &match_all[i * ZXL_MAX_CANDIDATES + c];
                if (m->mtype == MTYPE_EXACT && m->length - ZXL_MIN_MATCH < 256u) {
                    int ri = (m->offset == rep[0]) ? 0 :
                             (m->offset == rep[1]) ? 1 :
                             (m->offset == rep[2]) ? 2 :
                             (m->offset == rep[3]) ? 3 :
                             (m->offset == rep[4]) ? 4 : -1;
                    if (ri >= 0) {
                        if (m->length > rep_match[i].length)
                            rep_match[i] = *m;
                    }
                }
            }
            /* Advance: greedy — take best match if it saves bits, else literal */
            if (found_arr[i] >= 1 &&
                match_savings(match_all[i * ZXL_MAX_CANDIDATES].length,
                              match_all[i * ZXL_MAX_CANDIDATES].mtype) > 0) {
                Match *m = &match_all[i * ZXL_MAX_CANDIDATES];
                if (m->mtype == MTYPE_EXACT) {
                    int ri = (m->offset == rep[0]) ? 0 :
                             (m->offset == rep[1]) ? 1 :
                             (m->offset == rep[2]) ? 2 :
                             (m->offset == rep[3]) ? 3 :
                             (m->offset == rep[4]) ? 4 : -1;
                    if (ri > 0) {
                        uint32_t tmp = rep[ri];
                        for (int k = ri; k > 0; k--) rep[k] = rep[k-1];
                        rep[0] = tmp;
                    } else if (ri < 0) {
                        rep[4] = rep[3]; rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = m->offset;
                    }
                }
                i += m->length;
            } else {
                i++;
            }
        }
    }

    /*
     * Two-pass optimal parse:
     *
     * Pass 1 uses rough initial overhead estimates to produce a parse.
     * We then count the actual token-stream byte frequencies from that
     * parse to compute the true rANS bit cost per match token type.
     * Pass 2 re-runs backward DP + forward trace with those real costs,
     * yielding a parse that more accurately minimises the encoded size.
     *
     * Both passes reuse match_arr / found_arr; dp and choice are reused too.
     */
    /* Per-variant overhead estimates (bits); corrected after pass 1.
     * Suffix 1/2/none = 1-byte / 2-byte / 3-byte offset encoding.
     * Param counts: EXACT0=1 (offset only), EXACT1=2, EXACT2=3, EXACT=5,
     *                DELTA1=4, DELTA2=5, DELTA=7. */
    float ovhd_exact0 = 16.0f;  /* 3-byte exact: opcode + 1B offset only */
    float ovhd_exact1 = 24.0f, ovhd_exact2 = 32.0f, ovhd_exact = 48.0f;
    float ovhd_delta1 = 40.0f, ovhd_delta2 = 48.0f, ovhd_delta = 64.0f;
    float ovhd_rep    = 16.0f;  /* REP: token byte + 1B len = 2 param bytes */


    for (int _pass = 0; _pass < 4; _pass++) {
        /* Reset output streams for this parse attempt */
        opcode_len = 0; off_lo_len = 0; off_hi_len = 0; delta_len = 0; lbuf_size = 0; lit_len = 0; lit_run = 0;

        /* DP backward.
         * choice[u]: 0=literal, 1..ZXL_MAX_CANDIDATES=match candidate,
         *            CHOICE_REP=rep_match[u]
         * choice_len[u]: actual length to use (may be shorter than match's full length).
         *
         * For each match candidate, we try multiple lengths:
         *   - full length
         *   - ZXL_MIN_MATCH (shortest possible)
         *   - length at encoding boundary (259 = 255+MIN_MATCH, 1B vs 2B length)
         *   - a few intermediate lengths
         * This lets the DP discover "short match here + better match after" patterns. */
        dp[block_len] = 0.0f;
        for (int32_t i = (int32_t)block_len - 1; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            dp[u]     = sym_cost[src[block_start + u]] + dp[u + 1];
            choice[u] = 0;
            choice_len[u] = 0;

            /* Helper macro: try a match candidate at a specific length.
             * Updates dp[u], choice[u], choice_len[u] if this is cheaper.
             * Length 3 with MTYPE_EXACT and offset<256 uses the EXACT0 path
             * (opcode only + 1 offset byte, no length byte, no rep cache).
             * Length 3 otherwise not allowed (ZXL_MIN_MATCH=4 is the minimum
             * for all other encodings). */
            #define TRY_MATCH_LEN(cand_id, _m, try_len) do { \
                uint32_t _tl = (try_len); \
                if (_tl == 3u && (_m)->mtype == MTYPE_EXACT && (_m)->offset < 256u \
                    && _tl <= (_m)->length && u + _tl <= (uint32_t)block_len) { \
                    float _dp_m = ovhd_exact0 + dp[u + _tl]; \
                    if (_dp_m < dp[u]) { dp[u] = _dp_m; choice[u] = (cand_id); choice_len[u] = _tl; } \
                } else if (_tl >= ZXL_MIN_MATCH && _tl <= (_m)->length && u + _tl <= (uint32_t)block_len) { \
                    uint32_t _lm = _tl - ZXL_MIN_MATCH; \
                    float _ovhd; \
                    if ((_m)->mtype == MTYPE_EXACT) { \
                        if      (_lm < 256u && (_m)->offset <   256u) _ovhd = ovhd_exact1; \
                        else if (_lm < 256u && (_m)->offset < 65536u) _ovhd = ovhd_exact2; \
                        else                                           _ovhd = ovhd_exact; \
                    } else { \
                        if      (_lm < 256u && (_m)->offset <   256u) _ovhd = ovhd_delta1; \
                        else if (_lm < 256u && (_m)->offset < 65536u) _ovhd = ovhd_delta2; \
                        else                                           _ovhd = ovhd_delta; \
                    } \
                    float _dp_m = _ovhd + dp[u + _tl]; \
                    if (_dp_m < dp[u]) { dp[u] = _dp_m; choice[u] = (cand_id); choice_len[u] = _tl; } \
                } \
            } while (0)

            /* Try each match candidate at multiple lengths.
             * choice values: 0=literal, 1..ZXL_MAX_CANDIDATES=match candidate,
             *                ZXL_MAX_CANDIDATES+1=REP */
            for (int _ci = 0; _ci < (int)found_arr[u]; _ci++) {
                const Match *_m = &match_all[u * ZXL_MAX_CANDIDATES + _ci];
                uint8_t cid = (uint8_t)(_ci + 1);
                uint32_t mlen = _m->length;
                /* Full length */
                TRY_MATCH_LEN(cid, _m, mlen);
                /* EXACT0 special: length 3 with offset<256 (cheaper than 4-byte EXACT1) */
                if (_m->mtype == MTYPE_EXACT && _m->offset < 256u && mlen >= 3u)
                    TRY_MATCH_LEN(cid, _m, 3u);
                /* Min match length */
                if (mlen > ZXL_MIN_MATCH)
                    TRY_MATCH_LEN(cid, _m, ZXL_MIN_MATCH);
                /* Short intermediates */
                if (mlen > 5)
                    TRY_MATCH_LEN(cid, _m, 5u);
                if (mlen > 6)
                    TRY_MATCH_LEN(cid, _m, 6u);
                if (mlen > 7)
                    TRY_MATCH_LEN(cid, _m, 7u);
                /* At encoding boundary: 259 = 255 + 4 (1B->2B length transition) */
                if (mlen > 259u)
                    TRY_MATCH_LEN(cid, _m, 259u);
                /* Intermediate lengths for longer matches */
                if (mlen > 8)
                    TRY_MATCH_LEN(cid, _m, 8u);
                if (mlen > 10)
                    TRY_MATCH_LEN(cid, _m, 10u);
                if (mlen > 12)
                    TRY_MATCH_LEN(cid, _m, 12u);
                if (mlen > 16)
                    TRY_MATCH_LEN(cid, _m, 16u);
                if (mlen > 20)
                    TRY_MATCH_LEN(cid, _m, 20u);
                if (mlen > 24)
                    TRY_MATCH_LEN(cid, _m, 24u);
                if (mlen > 32)
                    TRY_MATCH_LEN(cid, _m, 32u);
                if (mlen > 40)
                    TRY_MATCH_LEN(cid, _m, 40u);
                if (mlen > 48)
                    TRY_MATCH_LEN(cid, _m, 48u);
                if (mlen > 64)
                    TRY_MATCH_LEN(cid, _m, 64u);
                if (mlen > 96)
                    TRY_MATCH_LEN(cid, _m, 96u);
                if (mlen > 128)
                    TRY_MATCH_LEN(cid, _m, 128u);
                if (mlen > 192)
                    TRY_MATCH_LEN(cid, _m, 192u);
            }
            #undef TRY_MATCH_LEN

            /* REP candidate: try full length, MIN_MATCH, and intermediate lengths.
             * REP is cheap (2 bytes total), so worth trying many cut-points. */
            #define CHOICE_REP (ZXL_MAX_CANDIDATES + 1)
            if (rep_match[u].length > 0) {
                uint32_t rlen = rep_match[u].length;
                #define TRY_REP_LEN(_tl) do { \
                    uint32_t _tll = (_tl); \
                    if (_tll >= ZXL_MIN_MATCH && _tll <= rlen && u + _tll <= (uint32_t)block_len) { \
                        float _dp_r = ovhd_rep + dp[u + _tll]; \
                        if (_dp_r < dp[u]) { dp[u] = _dp_r; choice[u] = CHOICE_REP; choice_len[u] = _tll; } \
                    } \
                } while (0)
                TRY_REP_LEN(rlen);
                TRY_REP_LEN(ZXL_MIN_MATCH);
                TRY_REP_LEN(5u);
                TRY_REP_LEN(6u);
                TRY_REP_LEN(8u);
                TRY_REP_LEN(12u);
                TRY_REP_LEN(16u);
                TRY_REP_LEN(24u);
                TRY_REP_LEN(32u);
                TRY_REP_LEN(48u);
                TRY_REP_LEN(64u);
                TRY_REP_LEN(96u);
                TRY_REP_LEN(128u);
                TRY_REP_LEN(192u);
                TRY_REP_LEN(259u);
                #undef TRY_REP_LEN
            }
        }

        /* Forward trace: REP substitution + 8-context literal tagging.
         * rep[0..2]  = LRU exact-offset cache.
         * prev_out   = last output byte; high N_LIT_CTX_BITS select context. */
        {
            uint32_t rep[5]   = {0u, 0u, 0u, 0u, 0u};
            uint8_t  prev_out = 0;
            uint32_t i = 0;
            while (i < (uint32_t)block_len) {
                uint8_t ch = choice[i];
                if (ch == 0) {
                    uint8_t b = src[block_start + i];
                    /* Adaptive AC: store full prev byte as 8-bit context. */
                    lit_ctx_buf[lit_len] = prev_out;
                    lit_buf[lit_len++]   = b;
                    prev_out = b;
                    lit_run++;
                    if (lit_run == MAX_LIT_RUN) FLUSH_LITS();
                    i++;
                } else {
                    Match *m = (ch == CHOICE_REP) ? &rep_match[i]
                               : &match_all[i * ZXL_MAX_CANDIDATES + (ch - 1)];
                    uint32_t use_len = choice_len[i];
                    FLUSH_LITS();
                    uint32_t ref_base = (uint32_t)(block_start + i) - m->offset;
                    uint8_t  ref_last = src[ref_base + use_len - 1];
                    /* Special short-match path: 3-byte exact, offset < 256.
                     * Encoded as TOK_EXACT0 + 1-byte offset, no length, no
                     * rep-cache update (kept disjoint from LRU to avoid
                     * polluting it with ultra-short local matches). */
                    if (m->mtype == MTYPE_EXACT && use_len == 3u && m->offset < 256u) {
                        opcode_buf[opcode_len++] = TOK_EXACT0;
                        off_lo_buf[off_lo_len++] = (uint8_t)m->offset;
                        prev_out = ref_last;
                        i += use_len;
                        continue;
                    }
                    uint32_t lm = use_len - ZXL_MIN_MATCH;
                    if (m->mtype == MTYPE_EXACT) {
                        int ri = (m->offset == rep[0]) ? 0 :
                                 (m->offset == rep[1]) ? 1 :
                                 (m->offset == rep[2]) ? 2 :
                                 (m->offset == rep[3]) ? 3 :
                                 (m->offset == rep[4]) ? 4 : -1;
                        if (ri >= 0 && lm < 256u) {
                            /* REP0/1/2/3/4: opcode + 1-byte length → lbuf */
                            opcode_buf[opcode_len++] = (ri == 0) ? TOK_REP0 :
                                                       (ri == 1) ? TOK_REP1 :
                                                       (ri == 2) ? TOK_REP2 :
                                                       (ri == 3) ? TOK_REP3 : TOK_REP4;
                            lbuf[lbuf_size++] = (uint8_t)lm;
                            if (ri > 0) {
                                uint32_t tmp = rep[ri];
                                for (int k = ri; k > 0; k--) rep[k] = rep[k-1];
                                rep[0] = tmp;
                            }
                        } else {
                            /* Non-REP or long-length REP → variable-length EXACT.
                             * Offset bytes → param_buf; length bytes → lbuf. */
                            if (m->offset < 256u && lm < 256u) {
                                opcode_buf[opcode_len++] = TOK_EXACT1;
                                off_lo_buf[off_lo_len++] = (uint8_t)m->offset;
                                lbuf[lbuf_size++] = (uint8_t)lm;
                            } else if (m->offset < 65536u && lm < 256u) {
                                opcode_buf[opcode_len++] = TOK_EXACT2;
                                off_lo_buf[off_lo_len++] = (uint8_t)(m->offset);
                                off_hi_buf[off_hi_len++] = (uint8_t)(m->offset >> 8);
                                lbuf[lbuf_size++] = (uint8_t)lm;
                            } else {
                                opcode_buf[opcode_len++] = TOK_EXACT;
                                off_lo_buf[off_lo_len++]  = (uint8_t)(m->offset);
                                off_hi_buf[off_hi_len++]  = (uint8_t)(m->offset >> 8);
                                off_hi_buf[off_hi_len++]  = (uint8_t)(m->offset >> 16);
                                write_u16(lbuf + lbuf_size, (uint16_t)lm); lbuf_size += 2;
                            }
                            rep[4] = rep[3]; rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = m->offset;
                        }
                        prev_out = ref_last;
                    } else {
                        /* Delta match: offset/mtype/delta → param_buf; lm → lbuf */
                        if (m->offset < 256u && lm < 256u) {
                            opcode_buf[opcode_len++] = TOK_DELTA1;
                            delta_buf[delta_len++] = m->mtype;
                            delta_buf[delta_len++] = m->delta;
                            off_lo_buf[off_lo_len++] = (uint8_t)m->offset;
                            lbuf[lbuf_size++] = (uint8_t)lm;
                        } else if (m->offset < 65536u && lm < 256u) {
                            opcode_buf[opcode_len++] = TOK_DELTA2;
                            delta_buf[delta_len++] = m->mtype;
                            delta_buf[delta_len++] = m->delta;
                            off_lo_buf[off_lo_len++] = (uint8_t)(m->offset);
                            off_hi_buf[off_hi_len++] = (uint8_t)(m->offset >> 8);
                            lbuf[lbuf_size++] = (uint8_t)lm;
                        } else {
                            opcode_buf[opcode_len++] = TOK_DELTA;
                            delta_buf[delta_len++] = m->mtype;
                            delta_buf[delta_len++] = m->delta;
                            off_lo_buf[off_lo_len++] = (uint8_t)(m->offset);
                            off_hi_buf[off_hi_len++] = (uint8_t)(m->offset >> 8);
                            off_hi_buf[off_hi_len++] = (uint8_t)(m->offset >> 16);
                            write_u16(lbuf + lbuf_size, (uint16_t)lm); lbuf_size += 2;
                        }
                        prev_out = (m->mtype == MTYPE_XOR)
                                   ? (ref_last ^ m->delta)
                                   : (uint8_t)(ref_last + m->delta);
                    }
                    i += use_len;
                }
            }
        }
        FLUSH_LITS();

        if (_pass < 3) {
            /* Re-estimate overhead from this pass's token stream for the next pass.
             * overhead = rANS cost of the opcode byte (context-weighted)
             *          + h_param bits/byte × number of parameter bytes.
             * Param counts: EXACT1=2, EXACT2=3, EXACT=5,
             *               DELTA1=4, DELTA2=5, DELTA=7.
             *
             * We split opcode counts by context (am/al) to get accurate rANS costs:
             * cost(T) = P(am|T)*(-log2(P(T|am))) + P(al|T)*(-log2(P(T|al)))
             */
            /* Rebuild 2-context counts from opcode_buf for cost estimation.
             * ctx: 0=after-match (REP/exact/delta), 1=after-literal */
            uint32_t oc_am[256]={0}, oc_al[256]={0};
            { int _ctx = 0; /* start in after-match context */
              for (size_t _j = 0; _j < opcode_len; _j++) {
                  uint8_t _op = opcode_buf[_j];
                  if (_ctx == 0) oc_am[_op]++; else oc_al[_op]++;
                  /* Literal-run tokens are 0x00..0xF3; 0xF4..0xFF are all match tokens */
                  _ctx = (_op < 0xF4u) ? 1 : 0;
              }
            }
            uint32_t oc[256];
            for (int _j = 0; _j < 256; _j++) oc[_j] = oc_am[_j]+oc_al[_j];
            float ftok = (float)opcode_len;
            float ftok_am=0.f, ftok_al=0.f;
            for (int _j=0;_j<256;_j++){ftok_am+=(float)oc_am[_j]; ftok_al+=(float)oc_al[_j];}
            /* Param entropy: separate estimates for offset/type/delta bytes (h_param)
             * and length bytes (h_plen).  DP overhead uses the appropriate rate for
             * each field: offsets cost h_param bits each, lengths cost h_plen bits. */
            float h_off_lo = 0.0f, h_off_hi = 0.0f;
            if (off_lo_len > 0) {
                uint32_t pc[256] = {0};
                for (size_t _j = 0; _j < off_lo_len; _j++) pc[off_lo_buf[_j]]++;
                float fpar = (float)off_lo_len;
                for (int _j = 0; _j < 256; _j++) {
                    if (pc[_j] > 0) { float _p = (float)pc[_j]/fpar; h_off_lo -= _p*log2f(_p); }
                }
            }
            if (off_hi_len > 0) {
                uint32_t pc[256] = {0};
                for (size_t _j = 0; _j < off_hi_len; _j++) pc[off_hi_buf[_j]]++;
                float fpar = (float)off_hi_len;
                for (int _j = 0; _j < 256; _j++) {
                    if (pc[_j] > 0) { float _p = (float)pc[_j]/fpar; h_off_hi -= _p*log2f(_p); }
                }
            }
            float h_delta = 0.0f;
            if (delta_len > 0) {
                uint32_t dc[256] = {0};
                for (size_t _j = 0; _j < delta_len; _j++) dc[delta_buf[_j]]++;
                float fdel = (float)delta_len;
                for (int _j = 0; _j < 256; _j++) {
                    if (dc[_j] > 0) { float _p = (float)dc[_j]/fdel; h_delta -= _p*log2f(_p); }
                }
            }
            float h_plen = 0.0f;
            if (lbuf_size > 0) {
                uint32_t lc[256] = {0};
                for (size_t _j = 0; _j < lbuf_size; _j++) lc[lbuf[_j]]++;
                float flen = (float)lbuf_size;
                for (int _j = 0; _j < 256; _j++) {
                    if (lc[_j] > 0) { float _p = (float)lc[_j]/flen; h_plen -= _p*log2f(_p); }
                }
            }
            /* Context-weighted opcode cost + per-field param costs.
             * Param counts: (n_off offset/delta bytes, n_len length bytes) per token.
             *   EXACT1: 1 off + 1 len   EXACT2: 2 off + 1 len   EXACT: 3 off + 2 len
             *   DELTA1: 3 off + 1 len   DELTA2: 4 off + 1 len   DELTA: 5 off + 2 len */
            /* Offset bytes split: lo stream (1 per match) + hi stream (1 for E2/D2, 2 for E/D).
             *   EXACT1: 1 lo                     + 1 len
             *   EXACT2: 1 lo + 1 hi              + 1 len
             *   EXACT:  1 lo + 2 hi              + 2 len
             *   DELTA1: 1 lo          + 2 delta  + 1 len
             *   DELTA2: 1 lo + 1 hi   + 2 delta  + 1 len
             *   DELTA:  1 lo + 2 hi   + 2 delta  + 2 len */
            #define OVHD_OP(tid, fb) \
                ((oc[(tid)] > 0) ? _ovhd_ctx((float)oc_am[(tid)], (float)oc_al[(tid)], ftok_am, ftok_al, ftok) : (fb))
            /* EXACT0: opcode + 1 off_lo byte, no length, no delta → h_op + h_off_lo */
            ovhd_exact0 = OVHD_OP(TOK_EXACT0, 8.0f) + 1.0f*h_off_lo + 0.0f*h_off_hi + 0.0f*h_delta + 0.0f*h_plen;
            ovhd_exact1 = OVHD_OP(TOK_EXACT1, 8.0f) + 1.0f*h_off_lo + 0.0f*h_off_hi + 0.0f*h_delta + 1.0f*h_plen;
            ovhd_exact2 = OVHD_OP(TOK_EXACT2, 8.0f) + 1.0f*h_off_lo + 1.0f*h_off_hi + 0.0f*h_delta + 1.0f*h_plen;
            ovhd_exact  = OVHD_OP(TOK_EXACT,  8.0f) + 1.0f*h_off_lo + 2.0f*h_off_hi + 0.0f*h_delta + 2.0f*h_plen;
            ovhd_delta1 = OVHD_OP(TOK_DELTA1, 8.0f) + 1.0f*h_off_lo + 0.0f*h_off_hi + 2.0f*h_delta + 1.0f*h_plen;
            ovhd_delta2 = OVHD_OP(TOK_DELTA2, 8.0f) + 1.0f*h_off_lo + 1.0f*h_off_hi + 2.0f*h_delta + 1.0f*h_plen;
            ovhd_delta  = OVHD_OP(TOK_DELTA,  8.0f) + 1.0f*h_off_lo + 2.0f*h_off_hi + 2.0f*h_delta + 2.0f*h_plen;
            #undef OVHD_OP
            if (ovhd_exact0 < 10.0f) ovhd_exact0 = 10.0f;
            if (ovhd_exact1 < 16.0f) ovhd_exact1 = 16.0f;
            if (ovhd_exact2 < 24.0f) ovhd_exact2 = 24.0f;
            if (ovhd_exact  < 32.0f) ovhd_exact  = 32.0f;
            if (ovhd_delta1 < 24.0f) ovhd_delta1 = 24.0f;
            if (ovhd_delta2 < 32.0f) ovhd_delta2 = 32.0f;
            if (ovhd_delta  < 40.0f) ovhd_delta  = 40.0f;
            /* REP overhead: 1 length byte only (no offset) → use h_plen */
            {
                float rep_cnt = (float)(oc[TOK_REP0] + oc[TOK_REP1] + oc[TOK_REP2] + oc[TOK_REP3] + oc[TOK_REP4]);
                if (rep_cnt > 0.0f)
                    ovhd_rep = -log2f(rep_cnt / ftok) + 1.0f * h_plen;
                if (ovhd_rep < 8.0f) ovhd_rep = 8.0f;
            }
            /* After pass 1 (not pass 0): rebuild sym_cost from residual literals.
             * Pass 1 and pass 2 parse decisions are close; the residual literal
             * distribution from pass 1 is a good model for pass 2's literal costs.
             * (After pass 0 the parse differs too much to be reliable.) */
            if (_pass >= 1 && lit_len > 0) {
                uint32_t lf[256] = {0};
                for (size_t _j = 0; _j < lit_len; _j++) lf[lit_buf[_j]]++;
                float ftot = 0.0f;
                for (int _b = 0; _b < 256; _b++)
                    ftot += (float)(lf[_b] ? lf[_b] : 1u);
                for (int _b = 0; _b < 256; _b++) {
                    uint32_t f = lf[_b] ? lf[_b] : 1u;
                    sym_cost[_b] = -log2f((float)f / ftot);
                }
            }
        }
    }

    free(match_all); free(rep_match);
    free(found_arr); free(dp); free(choice); free(choice_len);
    match_all = NULL; rep_match = NULL;
    found_arr = NULL; choice = NULL; choice_len = NULL;
    #undef CHOICE_REP

    #undef FLUSH_LITS

    /* ---- Split opcode stream into 2 context sub-streams ----------- *
     * Context rule (applied to each opcode position):
     *   ctx=0 (after-match):   prev opcode was a match token (0xF4..0xFF) or first opcode
     *   ctx=1 (after-literal): prev opcode was a literal run token (0x00..0xF3)
     * After a literal run the next-opcode distribution skews heavily toward match
     * tokens; after a match it is more mixed.  Separate rANS models exploit this.
     * Block starts in ctx=0 (after-match, neutral). */
    uint8_t *opcode_am = (uint8_t *)malloc(opcode_len + 1);  /* after-match */
    uint8_t *opcode_al = (uint8_t *)malloc(opcode_len + 1);  /* after-lit   */
    size_t am_len = 0, al_len = 0;
    if (!opcode_am || !opcode_al) {
        free(opcode_am); free(opcode_al);
        free(opcode_buf); free(off_lo_buf); free(off_hi_buf); free(delta_buf); free(lbuf); free(lit_buf); free(lit_ctx_buf); return 0;
    }
    {
        int ctx = 0; /* start in after-match context */
        for (size_t i = 0; i < opcode_len; i++) {
            uint8_t op = opcode_buf[i];
            if (ctx == 0) opcode_am[am_len++] = op;
            else          opcode_al[al_len++] = op;
            ctx = (op < 0xF4u) ? 1 : 0;
        }
    }

    /* Build rANS tables + per-table rank-1/dense mode. */
    int      am_mode, al_mode, off_lo_mode, off_hi_mode, delta_mode, len_mode;
    uint32_t am_row[16], am_col[16], al_row[16], al_col[16];
    uint32_t off_lo_row[16], off_lo_col[16], off_hi_row[16], off_hi_col[16];
    uint32_t delta_row[16], delta_col[16], len_row[16], len_col[16];

    uint32_t am_counts[256] = {0};
    for (size_t i = 0; i < am_len; i++) am_counts[opcode_am[i]]++;
    RansSym  am_syms[256];  RansSlot am_slots[RANS_SCALE];
    am_mode = build_freqs_auto(am_counts, am_syms, am_slots, am_row, am_col);

    uint32_t al_counts[256] = {0};
    for (size_t i = 0; i < al_len; i++) al_counts[opcode_al[i]]++;
    RansSym  al_syms[256];  RansSlot al_slots[RANS_SCALE];
    al_mode = build_freqs_auto(al_counts, al_syms, al_slots, al_row, al_col);

    uint32_t off_lo_counts[256] = {0};
    for (size_t i = 0; i < off_lo_len; i++) off_lo_counts[off_lo_buf[i]]++;
    RansSym  off_lo_syms[256]; RansSlot off_lo_slots[RANS_SCALE];
    off_lo_mode = build_freqs_auto(off_lo_counts, off_lo_syms, off_lo_slots, off_lo_row, off_lo_col);

    uint32_t off_hi_counts[256] = {0};
    for (size_t i = 0; i < off_hi_len; i++) off_hi_counts[off_hi_buf[i]]++;
    RansSym  off_hi_syms[256]; RansSlot off_hi_slots[RANS_SCALE];
    off_hi_mode = build_freqs_auto(off_hi_counts, off_hi_syms, off_hi_slots, off_hi_row, off_hi_col);

    uint32_t delta_counts[256] = {0};
    for (size_t i = 0; i < delta_len; i++) delta_counts[delta_buf[i]]++;
    RansSym  delta_syms[256];  RansSlot delta_slots[RANS_SCALE];
    delta_mode = build_freqs_auto(delta_counts, delta_syms, delta_slots, delta_row, delta_col);

    uint32_t len_counts[256] = {0};
    for (size_t i = 0; i < lbuf_size; i++) len_counts[lbuf[i]]++;
    RansSym  len_syms[256];  RansSlot len_slots[RANS_SCALE];
    len_mode = build_freqs_auto(len_counts, len_syms, len_slots, len_row, len_col);

    /* ---- Entropy-code literal stream: adaptive binary range coder ----
     * Each literal byte is bit-tree encoded under a 256-context model
     * keyed on the previous output byte (lit_ctx_buf[i]). Adaptive
     * probabilities (LZMA-style, 11-bit precision) eliminate per-block
     * frequency-table overhead and exploit cross-symbol structure beyond
     * the 4-bit nibble context the prior 16-stream rANS model used. */
    size_t scratch_cap = zxl_bound(block_len + lit_len + off_lo_len + off_hi_len + delta_len);
    uint8_t *scratch = (uint8_t *)malloc(scratch_cap);
    if (!scratch) { free(opcode_buf); free(off_lo_buf); free(off_hi_buf); free(delta_buf); free(lbuf); free(lit_buf); free(lit_ctx_buf); return 0; }

    size_t   lit_ac_cap = lit_len + (lit_len >> 4) + 64;
    uint8_t *lit_enc    = (uint8_t *)malloc(lit_ac_cap);
    zxl_ac_prob (*lit_probs)[256] = (zxl_ac_prob (*)[256])malloc(256 * 256 * sizeof(zxl_ac_prob));
    if (!lit_enc || !lit_probs) {
        free(lit_enc); free(lit_probs);
        free(scratch); free(opcode_buf); free(off_lo_buf); free(off_hi_buf); free(delta_buf); free(lbuf); free(lit_buf); free(lit_ctx_buf); return 0;
    }
    for (int c = 0; c < 256; c++) for (int k = 0; k < 256; k++) lit_probs[c][k] = ZXL_AC_PROB_INIT;
    size_t lit_enc_total = 0;
    {
        zxl_ac_enc rc;
        zxl_ac_enc_init(&rc, lit_enc, lit_ac_cap);
        for (size_t j = 0; j < lit_len; j++) {
            zxl_ac_enc_byte(&rc, lit_probs[lit_ctx_buf[j]], lit_buf[j]);
        }
        lit_enc_total = zxl_ac_enc_finish(&rc);
        if (lit_len > 0 && lit_enc_total == 0) {
            free(lit_probs); free(lit_enc);
            free(scratch); free(opcode_buf); free(off_lo_buf); free(off_hi_buf); free(delta_buf); free(lbuf); free(lit_buf); free(lit_ctx_buf); return 0;
        }
    }
    free(lit_probs);

    /* ---- Encode 2 opcode sub-streams ------------------------------ */
    #define ENC_OP(name, buf, blen, syms, enc_sz, enc_ptr, cleanup) \
        size_t enc_sz = 0; uint8_t *enc_ptr = NULL; \
        if (blen > 0) { \
            enc_sz = rans_encode(buf, blen, syms, scratch, scratch_cap); \
            if (!enc_sz) { cleanup; return 0; } \
            enc_ptr = (uint8_t *)malloc(enc_sz); \
            if (!enc_ptr) { cleanup; return 0; } \
            memcpy(enc_ptr, scratch, enc_sz); \
        }
    #define FREE2OP free(opcode_am); free(opcode_al); \
                    free(lit_enc); free(scratch); free(opcode_buf); \
                    free(off_lo_buf); free(off_hi_buf); free(delta_buf); free(lbuf); free(lit_buf); free(lit_ctx_buf)

    ENC_OP(am, opcode_am, am_len, am_syms, enc_opcode_am, opcode_am_enc, FREE2OP)
    ENC_OP(al, opcode_al, al_len, al_syms, enc_opcode_al, opcode_al_enc,
           if(opcode_am_enc)free(opcode_am_enc); FREE2OP)
    #undef ENC_OP

    #define FREE4ALL if(opcode_al_enc)free(opcode_al_enc); \
                     if(opcode_am_enc)free(opcode_am_enc); \
                     FREE2OP

    /* ---- Encode offset-lo stream ----------------------------------- */
    size_t   enc_off_lo = 0;
    uint8_t *off_lo_enc = NULL;
    if (off_lo_len > 0) {
        enc_off_lo = rans_encode(off_lo_buf, off_lo_len, off_lo_syms, scratch, scratch_cap);
        if (!enc_off_lo) { FREE4ALL; return 0; }
        off_lo_enc = (uint8_t *)malloc(enc_off_lo);
        if (!off_lo_enc) { FREE4ALL; return 0; }
        memcpy(off_lo_enc, scratch, enc_off_lo);
    }

    /* ---- Encode offset-hi stream ----------------------------------- */
    size_t   enc_off_hi = 0;
    uint8_t *off_hi_enc = NULL;
    if (off_hi_len > 0) {
        enc_off_hi = rans_encode(off_hi_buf, off_hi_len, off_hi_syms, scratch, scratch_cap);
        if (!enc_off_hi) { if(off_lo_enc)free(off_lo_enc); FREE4ALL; return 0; }
        off_hi_enc = (uint8_t *)malloc(enc_off_hi);
        if (!off_hi_enc) { if(off_lo_enc)free(off_lo_enc); FREE4ALL; return 0; }
        memcpy(off_hi_enc, scratch, enc_off_hi);
    }

    /* ---- Encode delta stream (mtype + delta bytes only) ----------- */
    size_t   enc_delta = 0;
    uint8_t *delta_enc = NULL;
    if (delta_len > 0) {
        enc_delta = rans_encode(delta_buf, delta_len, delta_syms, scratch, scratch_cap);
        if (!enc_delta) { if(off_hi_enc)free(off_hi_enc); if(off_lo_enc)free(off_lo_enc); FREE4ALL; return 0; }
        delta_enc = (uint8_t *)malloc(enc_delta);
        if (!delta_enc) { if(off_hi_enc)free(off_hi_enc); if(off_lo_enc)free(off_lo_enc); FREE4ALL; return 0; }
        memcpy(delta_enc, scratch, enc_delta);
    }

    /* ---- Encode length stream ------------------------------------- */
    size_t   enc_len = 0;
    uint8_t *len_enc = NULL;
    if (lbuf_size > 0) {
        enc_len = rans_encode(lbuf, lbuf_size, len_syms, scratch, scratch_cap);
        if (!enc_len) { if(delta_enc)free(delta_enc); if(off_hi_enc)free(off_hi_enc); if(off_lo_enc)free(off_lo_enc); FREE4ALL; return 0; }
        len_enc = (uint8_t *)malloc(enc_len);
        if (!len_enc) { if(delta_enc)free(delta_enc); if(off_hi_enc)free(off_hi_enc); if(off_lo_enc)free(off_lo_enc); FREE4ALL; return 0; }
        memcpy(len_enc, scratch, enc_len);
    }
    #undef FREE4ALL
    #undef FREE2OP
    free(scratch);

    /*
     * Block header (ZXLC, post-adaptive-AC literals):
     *   [4]×15      fields: uncomp, enc_am, enc_al,
     *                       enc_off_lo, enc_off_hi, enc_delta, enc_len, lit_ac_size,
     *                       dec_am, dec_al, dec_off_lo, dec_off_hi, dec_delta, dec_len, dec_lit
     *   [tagged]×6  freq tables (D1.5): am, al, off_lo, off_hi, delta, len
     *   streams: am, al, off_lo, off_hi, delta, len, lit_ac
     *
     *   Literals are coded with a single adaptive binary range coder
     *   conditioned on the previous output byte (256 contexts, 8-bit
     *   tree per context, init prob 0.5). No per-block freq tables.
     *
     *   enc_am == 0 → raw fallback (literal copy at offset 60).
     */
    #define N_HDR_FIELDS 15
    /* Worst-case freq tables: 1 mode byte + ZXL_COMPACT_FREQ_MAX dense payload per table.
     * 6 main tables (am, al, off_lo, off_hi, delta, len). Literals use AC: no header tables. */
    size_t hdr_size = 4*N_HDR_FIELDS + (ZXL_COMPACT_FREQ_MAX + 1)*6;

    size_t total_opcode = enc_opcode_am + enc_opcode_al;
    size_t total_needed = hdr_size + total_opcode + enc_off_lo + enc_off_hi + enc_delta + enc_len + lit_enc_total;
    if (total_needed > dst_cap) {
        if (len_enc) free(len_enc);
        if (delta_enc) free(delta_enc);
        if (off_hi_enc) free(off_hi_enc);
        if (off_lo_enc) free(off_lo_enc);
        if (opcode_al_enc) free(opcode_al_enc);
        if (opcode_am_enc) free(opcode_am_enc);
        free(opcode_am); free(opcode_al);
        free(lit_enc);
        free(opcode_buf); free(off_lo_buf); free(off_hi_buf); free(delta_buf); free(lbuf); free(lit_buf); free(lit_ctx_buf);
        /* Raw fallback: enc_am=0 signals no compression; raw data at offset N_HDR_FIELDS*4 */
        size_t raw_hdr = (size_t)(N_HDR_FIELDS * 4);
        if (block_len + raw_hdr > dst_cap) return 0;
        for (int _i = 0; _i < N_HDR_FIELDS; _i++) write_u32(dst + _i*4, 0);
        write_u32(dst,    (uint32_t)block_len);              /* uncomp_size */
        write_u32(dst+28, (uint32_t)block_len);              /* lit_ac_size (field [7]) */
        write_u32(dst+(N_HDR_FIELDS-1)*4, (uint32_t)block_len); /* dec_lit */
        memcpy(dst+raw_hdr, src + block_start, block_len);
        return raw_hdr + block_len;
    }

    uint8_t *p = dst;
    write_u32(p, (uint32_t)block_len);         p += 4;  /* [0]  uncomp */
    write_u32(p, (uint32_t)enc_opcode_am);     p += 4;  /* [1]  enc_am (0=raw) */
    write_u32(p, (uint32_t)enc_opcode_al);     p += 4;  /* [2]  enc_al */
    write_u32(p, (uint32_t)enc_off_lo);        p += 4;  /* [3]  enc_off_lo */
    write_u32(p, (uint32_t)enc_off_hi);        p += 4;  /* [4]  enc_off_hi */
    write_u32(p, (uint32_t)enc_delta);         p += 4;  /* [5]  enc_delta */
    write_u32(p, (uint32_t)enc_len);           p += 4;  /* [6]  enc_len */
    write_u32(p, (uint32_t)lit_enc_total);     p += 4;  /* [7]  lit_ac_size */
    write_u32(p, (uint32_t)am_len);            p += 4;  /* [8]  dec_am */
    write_u32(p, (uint32_t)al_len);            p += 4;  /* [9]  dec_al */
    write_u32(p, (uint32_t)off_lo_len);        p += 4;  /* [10] dec_off_lo */
    write_u32(p, (uint32_t)off_hi_len);        p += 4;  /* [11] dec_off_hi */
    write_u32(p, (uint32_t)delta_len);         p += 4;  /* [12] dec_delta */
    write_u32(p, (uint32_t)lbuf_size);         p += 4;  /* [13] dec_len */
    write_u32(p, (uint32_t)lit_len);           p += 4;  /* [14] dec_lit */

    /* D1.5 compact freq tables for the 6 rANS streams (literals use AC, no table). */
    p += write_freqs_tagged(p, am_mode,     am_syms,     am_row,     am_col);
    p += write_freqs_tagged(p, al_mode,     al_syms,     al_row,     al_col);
    p += write_freqs_tagged(p, off_lo_mode, off_lo_syms, off_lo_row, off_lo_col);
    p += write_freqs_tagged(p, off_hi_mode, off_hi_syms, off_hi_row, off_hi_col);
    p += write_freqs_tagged(p, delta_mode,  delta_syms,  delta_row,  delta_col);
    p += write_freqs_tagged(p, len_mode,    len_syms,    len_row,    len_col);

    if (opcode_am_enc && enc_opcode_am) { memcpy(p, opcode_am_enc, enc_opcode_am); p += enc_opcode_am; }
    if (opcode_al_enc && enc_opcode_al) { memcpy(p, opcode_al_enc, enc_opcode_al); p += enc_opcode_al; }
    if (off_lo_enc && enc_off_lo) { memcpy(p, off_lo_enc, enc_off_lo); p += enc_off_lo; }
    if (off_hi_enc && enc_off_hi) { memcpy(p, off_hi_enc, enc_off_hi); p += enc_off_hi; }
    if (delta_enc && enc_delta)   { memcpy(p, delta_enc,  enc_delta);  p += enc_delta; }
    if (len_enc   && enc_len)     { memcpy(p, len_enc,    enc_len);    p += enc_len; }
    memcpy(p, lit_enc, lit_enc_total); p += lit_enc_total;

    if (len_enc) free(len_enc);
    if (delta_enc) free(delta_enc);
    if (off_hi_enc) free(off_hi_enc);
    if (off_lo_enc) free(off_lo_enc);
    if (opcode_al_enc) free(opcode_al_enc);
    if (opcode_am_enc) free(opcode_am_enc);
    free(opcode_am); free(opcode_al);
    free(lit_enc);
    free(opcode_buf); free(off_lo_buf); free(off_hi_buf); free(delta_buf); free(lbuf); free(lit_buf); free(lit_ctx_buf);
    #undef N_HDR_FIELDS
    return (size_t)(p - dst);
}

/* ------------------------------------------------------------------ */
/* Block decompress                                                    */
/* ------------------------------------------------------------------ */

/*
 * Decompress one block.
 *
 * dst              : full output buffer from position 0
 * dst_cap          : total capacity of dst
 * global_out_pos   : where this block's output starts in dst
 *
 * Using absolute output positions lets match offsets reference data from
 * any prior block within the 1 MB window — the same offset the compressor
 * stored, measured back from the current absolute output position.
 *
 * Returns the number of uncompressed bytes written (== uncomp_size on
 * success), or 0 on error.  *consumed is set to the number of compressed
 * bytes consumed from src.
 */
static size_t decompress_block(const uint8_t *src, size_t src_len,
                               uint8_t *dst, size_t dst_cap,
                               size_t global_out_pos,
                               size_t *consumed)
{
    /* ZXLC header: 15 uint32 fields (60 bytes) */
    #define N_HDR_FIELDS_D 15
    size_t raw_hdr_d = (size_t)(N_HDR_FIELDS_D * 4);
    if (src_len < raw_hdr_d) return 0;
    uint32_t uncomp_size     = read_u32(src);
    uint32_t opcode_am_size  = read_u32(src + 4);   /* enc_am (0 = raw fallback) */
    uint32_t opcode_al_size  = read_u32(src + 8);
    uint32_t off_lo_size     = read_u32(src + 12);
    uint32_t off_hi_size     = read_u32(src + 16);
    uint32_t delta_size      = read_u32(src + 20);
    uint32_t len_size        = read_u32(src + 24);
    uint32_t lit_ac_size     = read_u32(src + 28);   /* AC stream size */
    uint32_t am_dec_len      = read_u32(src + 32);
    uint32_t al_dec_len      = read_u32(src + 36);
    uint32_t off_lo_dec_len  = read_u32(src + 40);
    uint32_t off_hi_dec_len  = read_u32(src + 44);
    uint32_t delta_dec_len   = read_u32(src + 48);
    uint32_t len_dec_len     = read_u32(src + 52);
    uint32_t lit_dec_len     = read_u32(src + 56);

    if (global_out_pos + uncomp_size > dst_cap) return 0;

    /* Uncompressed fallback (enc_am == 0) */
    if (opcode_am_size == 0) {
        if (src_len < raw_hdr_d + lit_ac_size) return 0;
        memcpy(dst + global_out_pos, src + raw_hdr_d, lit_ac_size);
        *consumed = raw_hdr_d + lit_ac_size;
        return lit_ac_size;
    }

    /* D1 compact freq tables: sizes are variable. We use a bounds-check on each
     * read rather than a precomputed hdr size, and then sanity-check remaining. */
    const uint8_t *tp = src + raw_hdr_d;
    const uint8_t *tp_end = src + src_len;

    #define READ_COMPACT_FREQS_INTO(syms_arr, slots_arr)                         \
        do {                                                                       \
            uint32_t _cnt[256];                                                    \
            size_t _consumed = read_freqs_tagged(tp, (size_t)(tp_end - tp), _cnt); \
            if (_consumed == 0) return 0;                                          \
            tp += _consumed;                                                       \
            rans_build_tables(_cnt, (syms_arr), (slots_arr));                      \
        } while (0)

    /* Two opcode freq tables: am, al */
    RansSym  am_syms[256];  RansSlot am_slots[RANS_SCALE];
    READ_COMPACT_FREQS_INTO(am_syms, am_slots);
    RansSym  al_syms[256];  RansSlot al_slots[RANS_SCALE];
    READ_COMPACT_FREQS_INTO(al_syms, al_slots);

    /* Offset-lo / offset-hi / delta / len freq tables */
    RansSym  off_lo_syms_d[256];  RansSlot off_lo_slots_d[RANS_SCALE];
    READ_COMPACT_FREQS_INTO(off_lo_syms_d, off_lo_slots_d);
    RansSym  off_hi_syms_d[256];  RansSlot off_hi_slots_d[RANS_SCALE];
    READ_COMPACT_FREQS_INTO(off_hi_syms_d, off_hi_slots_d);
    RansSym  delta_syms[256];  RansSlot delta_slots[RANS_SCALE];
    READ_COMPACT_FREQS_INTO(delta_syms, delta_slots);
    RansSym  len_syms[256];  RansSlot len_slots[RANS_SCALE];
    READ_COMPACT_FREQS_INTO(len_syms, len_slots);

    #undef READ_COMPACT_FREQS_INTO

    /* Bounds check: all streams must fit (literals are AC, no header tables). */
    size_t need = opcode_am_size + opcode_al_size
                + off_lo_size + off_hi_size + delta_size + len_size + lit_ac_size;
    if ((size_t)(tp_end - tp) < need) return 0;

    size_t hdr_consumed = (size_t)(tp - src);  /* total variable header size */
    const uint8_t *opcode_am_stream = tp;
    const uint8_t *opcode_al_stream = tp + opcode_am_size;
    size_t op2 = opcode_am_size + opcode_al_size;
    const uint8_t *off_lo_stream = tp + op2;
    const uint8_t *off_hi_stream = tp + op2 + off_lo_size;
    const uint8_t *delta_stream  = tp + op2 + off_lo_size + off_hi_size;
    const uint8_t *len_stream    = tp + op2 + off_lo_size + off_hi_size + delta_size;
    const uint8_t *lit_stream    = tp + op2 + off_lo_size + off_hi_size + delta_size + len_size;

    /* Decode 2 opcode sub-streams */
    #define DEC_OP(buf, stream, enc_sz, dec_len, slots, cleanup) \
        uint8_t *buf = (uint8_t *)malloc((dec_len) + 64); \
        if (!buf) { cleanup; return 0; } \
        if ((dec_len) > 0 && rans_decode(stream, enc_sz, slots, buf, dec_len) != 0) { \
            free(buf); cleanup; return 0; \
        }
    DEC_OP(opcode_am_buf, opcode_am_stream, opcode_am_size, am_dec_len, am_slots, )
    DEC_OP(opcode_al_buf, opcode_al_stream, opcode_al_size, al_dec_len, al_slots,
           free(opcode_am_buf))
    #undef DEC_OP

    #define FREE2BUF free(opcode_al_buf); free(opcode_am_buf)

    /* Decode offset-lo stream */
    uint8_t *off_lo_buf_d = NULL;
    if (off_lo_dec_len > 0) {
        off_lo_buf_d = (uint8_t *)malloc(off_lo_dec_len + 64);
        if (!off_lo_buf_d) { FREE2BUF; return 0; }
        if (rans_decode(off_lo_stream, off_lo_size, off_lo_slots_d, off_lo_buf_d, off_lo_dec_len) != 0) {
            free(off_lo_buf_d); FREE2BUF; return 0;
        }
    }

    /* Decode offset-hi stream */
    uint8_t *off_hi_buf_d = NULL;
    if (off_hi_dec_len > 0) {
        off_hi_buf_d = (uint8_t *)malloc(off_hi_dec_len + 64);
        if (!off_hi_buf_d) { if(off_lo_buf_d)free(off_lo_buf_d); FREE2BUF; return 0; }
        if (rans_decode(off_hi_stream, off_hi_size, off_hi_slots_d, off_hi_buf_d, off_hi_dec_len) != 0) {
            free(off_hi_buf_d); if(off_lo_buf_d)free(off_lo_buf_d); FREE2BUF; return 0;
        }
    }

    /* Decode delta stream — mtype+deltaval bytes */
    uint8_t *delta_buf = NULL;
    if (delta_dec_len > 0) {
        delta_buf = (uint8_t *)malloc(delta_dec_len + 64);
        if (!delta_buf) { if(off_hi_buf_d)free(off_hi_buf_d); if(off_lo_buf_d)free(off_lo_buf_d); FREE2BUF; return 0; }
        if (rans_decode(delta_stream, delta_size, delta_slots, delta_buf, delta_dec_len) != 0) {
            free(delta_buf); if(off_hi_buf_d)free(off_hi_buf_d); if(off_lo_buf_d)free(off_lo_buf_d); FREE2BUF; return 0;
        }
    }

    /* Decode len stream — match length bytes */
    uint8_t *len_buf = NULL;
    if (len_dec_len > 0) {
        len_buf = (uint8_t *)malloc(len_dec_len + 64);
        if (!len_buf) { if(delta_buf)free(delta_buf); if(off_hi_buf_d)free(off_hi_buf_d); if(off_lo_buf_d)free(off_lo_buf_d); FREE2BUF; return 0; }
        if (rans_decode(len_stream, len_size, len_slots, len_buf, len_dec_len) != 0) {
            free(len_buf); if(delta_buf)free(delta_buf); if(off_hi_buf_d)free(off_hi_buf_d); if(off_lo_buf_d)free(off_lo_buf_d); FREE2BUF; return 0;
        }
    }

    /* Initialise adaptive AC for literals: 256 contexts × 8-bit tree (256 prob slots/ctx). */
    zxl_ac_prob (*lit_probs)[256] = (zxl_ac_prob (*)[256])malloc(256 * 256 * sizeof(zxl_ac_prob));
    if (!lit_probs) { if(len_buf)free(len_buf); if(delta_buf)free(delta_buf); if(off_hi_buf_d)free(off_hi_buf_d); if(off_lo_buf_d)free(off_lo_buf_d); FREE2BUF; return 0; }
    for (int c = 0; c < 256; c++) for (int k = 0; k < 256; k++) lit_probs[c][k] = ZXL_AC_PROB_INIT;
    zxl_ac_dec rd;
    int rd_ok = (zxl_ac_dec_init(&rd, lit_stream, lit_ac_size) == 0);
    (void)lit_dec_len;

    /* Reconstruct output.
     * Opcodes are read from two sub-streams based on context:
     *   ctx=0 (after-match or start): read from opcode_am_buf
     *   ctx=1 (after-literal):        read from opcode_al_buf
     * pi_off_lo = index into off_lo_buf_d
     * pi_off_hi = index into off_hi_buf_d
     * pi_delta  = index into delta_buf
     * pi_len    = index into len_buf
     * prev_out tracks last byte; its high bits select literal context. */
    size_t   am_idx    = 0;   /* after-match opcode stream index */
    size_t   al_idx    = 0;   /* after-lit   opcode stream index */
    size_t   pi_off_lo = 0;
    size_t   pi_off_hi = 0;
    size_t   pi_delta  = 0;
    size_t   pi_len    = 0;
    size_t   out_pos  = global_out_pos;
    size_t   out_end  = global_out_pos + uncomp_size;
    uint32_t rep[5]   = {0u, 0u, 0u, 0u, 0u};
    uint8_t  prev_out = 0;
    int      op_ctx   = 0;  /* start in after-match context */

    (void)lit_dec_len;

    while (out_pos < out_end) {
        uint8_t tok;
        if (op_ctx == 0) tok = opcode_am_buf[am_idx++];
        else             tok = opcode_al_buf[al_idx++];
        op_ctx = (tok < 0xF4u) ? 1 : 0;

        if (tok == TOK_EXACT0) {
            /* 3-byte exact match: 1-byte offset, implicit length 3, no rep update */
            uint32_t off = off_lo_buf_d[pi_off_lo++];
            if (out_pos < off || out_pos + 3u > out_end) break;
            const uint8_t *ref = dst + out_pos - off;
            dst[out_pos]   = ref[0];
            dst[out_pos+1] = ref[1];
            dst[out_pos+2] = ref[2];
            prev_out = dst[out_pos + 2];
            out_pos += 3;

        } else if (tok == TOK_EXACT) {
            uint32_t off = (uint32_t)off_lo_buf_d[pi_off_lo];
            off |= (uint32_t)off_hi_buf_d[pi_off_hi] << 8;
            off |= (uint32_t)off_hi_buf_d[pi_off_hi + 1] << 16;
            pi_off_lo++; pi_off_hi += 2;
            uint32_t len = read_u16(len_buf + pi_len) + ZXL_MIN_MATCH; pi_len += 2;
            if (out_pos < off || out_pos + len > out_end) break;
            const uint8_t *ref = dst + out_pos - off;
            for (uint32_t k = 0; k < len; k++) dst[out_pos + k] = ref[k];
            prev_out = dst[out_pos + len - 1];
            out_pos += len;
            rep[4] = rep[3]; rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = off;

        } else if (tok == TOK_EXACT1) {
            uint32_t off = off_lo_buf_d[pi_off_lo++];
            uint32_t len = (uint32_t)len_buf[pi_len++] + ZXL_MIN_MATCH;
            if (out_pos < off || out_pos + len > out_end) break;
            const uint8_t *ref = dst + out_pos - off;
            for (uint32_t k = 0; k < len; k++) dst[out_pos + k] = ref[k];
            prev_out = dst[out_pos + len - 1];
            out_pos += len;
            rep[4] = rep[3]; rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = off;

        } else if (tok == TOK_EXACT2) {
            uint32_t off = (uint32_t)off_lo_buf_d[pi_off_lo++]
                         | ((uint32_t)off_hi_buf_d[pi_off_hi++] << 8);
            uint32_t len = (uint32_t)len_buf[pi_len++] + ZXL_MIN_MATCH;
            if (out_pos < off || out_pos + len > out_end) break;
            const uint8_t *ref = dst + out_pos - off;
            for (uint32_t k = 0; k < len; k++) dst[out_pos + k] = ref[k];
            prev_out = dst[out_pos + len - 1];
            out_pos += len;
            rep[4] = rep[3]; rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = off;

        } else if (tok == TOK_REP0 || tok == TOK_REP1 || tok == TOK_REP2 ||
                   tok == TOK_REP3 || tok == TOK_REP4) {
            int ri = (tok == TOK_REP0) ? 0 :
                     (tok == TOK_REP1) ? 1 :
                     (tok == TOK_REP2) ? 2 :
                     (tok == TOK_REP3) ? 3 : 4;
            uint32_t off = rep[ri];
            uint32_t len = (uint32_t)len_buf[pi_len++] + ZXL_MIN_MATCH; /* 1-byte length from len_buf */
            if (out_pos < off || out_pos + len > out_end) break;
            const uint8_t *ref = dst + out_pos - off;
            for (uint32_t k = 0; k < len; k++) dst[out_pos + k] = ref[k];
            prev_out = dst[out_pos + len - 1];
            out_pos += len;
            if (ri > 0) {
                uint32_t tmp = rep[ri];
                for (int k = ri; k > 0; k--) rep[k] = rep[k-1];
                rep[0] = tmp;
            }

        } else if (tok == TOK_DELTA) {
            uint8_t  mtype = delta_buf[pi_delta++];
            uint8_t  delta = delta_buf[pi_delta++];
            uint32_t off   = (uint32_t)off_lo_buf_d[pi_off_lo];
            off |= (uint32_t)off_hi_buf_d[pi_off_hi] << 8;
            off |= (uint32_t)off_hi_buf_d[pi_off_hi + 1] << 16;
            pi_off_lo++; pi_off_hi += 2;
            uint32_t len   = read_u16(len_buf + pi_len) + ZXL_MIN_MATCH; pi_len += 2;
            if (out_pos < off || out_pos + len > out_end) break;
            const uint8_t *ref = dst + out_pos - off;
            if (mtype == MTYPE_XOR) {
                for (uint32_t k = 0; k < len; k++) dst[out_pos + k] = ref[k] ^ delta;
            } else {
                for (uint32_t k = 0; k < len; k++) dst[out_pos + k] = (uint8_t)(ref[k] + delta);
            }
            prev_out = dst[out_pos + len - 1];
            out_pos += len;

        } else if (tok == TOK_DELTA1) {
            uint8_t  mtype = delta_buf[pi_delta++];
            uint8_t  delta = delta_buf[pi_delta++];
            uint32_t off   = off_lo_buf_d[pi_off_lo++];
            uint32_t len   = (uint32_t)len_buf[pi_len++] + ZXL_MIN_MATCH;
            if (out_pos < off || out_pos + len > out_end) break;
            const uint8_t *ref = dst + out_pos - off;
            if (mtype == MTYPE_XOR) {
                for (uint32_t k = 0; k < len; k++) dst[out_pos + k] = ref[k] ^ delta;
            } else {
                for (uint32_t k = 0; k < len; k++) dst[out_pos + k] = (uint8_t)(ref[k] + delta);
            }
            prev_out = dst[out_pos + len - 1];
            out_pos += len;

        } else if (tok == TOK_DELTA2) {
            uint8_t  mtype = delta_buf[pi_delta++];
            uint8_t  delta = delta_buf[pi_delta++];
            uint32_t off   = (uint32_t)off_lo_buf_d[pi_off_lo++]
                           | ((uint32_t)off_hi_buf_d[pi_off_hi++] << 8);
            uint32_t len   = (uint32_t)len_buf[pi_len++] + ZXL_MIN_MATCH;
            if (out_pos < off || out_pos + len > out_end) break;
            const uint8_t *ref = dst + out_pos - off;
            if (mtype == MTYPE_XOR) {
                for (uint32_t k = 0; k < len; k++) dst[out_pos + k] = ref[k] ^ delta;
            } else {
                for (uint32_t k = 0; k < len; k++) dst[out_pos + k] = (uint8_t)(ref[k] + delta);
            }
            prev_out = dst[out_pos + len - 1];
            out_pos += len;

        } else {
            /* Literal run (tok in 0x00..0xF6, run=tok+1): pull from context sub-stream */
            uint32_t run = (uint32_t)tok + 1;
            if (out_pos + run > out_end) break;
            if (!rd_ok) break;
            for (uint32_t k = 0; k < run; k++) {
                uint8_t b = (uint8_t)zxl_ac_dec_byte(&rd, lit_probs[prev_out]);
                dst[out_pos + k] = b;
                prev_out = b;
            }
            out_pos += run;
        }
    }

    FREE2BUF;
    #undef FREE2BUF
    if (off_lo_buf_d) free(off_lo_buf_d);
    if (off_hi_buf_d) free(off_hi_buf_d);
    if (delta_buf) free(delta_buf);
    if (len_buf)   free(len_buf);
    free(lit_probs);

    *consumed = hdr_consumed + opcode_am_size + opcode_al_size
                    + off_lo_size + off_hi_size + delta_size + len_size + lit_ac_size;
    return out_pos - global_out_pos;
}

/* ------------------------------------------------------------------ */
/* Public compress / decompress                                        */
/* ------------------------------------------------------------------ */

int zxl_compress(const uint8_t *src, size_t src_len,
                 uint8_t *dst,       size_t dst_cap, size_t *dst_len)
{
    if (dst_cap < 16) return -1;

    /*
     * BCJ pre-filter: if the input looks like an x86 PE binary ("MZ" magic),
     * transform all E8/E9 relative call/jump addresses to absolute addresses.
     * Call sites to the same function then have identical 4-byte address fields,
     * giving the LZ engine vastly more exact-match opportunities.
     */
    uint32_t flags = 0;
    const uint8_t *work = src;
    uint8_t *bcj_buf = NULL;
    if (src_len >= 2 && src[0] == 0x4Du && src[1] == 0x5Au) {  /* "MZ" */
        bcj_buf = (uint8_t *)malloc(src_len);
        if (bcj_buf) {
            memcpy(bcj_buf, src, src_len);
            bcj_x64_forward(bcj_buf, src_len);  /* x64 RIP-relative first */
            bcj_x86_forward(bcj_buf, src_len);  /* then x86 E8/E9/Jcc */
            iat_forward(bcj_buf, src_len);      /* C2: IAT delta filter */
            work  = bcj_buf;
            flags = ZXL_FLAG_BCJ | ZXL_FLAG_BCJ64 | ZXL_FLAG_IAT;
        }
    }

    uint8_t *p   = dst;
    uint8_t *end = dst + dst_cap;

    /* File header: magic + original size + flags */
    write_u32(p, ZXL_MAGIC);          p += 4;
    write_u64(p, (uint64_t)src_len);  p += 8;
    write_u32(p, flags);              p += 4;

    /* One MatchCtx persists across all blocks so the 1 MB window
     * lets later blocks reference data from earlier blocks. */
    MatchCtx *ctx = (MatchCtx *)malloc(sizeof(MatchCtx));
    if (!ctx) { free(bcj_buf); return -1; }
    match_ctx_init(ctx);

    /* B5: PE section-boundary splits. Each returned offset starts a
     * section; forcing a block split there lets the block's rANS tables
     * specialize to one section's statistics. */
    #define ZXL_MAX_PE_SPLITS 96
    #define ZXL_B5_MIN_BLOCK  (512u * 1024u)  /* guard: don't split if result < 512 KB */
    size_t pe_splits[ZXL_MAX_PE_SPLITS];
    size_t n_pe_splits = pe_section_splits(src, src_len, pe_splits, ZXL_MAX_PE_SPLITS);
    size_t next_split_idx = 0;

    size_t in_pos = 0;
    while (in_pos < src_len) {
        size_t block_end = in_pos + ZXL_BLOCK_SIZE;
        if (block_end > src_len) block_end = src_len;

        /* B5: find the earliest PE section boundary in (in_pos, block_end)
         * that yields a block of at least ZXL_B5_MIN_BLOCK on both sides.
         * Splits too close to in_pos or block_end are skipped (not useful)
         * but don't disqualify later splits in the same range. */
        while (next_split_idx < n_pe_splits && pe_splits[next_split_idx] <= in_pos)
            next_split_idx++;
        for (size_t _si = next_split_idx; _si < n_pe_splits; _si++) {
            size_t sp = pe_splits[_si];
            if (sp >= block_end) break;
            if ((sp - in_pos) >= ZXL_B5_MIN_BLOCK
                && (block_end - sp) >= ZXL_B5_MIN_BLOCK) {
                block_end = sp;
                break;
            }
        }

        size_t room = (size_t)(end - p);
        if (room < 16) { free(ctx); free(bcj_buf); return -1; }

        /* Reserve 4 bytes for block compressed size */
        uint8_t *blk_size_p = p; p += 4;

        size_t written = compress_block(ctx, work, in_pos, block_end,
                                        p, (size_t)(end - p));
        if (!written) { free(ctx); free(bcj_buf); return -1; }

        write_u32(blk_size_p, (uint32_t)written);
        p += written;
        in_pos = block_end;
    }

    free(ctx);
    free(bcj_buf);
    *dst_len = (size_t)(p - dst);
    return 0;
}

int zxl_decompress(const uint8_t *src, size_t src_len,
                   uint8_t *dst,       size_t dst_cap, size_t *dst_len)
{
    if (src_len < 16) return -1;

    uint32_t magic     = read_u32(src);
    if (magic != ZXL_MAGIC) return -1;

    uint64_t orig_size = read_u64(src + 4);
    uint32_t flags     = read_u32(src + 12);
    if (orig_size > dst_cap) return -1;

    const uint8_t *p   = src + 16;
    const uint8_t *end = src + src_len;
    size_t out_pos = 0;

    while (p < end) {
        if (p + 4 > end) return -1;
        uint32_t blk_comp = read_u32(p); p += 4;
        if (p + blk_comp > end) return -1;

        size_t consumed = 0;
        size_t wrote = decompress_block(p, blk_comp,
                                        dst, dst_cap,
                                        out_pos,
                                        &consumed);
        if (!wrote && blk_comp > 0) return -1;
        out_pos += wrote;
        p += blk_comp;
    }

    /* Undo filters in reverse order of application (IAT → BCJ_x86 → BCJ_x64). */
    if (flags & ZXL_FLAG_IAT)
        iat_inverse(dst, out_pos);
    if (flags & ZXL_FLAG_BCJ)
        bcj_x86_inverse(dst, out_pos);
    if (flags & ZXL_FLAG_BCJ64)
        bcj_x64_inverse(dst, out_pos);

    *dst_len = out_pos;
    return 0;
}
