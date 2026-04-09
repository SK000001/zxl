/*
 * ZXL - rANS Entropy Coder
 *
 * rANS (range Asymmetric Numeral Systems) by Jarek Duda.
 * Faster decode than Huffman, near-arithmetic compression ratio.
 *
 * Parameters:
 *   Scale bits : 12  (frequencies sum to 4096)
 *   State      : 32-bit, range [RANS_L, RANS_L<<8)
 *   Renorm     : one byte at a time
 */
#ifndef ZXL_RANS_H
#define ZXL_RANS_H

#include <stdint.h>
#include <stddef.h>

#define RANS_SCALE_BITS 12
#define RANS_SCALE      (1u << RANS_SCALE_BITS)   /* 4096 */
#define RANS_L          (1u << 23)                 /* lower bound of state */

/* Per-symbol encode info */
typedef struct {
    uint16_t freq;   /* normalised frequency (sums to RANS_SCALE) */
    uint16_t cumul;  /* cumulative freq of all symbols < this one */
} RansSym;

/* Per-slot decode info (one entry per slot in [0, RANS_SCALE)) */
typedef struct {
    uint8_t  sym;    /* which symbol this slot belongs to */
    uint16_t freq;   /* symbol's frequency                */
    uint16_t bias;   /* = cumul (subtracted during decode)*/
} RansSlot;

/*
 * Build encode table (syms[256]) and decode table (slots[RANS_SCALE])
 * from raw counts[256].  Counts of zero are inflated to 1 so every
 * symbol remains representable.
 */
void rans_build_tables(const uint32_t counts[256],
                       RansSym  syms [256],
                       RansSlot slots[RANS_SCALE]);

/*
 * Encode src[0..src_len) into dst[].
 * dst must be at least zxl_bound(src_len) bytes.
 * Returns number of bytes written, or 0 on error.
 *
 * NOTE: the encoded stream is written BACKWARD into dst (standard rANS),
 * then reversed in-place before returning.
 */
size_t rans_encode(const uint8_t *src, size_t src_len,
                   const RansSym syms[256],
                   uint8_t *dst, size_t dst_cap);

/*
 * Decode src[0..src_len) into dst[0..dst_len).
 * Returns 0 on success, -1 on error.
 */
int rans_decode(const uint8_t *src, size_t src_len,
                const RansSlot slots[RANS_SCALE],
                uint8_t *dst, size_t dst_len);

#endif /* ZXL_RANS_H */
