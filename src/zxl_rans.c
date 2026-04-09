/*
 * ZXL - rANS Entropy Coder Implementation
 *
 * Reference: Fabian Giesen "Simple rANS" (public domain ryg_rans)
 * Adapted and extended for ZXL's multi-stream block format.
 */
#include "zxl_rans.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

/* ------------------------------------------------------------------ */
/* Table construction                                                   */
/* ------------------------------------------------------------------ */

void rans_build_tables(const uint32_t counts[256],
                       RansSym  syms [256],
                       RansSlot slots[RANS_SCALE])
{
    /* Step 1: inflate zeros and compute total */
    uint32_t inflated[256];
    uint64_t total = 0;
    for (int i = 0; i < 256; i++) {
        inflated[i] = counts[i] ? counts[i] : 1u;
        total += inflated[i];
    }

    /* Step 2: normalise to RANS_SCALE using largest-remainder method */
    uint32_t norm[256];
    uint64_t allocated = 0;
    for (int i = 0; i < 256; i++) {
        norm[i] = (uint32_t)(((uint64_t)inflated[i] * RANS_SCALE) / total);
        if (norm[i] == 0) norm[i] = 1;  /* floor-to-1 */
        allocated += norm[i];
    }

    /* Distribute rounding error to the most frequent symbol */
    int64_t diff = (int64_t)RANS_SCALE - (int64_t)allocated;
    if (diff != 0) {
        uint32_t best = 0;
        for (int i = 1; i < 256; i++)
            if (inflated[i] > inflated[best]) best = i;
        norm[best] = (uint32_t)((int32_t)norm[best] + (int32_t)diff);
    }

    /* Step 3: fill encode table */
    uint32_t cumul = 0;
    for (int i = 0; i < 256; i++) {
        syms[i].freq  = (uint16_t)norm[i];
        syms[i].cumul = (uint16_t)cumul;
        cumul += norm[i];
    }
    assert(cumul == RANS_SCALE);

    /* Step 4: fill decode table (one slot per frequency unit) */
    uint32_t slot = 0;
    for (int i = 0; i < 256; i++) {
        for (uint32_t j = 0; j < norm[i]; j++) {
            slots[slot].sym   = (uint8_t)i;
            slots[slot].freq  = (uint16_t)norm[i];
            slots[slot].bias  = (uint16_t)(syms[i].cumul);
            slot++;
        }
    }
    assert(slot == RANS_SCALE);
}

/* ------------------------------------------------------------------ */
/* Encoder                                                             */
/* ------------------------------------------------------------------ */

/*
 * rANS encode one symbol into state x, flushing bytes to ptr (backward).
 * x must be in [RANS_L, RANS_L<<8) on entry and exit.
 */
static inline void rans_enc_put(uint32_t *x, uint8_t **ptr,
                                 uint16_t freq, uint16_t cumul)
{
    /* Renormalise: emit bytes until x fits in the pre-encode range */
    uint32_t x_max = (RANS_L >> RANS_SCALE_BITS) * freq;  /* = RANS_L*freq/RANS_SCALE */
    uint32_t s = *x;
    while (s >= (x_max << 8)) {   /* keep shifting until s < x_max<<8 */
        *--(*ptr) = (uint8_t)(s & 0xFF);
        s >>= 8;
    }
    /* Encode */
    *x = ((s / freq) << RANS_SCALE_BITS) + (s % freq) + cumul;
}

size_t rans_encode(const uint8_t *src, size_t src_len,
                   const RansSym syms[256],
                   uint8_t *dst, size_t dst_cap)
{
    if (dst_cap < src_len + 16) return 0;

    /*
     * We write encoded bytes BACKWARD into a temporary buffer, then
     * flush the final state (4 bytes) and reverse everything.
     * Use the end of dst as scratch to avoid extra allocation.
     */
    uint8_t *end = dst + dst_cap;
    uint8_t *ptr = end;               /* grows downward */

    uint32_t x = RANS_L;

    /* Encode symbols in reverse order (rANS is a stack) */
    for (size_t i = src_len; i-- > 0; ) {
        uint8_t  sym  = src[i];
        uint16_t freq  = syms[sym].freq;
        uint16_t cumul = syms[sym].cumul;
        rans_enc_put(&x, &ptr, freq, cumul);
        if (ptr < dst + 4) return 0;   /* overflow */
    }

    /* Flush final state (little-endian 32-bit) */
    ptr -= 4;
    ptr[0] = (uint8_t)(x      );
    ptr[1] = (uint8_t)(x >>  8);
    ptr[2] = (uint8_t)(x >> 16);
    ptr[3] = (uint8_t)(x >> 24);

    size_t enc_len = (size_t)(end - ptr);

    /* Move to front of dst. The bytes are already in forward decode order
     * (encoding goes backward, so the first-decoded symbol's renorm bytes
     * land at the lowest addresses, right after the state header). */
    memmove(dst, ptr, enc_len);

    return enc_len;
}

/* ------------------------------------------------------------------ */
/* Decoder                                                             */
/* ------------------------------------------------------------------ */

static inline uint32_t rans_dec_advance(uint32_t x, const RansSlot *slot,
                                        const uint8_t **ptr, const uint8_t *end)
{
    /* Decode step */
    x = (uint32_t)slot->freq * (x >> RANS_SCALE_BITS)
        + (x & (RANS_SCALE - 1))
        - slot->bias;

    /* Renormalise: refill bytes until x >= RANS_L */
    while (x < RANS_L && *ptr < end) {
        x = (x << 8) | *(*ptr)++;
    }
    return x;
}

int rans_decode(const uint8_t *src, size_t src_len,
                const RansSlot slots[RANS_SCALE],
                uint8_t *dst, size_t dst_len)
{
    if (src_len < 4) return -1;

    /* Read initial state (little-endian 32-bit) */
    uint32_t x = (uint32_t)src[0]
               | ((uint32_t)src[1] <<  8)
               | ((uint32_t)src[2] << 16)
               | ((uint32_t)src[3] << 24);

    const uint8_t *ptr = src + 4;
    const uint8_t *end = src + src_len;

    for (size_t i = 0; i < dst_len; i++) {
        uint32_t slot_idx = x & (RANS_SCALE - 1);
        const RansSlot *sl = &slots[slot_idx];
        dst[i] = sl->sym;
        x = rans_dec_advance(x, sl, &ptr, end);
    }

    return 0;
}
