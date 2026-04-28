/* ZXL adaptive binary range coder. See zxl_ac.h. */

#include "zxl_ac.h"
#include <string.h>

/* ---- Encoder ----------------------------------------------------- */

void zxl_ac_enc_init(zxl_ac_enc *e, uint8_t *out, size_t out_cap) {
    e->range      = 0xFFFFFFFFu;
    e->low        = 0;
    e->cache_size = 1;
    e->cache      = 0;
    e->out        = out;
    e->out_pos    = 0;
    e->out_cap    = out_cap;
    e->overflow   = 0;
}

static void rc_shift_low(zxl_ac_enc *e) {
    /* If the top of `low` (bit 32 of the 33-bit state) is set or stable,
     * flush cached bytes (with carry propagated). */
    if ((uint32_t)e->low < 0xFF000000u || (e->low >> 32) != 0) {
        uint8_t carry = (uint8_t)(e->low >> 32);
        uint8_t b = (uint8_t)(e->cache + carry);
        for (uint64_t i = 0; i < e->cache_size; i++) {
            if (e->out_pos >= e->out_cap) { e->overflow = 1; return; }
            e->out[e->out_pos++] = b;
            b = 0xFFu + carry;
        }
        e->cache = (uint8_t)((uint32_t)e->low >> 24);
        e->cache_size = 0;
    }
    e->cache_size++;
    e->low = ((uint32_t)e->low) << 8;
}

void zxl_ac_enc_bit(zxl_ac_enc *e, zxl_ac_prob *p, unsigned bit) {
    uint32_t prob = *p;
    uint32_t bound = (e->range >> ZXL_AC_PROB_BITS) * prob;
    if (bit == 0) {
        e->range = bound;
        *p = (zxl_ac_prob)(prob + ((ZXL_AC_PROB_TOTAL - prob) >> ZXL_AC_MOVE_BITS));
    } else {
        e->low  += bound;
        e->range -= bound;
        *p = (zxl_ac_prob)(prob - (prob >> ZXL_AC_MOVE_BITS));
    }
    while (e->range < (1u << 24)) {
        e->range <<= 8;
        rc_shift_low(e);
    }
}

void zxl_ac_enc_byte(zxl_ac_enc *e, zxl_ac_prob *probs, unsigned sym) {
    unsigned pos = 1;
    /* MSB-first bit tree; matches the decoder. */
    for (int i = 7; i >= 0; i--) {
        unsigned bit = (sym >> i) & 1u;
        zxl_ac_enc_bit(e, &probs[pos], bit);
        pos = (pos << 1) | bit;
    }
}

size_t zxl_ac_enc_finish(zxl_ac_enc *e) {
    for (int i = 0; i < 5; i++) rc_shift_low(e);
    if (e->overflow) return 0;
    return e->out_pos;
}

/* ---- Decoder ----------------------------------------------------- */

int zxl_ac_dec_init(zxl_ac_dec *d, const uint8_t *src, size_t src_len) {
    d->src     = src;
    d->src_pos = 0;
    d->src_len = src_len;
    d->range   = 0xFFFFFFFFu;
    d->code    = 0;
    if (src_len < 5) return -1;
    /* First byte is discarded (LZMA convention: encoder's initial cache is 0). */
    d->src_pos = 1;
    for (int i = 0; i < 4; i++) {
        d->code = (d->code << 8) | d->src[d->src_pos++];
    }
    return 0;
}

unsigned zxl_ac_dec_bit(zxl_ac_dec *d, zxl_ac_prob *p) {
    uint32_t prob = *p;
    uint32_t bound = (d->range >> ZXL_AC_PROB_BITS) * prob;
    unsigned bit;
    if (d->code < bound) {
        d->range = bound;
        *p = (zxl_ac_prob)(prob + ((ZXL_AC_PROB_TOTAL - prob) >> ZXL_AC_MOVE_BITS));
        bit = 0;
    } else {
        d->code -= bound;
        d->range -= bound;
        *p = (zxl_ac_prob)(prob - (prob >> ZXL_AC_MOVE_BITS));
        bit = 1;
    }
    while (d->range < (1u << 24)) {
        d->range <<= 8;
        d->code = (d->code << 8) | (d->src_pos < d->src_len ? d->src[d->src_pos] : 0);
        if (d->src_pos < d->src_len) d->src_pos++;
    }
    return bit;
}

unsigned zxl_ac_dec_byte(zxl_ac_dec *d, zxl_ac_prob *probs) {
    unsigned pos = 1;
    for (int i = 0; i < 8; i++) {
        unsigned bit = zxl_ac_dec_bit(d, &probs[pos]);
        pos = (pos << 1) | bit;
    }
    return pos & 0xFFu;
}
