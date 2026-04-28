/* ZXL adaptive binary range coder.
 * LZMA-style: 11-bit prob precision, MOVE_BITS=5 update.
 * prob[i] represents P(bit=0) scaled to [0, 2048]. */

#ifndef ZXL_AC_H
#define ZXL_AC_H

#include <stdint.h>
#include <stddef.h>

#define ZXL_AC_PROB_BITS  11
#define ZXL_AC_PROB_TOTAL (1u << ZXL_AC_PROB_BITS)   /* 2048 */
#define ZXL_AC_PROB_INIT  (ZXL_AC_PROB_TOTAL >> 1)   /* 1024 = 50% */
#define ZXL_AC_MOVE_BITS  5

typedef uint16_t zxl_ac_prob;

/* Encoder state. Carry-style range coder using LZMA's cache mechanism. */
typedef struct {
    uint32_t  range;
    uint64_t  low;          /* 33-bit logical state via cache */
    uint64_t  cache_size;   /* number of pending 0xFF bytes (and one cache byte) */
    uint8_t   cache;
    uint8_t  *out;
    size_t    out_pos;
    size_t    out_cap;
    int       overflow;     /* set if writes would exceed out_cap */
} zxl_ac_enc;

/* Decoder state. */
typedef struct {
    uint32_t       range;
    uint32_t       code;
    const uint8_t *src;
    size_t         src_pos;
    size_t         src_len;
} zxl_ac_dec;

/* ---- Encoder ----------------------------------------------------- */
void   zxl_ac_enc_init(zxl_ac_enc *e, uint8_t *out, size_t out_cap);
void   zxl_ac_enc_bit (zxl_ac_enc *e, zxl_ac_prob *p, unsigned bit);
size_t zxl_ac_enc_finish(zxl_ac_enc *e);   /* returns bytes written, 0 on overflow */

/* Bit-tree encode an 8-bit symbol. probs must point to >= 256 zxl_ac_probs.
 * Uses indices 1..255 (LZMA-style bit tree). */
void   zxl_ac_enc_byte(zxl_ac_enc *e, zxl_ac_prob *probs256, unsigned sym);

/* ---- Decoder ----------------------------------------------------- */
int      zxl_ac_dec_init(zxl_ac_dec *d, const uint8_t *src, size_t src_len);  /* 0 ok */
unsigned zxl_ac_dec_bit (zxl_ac_dec *d, zxl_ac_prob *p);
unsigned zxl_ac_dec_byte(zxl_ac_dec *d, zxl_ac_prob *probs256);

#endif
