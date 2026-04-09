/*
 * ZXL - Novel Binary Compression
 * Public API
 */
#ifndef ZXL_H
#define ZXL_H

#include <stdint.h>
#include <stddef.h>

/* Returns upper bound on compressed output size */
size_t zxl_bound(size_t src_len);

/* Compress src -> dst. Returns 0 on success, -1 on error. */
int zxl_compress(const uint8_t *src, size_t src_len,
                 uint8_t *dst,       size_t dst_cap, size_t *dst_len);

/* Decompress src -> dst. Returns 0 on success, -1 on error. */
int zxl_decompress(const uint8_t *src, size_t src_len,
                   uint8_t *dst,       size_t dst_cap, size_t *dst_len);

#endif /* ZXL_H */
