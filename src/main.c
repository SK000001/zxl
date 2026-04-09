/*
 * ZXL - Command Line Tool
 *
 * Usage:
 *   zxl c <input> <output>    compress
 *   zxl d <input> <output>    decompress
 *   zxl t <input>             test round-trip (compress+decompress, verify)
 *   zxl b <input>             benchmark (ratio + speed)
 */
#include "zxl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* File helpers                                                        */
/* ------------------------------------------------------------------ */

static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "Cannot open: %s\n", path); return NULL; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f); free(buf); return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "Cannot write: %s\n", path); return -1; }
    if (fwrite(data, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Timer                                                               */
/* ------------------------------------------------------------------ */

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

static int cmd_compress(const char *in_path, const char *out_path)
{
    size_t src_len;
    uint8_t *src = read_file(in_path, &src_len);
    if (!src) return 1;

    size_t dst_cap = zxl_bound(src_len);
    uint8_t *dst   = (uint8_t *)malloc(dst_cap);
    if (!dst) { free(src); return 1; }

    double t0 = now_ms();
    size_t dst_len = 0;
    int rc = zxl_compress(src, src_len, dst, dst_cap, &dst_len);
    double t1 = now_ms();

    if (rc != 0) {
        fprintf(stderr, "Compression failed\n");
        free(src); free(dst); return 1;
    }

    if (write_file(out_path, dst, dst_len) != 0) {
        free(src); free(dst); return 1;
    }

    double ratio = (src_len > 0) ? (double)dst_len / (double)src_len : 1.0;
    double speed = (src_len > 0 && t1 > t0)
                   ? (double)src_len / (t1 - t0) / 1000.0 : 0.0;

    printf("Compressed  : %s\n", in_path);
    printf("Input       : %llu bytes\n", (unsigned long long)src_len);
    printf("Output      : %llu bytes\n", (unsigned long long)dst_len);
    printf("Ratio       : %.4f  (%.2f%%)\n", ratio, ratio * 100.0);
    printf("Speed       : %.1f MB/s\n", speed);

    free(src); free(dst);
    return 0;
}

static int cmd_decompress(const char *in_path, const char *out_path)
{
    size_t src_len;
    uint8_t *src = read_file(in_path, &src_len);
    if (!src) return 1;

    /* Allocate generously for decompressed output */
    size_t dst_cap = src_len * 8 + (1 << 20);
    uint8_t *dst   = (uint8_t *)malloc(dst_cap);
    if (!dst) { free(src); return 1; }

    double t0 = now_ms();
    size_t dst_len = 0;
    int rc = zxl_decompress(src, src_len, dst, dst_cap, &dst_len);
    double t1 = now_ms();

    if (rc != 0) {
        fprintf(stderr, "Decompression failed\n");
        free(src); free(dst); return 1;
    }

    if (write_file(out_path, dst, dst_len) != 0) {
        free(src); free(dst); return 1;
    }

    double speed = (dst_len > 0 && t1 > t0)
                   ? (double)dst_len / (t1 - t0) / 1000.0 : 0.0;

    printf("Decompressed: %s\n", in_path);
    printf("Output      : %llu bytes\n", (unsigned long long)dst_len);
    printf("Speed       : %.1f MB/s\n", speed);

    free(src); free(dst);
    return 0;
}

static int cmd_test(const char *in_path)
{
    size_t src_len;
    uint8_t *src = read_file(in_path, &src_len);
    if (!src) return 1;

    size_t cmp_cap = zxl_bound(src_len);
    uint8_t *cmp   = (uint8_t *)malloc(cmp_cap);
    uint8_t *dec   = (uint8_t *)malloc(src_len + 64);
    if (!cmp || !dec) { free(src); free(cmp); free(dec); return 1; }

    size_t cmp_len = 0;
    if (zxl_compress(src, src_len, cmp, cmp_cap, &cmp_len) != 0) {
        fprintf(stderr, "Compression failed\n");
        free(src); free(cmp); free(dec); return 1;
    }

    size_t dec_len = 0;
    if (zxl_decompress(cmp, cmp_len, dec, src_len + 64, &dec_len) != 0) {
        fprintf(stderr, "Decompression failed\n");
        free(src); free(cmp); free(dec); return 1;
    }

    if (dec_len != src_len || memcmp(src, dec, src_len) != 0) {
        fprintf(stderr, "MISMATCH: round-trip failed!\n");
        free(src); free(cmp); free(dec); return 1;
    }

    double ratio = (src_len > 0) ? (double)cmp_len / (double)src_len : 1.0;
    printf("Round-trip  : OK\n");
    printf("Input       : %llu bytes\n", (unsigned long long)src_len);
    printf("Compressed  : %llu bytes  (%.2f%%)\n", (unsigned long long)cmp_len, ratio * 100.0);

    free(src); free(cmp); free(dec);
    return 0;
}

static int cmd_bench(const char *in_path)
{
    size_t src_len;
    uint8_t *src = read_file(in_path, &src_len);
    if (!src) return 1;

    size_t cmp_cap = zxl_bound(src_len);
    uint8_t *cmp   = (uint8_t *)malloc(cmp_cap);
    uint8_t *dec   = (uint8_t *)malloc(src_len + 64);
    if (!cmp || !dec) { free(src); free(cmp); free(dec); return 1; }

    /* Warm-up */
    size_t cmp_len = 0;
    zxl_compress(src, src_len, cmp, cmp_cap, &cmp_len);

    /* Compress benchmark: 3 runs */
    double c_best = 1e18;
    for (int r = 0; r < 3; r++) {
        double t0 = now_ms();
        zxl_compress(src, src_len, cmp, cmp_cap, &cmp_len);
        double t1 = now_ms();
        if (t1 - t0 < c_best) c_best = t1 - t0;
    }

    /* Decompress benchmark: 3 runs */
    double d_best = 1e18;
    size_t dec_len = 0;
    for (int r = 0; r < 3; r++) {
        double t0 = now_ms();
        zxl_decompress(cmp, cmp_len, dec, src_len + 64, &dec_len);
        double t1 = now_ms();
        if (t1 - t0 < d_best) d_best = t1 - t0;
    }

    double ratio = (double)cmp_len / (double)src_len;
    double c_spd = (double)src_len / c_best / 1000.0;
    double d_spd = (double)src_len / d_best / 1000.0;

    printf("File        : %s  (%llu bytes)\n", in_path, (unsigned long long)src_len);
    printf("Compressed  : %llu bytes\n", (unsigned long long)cmp_len);
    printf("Ratio       : %.4f  (%.2f%%)\n", ratio, ratio * 100.0);
    printf("Compress    : %.1f MB/s\n", c_spd);
    printf("Decompress  : %.1f MB/s\n", d_spd);

    free(src); free(cmp); free(dec);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr,
            "ZXL Binary Compressor\n"
            "Usage:\n"
            "  zxl c <input> <output>   compress\n"
            "  zxl d <input> <output>   decompress\n"
            "  zxl t <input>            round-trip test\n"
            "  zxl b <input>            benchmark\n");
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "c") == 0 && argc >= 4)
        return cmd_compress(argv[2], argv[3]);
    if (strcmp(cmd, "d") == 0 && argc >= 4)
        return cmd_decompress(argv[2], argv[3]);
    if (strcmp(cmd, "t") == 0)
        return cmd_test(argv[2]);
    if (strcmp(cmd, "b") == 0)
        return cmd_bench(argv[2]);

    fprintf(stderr, "Unknown command: %s\n", cmd);
    return 1;
}
