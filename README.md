# ZXL

A lossless binary compression codec tuned for x86/x64 PE executables. Written in C, no external dependencies.

Beats gzip-9, zstd-9, and bzip2-9 on every PE benchmark file. Within 1 pt of zstd-19 on ntdll.dll.

## Current benchmarks (post D1.5, 2026-04-25)

| File         | Size    | ZXL    | gzip-9 | zstd-9 | bzip2-9 | zstd-19 | xz-9e  |
|--------------|--------:|-------:|-------:|-------:|--------:|--------:|-------:|
| ntdll.dll    | 2.52 MB | **0.4098** | 0.4596 | 0.4442 | 0.4346 | 0.4013 | 0.3772 |
| kernel32.dll | 836 KB  | **0.4236** | 0.4574 | 0.4455 | 0.4416 | 0.4024 | 0.3785 |
| user32.dll   | 1.87 MB | **0.3419** | 0.3852 | 0.3630 | 0.3651 | 0.3312 | 0.3065 |

Ratios shown as compressed / original (lower is better).

## Build & Run

```bash
make              # Build ./zxl.exe (gcc -O3 -march=native)
make clean        # Remove build artifacts
bash tests/bench.sh  # Bench vs gzip-9 / zstd-9 with round-trip check
```

CLI:

```bash
./zxl.exe c <input> <output>   # Compress
./zxl.exe d <input> <output>   # Decompress
./zxl.exe t <input>            # Round-trip test
./zxl.exe b <input>            # Benchmark (ratio + MB/s)
```

Requires a C11 compiler with AVX2/SSE2 (`-march=native`) and `-lm`.

## Design

### Match finding
- Five hash chains, all sharing the same 512 K-bucket hash table: **exact** (4-byte), **XOR-delta** (4-byte first-differences under XOR), **additive-delta** (4-byte first-differences under subtraction), **short** (3-byte for local TOK_EXACT0 matches), **long** (8-byte for high-quality long-match candidates). Chain depth 256.
- **B1 binary-tree match finder** (LZMA BT4-style, additive candidate) alongside the chains.
- `match_find()` returns up to 6 candidates per position: best-savings match, shortest viable match, best small-offset (EXACT1), best mid-offset (EXACT2), longest-any, best 3-byte short. All feed the DP.
- AVX2 (32-byte) or SSE2 (16-byte) SIMD for match extension.

### Parsing
- **4-pass entropy-weighted DP optimal parser.** Each pass refines token-cost estimates using the previous pass's observed frequencies. Tries 20+ candidate lengths per match and for REP tokens.

### Token format
13 token types (single-byte opcode + variable-size parameters):

| Byte  | Token      | Parameters                                   | Notes |
|-------|------------|----------------------------------------------|-------|
| 0x00..0xF3 | literal run | —                                       | run length = byte + 1 (1–244) |
| 0xF4  | TOK_EXACT0 | off[1]                                       | 3-byte exact, implicit length, no REP update |
| 0xF5  | TOK_REP3   | lbuf[1]                                      | reuse 4th-last offset |
| 0xF6  | TOK_REP4   | lbuf[1]                                      | reuse 5th-last offset |
| 0xF7  | TOK_EXACT1 | off[1], lbuf[1]                              | off<256, 4..259 bytes |
| 0xF8  | TOK_EXACT2 | off[2], lbuf[1]                              | off<65536, 4..259 bytes |
| 0xF9  | TOK_DELTA1 | mtype[1], delta[1], off[1], lbuf[1]          | XOR/ADD delta match, off<256 |
| 0xFA  | TOK_DELTA2 | mtype[1], delta[1], off[2], lbuf[1]          | delta match, off<65536 |
| 0xFB  | TOK_REP0   | lbuf[1]                                      | reuse last offset |
| 0xFC  | TOK_REP1   | lbuf[1]                                      | reuse 2nd-last offset |
| 0xFD  | TOK_REP2   | lbuf[1]                                      | reuse 3rd-last offset |
| 0xFE  | TOK_EXACT  | off[3], lbuf[2]                              | large offset or length ≥ 260 |
| 0xFF  | TOK_DELTA  | mtype[1], delta[1], off[3], lbuf[2]          | large delta match |

### Entropy coding
- Range-ANS (rANS, Fabian Giesen's "Simple rANS"). Freq tables normalised to sum 16384 (scale bits = 14).
- **22 independent rANS streams per block**: 2 opcode contexts (after-match / after-literal), off_lo, off_hi, delta, length, and 16 context-coded literal sub-streams (context = `prev_out >> 4`).
- **D1 compact freq tables**: 32-byte bitmap of nonzero entries + varint-encoded freqs (1 byte for f<128, 2 bytes for f<16384). Cuts per-block header from ~10.5 KB raw to ~3 KB.
- **D1.5 rank-1 factored freq tables**: per-table encoder choice. When a 256-bin distribution factors well in (high-nibble, low-nibble) coordinates, ship 16 row + 16 col marginals (~40 B) and reconstruct via outer product, instead of dense compact (~150 B). Encoder compares header + analytical coding cost under each model, picks smaller. Preceded by a one-byte mode flag. Cut small-file ratios by 1–3 pts.

### Pre-filters (applied to MZ-magic inputs only)
- **x64 RIP-relative BCJ**: `MOV/LEA/CMP [rip+disp32]` + SSE/CMOV variants → absolute addresses.
- **x86 BCJ**: E8/E9 CALL/JMP and 0F 80..8F Jcc near jumps → absolute addresses.
- **C2 IAT delta filter**: runs of ≥80 consecutive 8-byte-aligned entries where `byte[7]==0 && byte[6]==0 && byte[5]<=0x7F` get their low 5 bytes XOR-chained with their predecessor. Targets 64-bit import/vtable pointer tables.
- **B5 PE section-aware blocks**: parses the PE section table and forces block splits at section starts (guarded by a 512 KB min-block floor) so each block's freq tables specialize to one section's statistics (.text / .rdata / .data / ...) rather than averaging across regimes.

### Block layout
- 4 MB blocks (or smaller at forced section boundaries); persistent 2 MB window across blocks; raw fallback if compression expands the block.
- Each block carries its own full set of rANS freq tables (compact-encoded via D1).

## File format

```
File header:
  [4]  Magic "ZXLB" (0x5A584C42)
  [8]  Original size (uint64 LE)
  [4]  Flags: bit 0 = BCJ x86, bit 1 = BCJ x64, bit 2 = IAT filter

Per block:
  [4]  Block compressed size (uint32 LE)
  Block:
    [4×17]       Header fields (uncomp, enc/dec sizes of each stream, etc.)
    [compact]×(6 main + 16 literal)  D1 bitmap+varint freq tables
    [16×4]×2     Compressed + decoded sizes of each literal sub-stream
    [...]        rANS-encoded streams concatenated: am, al, off_lo, off_hi,
                 delta, len, lit[0..15]
    (enc_am == 0 in header signals raw-fallback block)
```

## Source layout

- `src/zxl_codec.c` — Block orchestrator, pre-filters, encode/decode, public API (`zxl_compress`, `zxl_decompress`, `zxl_bound`).
- `src/zxl_match.c` — LZ matching: hash chains, binary tree, SIMD match extension.
- `src/zxl_rans.c` — rANS entropy coder.
- `src/main.c` — CLI.

## Roadmap

See `roadmap.md` for the full forward plan, shipped work, and experimental constraints learned so far.

**Next up:** N_LIT_CTX expansion (16 → 32 or 64), newly viable now that D1.5 slashed per-block header overhead.

## License

MIT.
