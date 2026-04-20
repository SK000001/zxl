# README.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZXL (format name: ZXLB) is a novel binary compression algorithm in C. Its key innovations are:

1. **Three simultaneous LZ matching strategies**: exact matches, XOR-delta matches (for relocated addresses/bit-shifted patterns), and additive-delta matches (for incrementing counters).
2. **LRU-5 repeat-offset (REP) cache**: five recent match offsets are tracked; REP matches encode with just an opcode + 1-byte length, much cheaper than a full offset.
3. **Variable-length token encoding**: six match token variants (EXACT1/2/EXACT, DELTA1/2/DELTA) with 1-, 2-, or 3-byte offsets to minimize parameter bytes.
4. **4-pass optimal parsing (DP)**: backward DP minimises true bit cost; overhead estimates are refined from actual token frequencies across four passes.
5. **x86 BCJ filter**: E8/E9 (CALL/JMP) and Jcc near-branch relative addresses are converted to absolute before compression, exposing many more LZ matches. Applied automatically to MZ (PE) files; flag bit 0 signals its use.
6. **Seven independent rANS entropy streams**: opcodes split by 2-context model (after-match vs. after-literal), offset bytes, delta bytes, length bytes, and 16 context-coded literal sub-streams.

## Build & Run

```bash
make              # Build ./zxl binary (gcc -O3 -march=native)
make clean        # Remove build artifacts
make test         # Round-trip test on ./zxl itself
make bench        # 3x compress + 3x decompress benchmark on ./zxl
```

CLI commands:
```bash
./zxl c <input> <output>   # Compress
./zxl d <input> <output>   # Decompress
./zxl t <input>            # Round-trip test (compress → decompress → verify)
./zxl b <input>            # Benchmark (ratio + MB/s)
```

No external dependencies. Requires GCC with AVX2/SSE2 support (`-march=native`). Links `-lm` for `log2f`.

## Architecture

**Data flow:** `main.c` → `zxl_codec.c` (BCJ filter + block loop) → `zxl_match.c` (matching) + `zxl_rans.c` (entropy coding)

### Modules

**`src/zxl_codec.c`** — Block orchestrator and public API (`zxl_compress`, `zxl_decompress`, `zxl_bound`).
- Applies x86 BCJ forward filter to MZ/PE inputs before compression; inverse on decompression.
- Processes input in **1 MB** blocks with a single `MatchCtx` that persists across blocks (enabling cross-block back-references within the 2 MB window).
- Each block: 4-pass DP → build 7 output streams → rANS-encode each stream independently → write block header + encoded streams. Raw fallback if compression expands the block.

**`src/zxl_match.c`** — LZ matching engine with three independent chained hash tables (one each for exact, XOR-diff, add-diff matching).
- `match_find()` returns up to 6 candidates: best-savings match, shortest viable match, best small-offset match (offset < 256), best mid-offset match (256 ≤ offset < 65536), longest match of any type, and best 3-byte short match (offset < 256, fits TOK_EXACT0). All six feed the DP.
- `match_update()` inserts the current position into all four chains (exact, XOR-delta, additive-delta, and 3-gram short).
- Hash table: **2^19 = 512 K buckets** × 4 chains; chain depth: 2048 for 4-byte chains, 64 for 3-byte short chain; sliding window: **2 MB** (`ZXL_WINDOW = 2^21`); min match: **3 bytes** (via EXACT0), 4 bytes for all other match types; max match: 65535 bytes.
- AVX2 (32-byte) or SSE2 (16-byte) SIMD accelerates match extension.

**`src/zxl_rans.c`** — Range ANS entropy coder (Fabian Giesen's "Simple rANS"). `rans_build_tables()` normalises byte frequencies to sum 4096 (scale bits = 12). Encodes backward then reverses in-place. Used for all seven independent streams per block.

**`src/main.c`** — CLI dispatcher. Reads file, allocates buffers, calls codec, reports ratio and throughput.

### Token Encoding (ZXLB format)

```
Token byte  Payload                             Description
─────────────────────────────────────────────────────────────────────────
0x00..0xF3  (none)                              Literal run; run length = tok+1 (1–244 bytes)
0xF4        off[1]                              TOK_EXACT0: 3-byte exact match, 1-byte offset, implicit length 3
0xF5        lbuf[1]: len-MIN_MATCH              TOK_REP3: reuse 4th-last offset
0xF6        lbuf[1]: len-MIN_MATCH              TOK_REP4: reuse 5th-last offset
0xF7        off[1], lbuf[1]                     TOK_EXACT1: 1-byte offset (1–255), 1-byte len
0xF8        off[2], lbuf[1]                     TOK_EXACT2: 2-byte offset (256–65535), 1-byte len
0xF9        delta[1] mtype, delta[1] val, off[1], lbuf[1]   TOK_DELTA1: 1-byte offset
0xFA        delta[1] mtype, delta[1] val, off[2], lbuf[1]   TOK_DELTA2: 2-byte offset
0xFB        lbuf[1]: len-MIN_MATCH              TOK_REP0: reuse last-used offset
0xFC        lbuf[1]: len-MIN_MATCH              TOK_REP1: reuse 2nd-last offset
0xFD        lbuf[1]: len-MIN_MATCH              TOK_REP2: reuse 3rd-last offset
0xFE        off[3], lbuf[2]                     TOK_EXACT: 3-byte offset, 2-byte len (large)
0xFF        delta[1] mtype, delta[1] val, off[3], lbuf[2]   TOK_DELTA: large offset/len
```

Opcode bytes go to the **opcode stream** (split into after-match / after-literal sub-streams), offset bytes to the **offset stream**, mtype+delta bytes to the **delta stream**, and length bytes to the **length stream**. Literals go to the **literal stream** (split into 16 context sub-streams by `prev_byte >> 4`).

### File Format

```
File header:
  [4]  Magic "ZXLB" (0x5A584C42)
  [8]  Original size (uint64_t LE)
  [4]  Flags (bit 0: BCJ x86 filter applied)

Per 1 MB block:
  Block header (10,932 bytes):
    [4×13]         Fields: uncomp_size, enc_am, enc_al, enc_off, enc_delta,
                           enc_len, lit_enc_total, dec_am, dec_al, dec_off,
                           dec_delta, dec_len, dec_lit
                   enc_am == 0 → raw fallback (uncompressed block at offset 52)
    [512×5]        rANS freq tables: opcode_am, opcode_al, offset, delta, length
    [16×512]       rANS freq tables for 16 literal context sub-streams
    [16×4]         Compressed sizes of each literal sub-stream
    [16×4]         Decoded sizes of each literal sub-stream
  Streams (variable):
    [enc_am]       opcode after-match sub-stream (rANS)
    [enc_al]       opcode after-literal sub-stream (rANS)
    [enc_off]      offset stream (rANS)
    [enc_delta]    delta stream (rANS)
    [enc_len]      length stream (rANS)
    [lit_enc_sz[0..15]]  literal context sub-streams (rANS, 16 independent)
```

## Current Status (as of 2026-04-20)

Implementation complete including: BCJ x86 filter (E8/E9/Jcc), BCJ x64 RIP-relative filter, LRU-5 REP cache, variable-length EXACT0/1/2/EXACT and DELTA1/2/DELTA tokens, 3-byte MIN_MATCH via TOK_EXACT0 with dedicated 3-gram hash, 4-pass DP optimal parsing, 6-candidate match finder, 2-context opcode entropy coding, 16-context literal entropy coding, and 7 independent rANS streams per block.

Benchmark results (2026-04-20, post B2 3-byte MIN_MATCH):

| File         | ZXL    | gzip-9 | zstd-9 | bzip2-9 |
|--------------|--------|--------|--------|---------|
| ntdll.dll    | 0.4244 | 0.4596 | 0.4442 | 0.4346  |
| kernel32.dll | 0.4304 | 0.4574 | 0.4455 | 0.4416  |
| user32.dll   | 0.3521 | 0.3852 | 0.3630 | 0.3651  |

Beats gzip-9, zstd-9, AND bzip2-9 on all files. Next target: beat zstd-19.
