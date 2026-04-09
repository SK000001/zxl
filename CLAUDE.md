# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZXL is a novel binary compression algorithm in C. Its key innovation is three simultaneous LZ matching strategies: exact matches, XOR-delta matches (for relocated addresses/bit-shifted patterns), and additive-delta matches (for incrementing counters). These feed into entropy-weighted optimal parsing and rANS entropy coding.

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

No external dependencies. Requires GCC with AVX2/SSE2 support (`-march=native`).

## Architecture

**Data flow:** `main.c` → `zxl_codec.c` (block loop) → `zxl_match.c` (matching) + `zxl_rans.c` (entropy coding)

### Modules

**`src/zxl_codec.c`** — Block orchestrator and public API (`zxl_compress`, `zxl_decompress`, `zxl_bound`). Processes input in 64 KB blocks. Each block: find matches → build token + literal streams → rANS encode both. Stores uncompressed if compression doesn't help (seq_size=0 flag).

**`src/zxl_match.c`** — LZ matching engine with three independent hash tables (one per match type). `match_find()` searches all three and returns the best match by entropy cost; `match_update()` inserts current position into all tables. AVX2 (32-byte) or SSE2 (16-byte) SIMD accelerates match extension. Hash window: 1 MB; min match: 4 bytes; table size: 2^20 entries.

**`src/zxl_rans.c`** — Range ANS entropy coder (Fabian Giesen's "Simple rANS"). `rans_build_tables()` normalizes byte frequencies to sum 4096 (scale bits = 12). Encodes backward then reverses. Separate frequency tables for tokens and literals.

**`src/main.c`** — CLI dispatcher. Reads file, allocates buffers, calls codec, reports ratio and throughput.

### File Format

```
[4]  Magic "ZXL1"
[8]  Original size (uint64_t LE)
Per 64 KB block:
  [4]   Uncompressed block size
  [4]   Token stream compressed size (0 = raw fallback)
  [4]   Literal stream compressed size
  [512] Token rANS frequency table (uint16_t[256])
  [512] Literal rANS frequency table (uint16_t[256])
  [N]   Encoded token stream
  [M]   Encoded literal stream
```

## Current Status (as of 2026-04-01)

Implementation is complete. Remaining work: compile testing, benchmark against zstd/lz4, and parameter tuning (block size, hash table size, match costs).
