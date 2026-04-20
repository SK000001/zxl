# ZXL Compression — Phase Roadmap

Goal: achieve the best compression ratio on x86 PE binaries among all publicly available
compressors — surpassing zstd-19, LZMA/xz, 7-zip Ultra, and eventually PPMd-class tools.

## Baseline (ZXL9, 2026-04-09)

| File         | ZXL9   | gzip-9 | zstd-9 | bzip2-9 | zstd-19 | lzma   | 7z Ultra |
|--------------|--------|--------|--------|---------|---------|--------|----------|
| ntdll.dll    | 0.4474 | 0.4596 | 0.4442 | 0.4346  | ~0.428  | ~0.380 | ~0.350   |
| kernel32.dll | 0.4442 | 0.4574 | 0.4455 | 0.4416  | ~0.425  | ~0.375 | ~0.345   |
| user32.dll   | 0.3661 | 0.3852 | 0.3630 | 0.3651  | ~0.349  | ~0.310 | ~0.285   |

## Current (post CHAIN_DEPTH=4096, 2026-04-21)

| File         | ZXL    | gzip-9 | zstd-9 | bzip2-9 |
|--------------|--------|--------|--------|---------|
| ntdll.dll    | 0.4242 | 0.4596 | 0.4442 | 0.4346  |
| kernel32.dll | 0.4303 | 0.4574 | 0.4455 | 0.4416  |
| user32.dll   | 0.3519 | 0.3852 | 0.3630 | 0.3651  |

Streams: opcode_am + opcode_al + off_buf + delta_buf + lbuf + 16×literal (21 rANS models)
Chain depth: 4096. Match candidates: 6 per position (incl. 3-byte short).
Compress: ~0.05–0.1 MB/s. Decompress: ~70–100 MB/s.

---

## Phase 1 — Beat zstd-9 convincingly on all files
**Target: ntdll < 0.440 (currently 0.4474, gap 3.2 pts)**
Estimated total gain: −3 to −5 pts

- [x] **A1** Split param stream by field: separate offset-bytes stream from
      delta-type+delta-value stream. mtype (always 1 or 2) has near-zero entropy
      and pollutes the offset model. Streams: `off_buf`, `delta_buf`, `lbuf`.
      **Result: −1.1 pts ntdll, negligible on kernel32/user32 (ZXLA, 2026-04-09)**

- [~] **A2** 4-context opcode model: after-literal / after-REP / after-exact / after-delta.
      **TRIED AND REVERTED** — +1.0 pts regression. After-REP/delta streams too sparse;
      4×512=2KB extra freq table overhead outweighs modeling gain.

- [~] **A3** Increase literal contexts: 16 → 32 (prev_byte >> 3).
      **TRIED AND REVERTED** — +6.5 pts regression. 32×512=16KB extra freq tables per block;
      at 1MB blocks the header overhead (1.56%) exceeds any modeling gain.

- [~] **A4** Separate offset streams by size class: EXACT1/EXACT2/EXACT3 each with own
      rANS model. **TRIED AND REVERTED** — essentially neutral (+0.1 to +0.4 pts).
      Offset byte distributions too similar across size classes; extra 2 freq tables
      (1KB overhead) not justified by marginal modeling improvement.

- [x] **A5** More REP offsets: LRU-5 (was LRU-3). TOK_REP3=0xF5, TOK_REP4=0xF6;
      literal runs capped at 245. rep[] expanded to 5 entries throughout.
      **Result: −0.1 to −0.3 pts (ZXLB, 2026-04-09)**

- [x] **A6** Deeper hash chains + 5 match candidates. CHAIN_DEPTH 256 → 1024.
      match_find expanded to 5 candidates: best-savings, shortest viable,
      best EXACT1/DELTA1 (off < 256), best mid-offset (256 ≤ off < 65536), longest-any.
      **Result: −0.22/−0.12/−0.09 pts ntdll/kernel32/user32 (2026-04-13)**

---

## Phase 2 — Beat zstd-19
**Target: ntdll < 0.425 (currently 0.4474, gap ~22 pts)**
Estimated total gain: −5 to −10 pts on top of Phase 1

- [ ] **B1** Binary-tree hash chains (btree4). Replace singly-linked hash chains with
      binary trees sorted by position. Enables O(n log n) best-match search across
      the full window. Expected: −0.5 to −1.5 pts.

- [x] **B2** 3-byte minimum match (MIN_MATCH 4 → 3). Added TOK_EXACT0 (3-byte exact
      match, 1-byte offset, implicit length 3, no length/rep update). New 3-gram
      hash (short_ht) with SHORT_DEPTH=64 walk, bails at offset≥256. Disjoint from
      LRU REP cache so ultra-short local matches don't pollute rep[].
      **Result: −1.04/−0.71/−0.58 pts ntdll/kernel32/user32 (2026-04-20)**

- [ ] **B3** 8 MB window (currently 2 MB). Captures long-range repeated patterns
      common in large PE files (repeated PE section headers, repeated strings).
      Requires scaling WINDOW constant and next[] array size.
      Expected: −0.3 to −0.8 pts on ntdll-size files.

- [ ] **B4** 2-level hash: fast 4-byte table (current) + secondary 8-byte table for
      long-match candidates. Long exact matches are currently found only by luck of
      chain walk depth hitting them. Expected: −0.3 to −0.7 pts.

- [ ] **B5** Content-adaptive block boundaries. Detect PE section boundaries
      (`.text`, `.data`, `.rdata`, `.rsrc`) and use them as block split points.
      Different sections have different statistics; cross-section pollution hurts models.
      Expected: −0.2 to −0.5 pts.

- [x] **C1** x64 BCJ filter: RIP-relative addressing (64-bit PE files).
      `MOV rax, [rip+X]`, `LEA rax, [rip+X]` → convert to absolute addresses.
      Opcode patterns: `48 8B 05 XX XX XX XX`, `48 8D 05 XX XX XX XX`, etc.
      Plus 0F-prefixed SSE/CMOV variants and 0x83/0xC7/0xF7 immediate-group ops.
      **Result: −0.70/−0.34/−0.58 pts ntdll/kernel32/user32 (2026-04-20)**

- [ ] **C2** Import table delta filter. IAT entries are 8-byte (64-bit) pointers
      clustered near each other. Apply delta encoding on the IAT section.
      Expected: −0.1 to −0.4 pts.

---

## Phase 3 — Beat LZMA / xz -9
**Target: ntdll < 0.375 (currently 0.4474, gap ~72 pts)**
Estimated total gain: −10 to −20 pts on top of Phase 2

- [ ] **D1** Compressed frequency tables (meta-entropy). rANS-encode the rANS
      frequency tables themselves before writing the block header. Tables are sparse
      (many zero entries) and highly compressible. This unlocks larger context tables
      without header overhead penalty. Expected: enables D2/D3 at no extra cost.

- [ ] **D2** Order-1 literal model (256 contexts, condition on full prev byte).
      Currently: 16–32 contexts (top 4–5 bits only). Full order-1 = 256 sub-streams.
      Requires D1 (compressed tables) to keep header overhead acceptable.
      Expected: −2 to −4 pts.

- [ ] **D3** Order-2 literal context (prev 2 bytes → 256 contexts via hash mixing).
      Combine top bits of prev byte and prev-prev byte into a 256-bucket context.
      Higher-order context without full 65536-entry table.
      Expected: −1 to −2 pts beyond D2.

- [ ] **E1** Suffix array matching (SA-IS algorithm). Build a suffix array over
      each block for guaranteed optimal longest-match queries. Replaces hash chains.
      O(n) build, O(log n) lookup. Much better long-match quality.
      Expected: −2 to −5 pts.

- [ ] **E2** Match tree (LZMA-style binary search tree). Hybrid: use hash chains for
      short matches (speed), binary tree for long matches (quality).
      Standard LZMA approach. Expected: −1 to −3 pts.

---

## Phase 4 — Beat 7-zip Ultra / PPMd
**Target: ntdll < 0.340 (currently 0.4474, gap ~107 pts)**
Estimated total gain: highly implementation-dependent

- [ ] **F1** PPM-class literal model (order-4 context with escape mechanism).
      Full prediction by partial matching for literals. Requires per-context adaptive
      frequency tables and escape/exclusion logic. Very high implementation complexity.
      Expected: −5 to −10 pts beyond Phase 3.

- [ ] **F2** Context mixing (PAQ-style). Combine predictions from multiple models
      (LZ match, order-1 literal, order-4 literal, word model) with learned weights.
      Expected: −2 to −5 pts.

- [ ] **F3** Arithmetic coding (replace rANS). True arithmetic coder achieves
      exact Shannon entropy; rANS is ~0.001 bits/symbol below ideal. Negligible
      on its own but pairs well with very tight models.

- [ ] **F4** Structure-aware preprocessing. Detect and specially encode:
      - PE section tables (fixed-size records, rich delta patterns)
      - Debug/DWARF sections (address tables, line number tables)
      - .NET metadata heaps (blob heap, string heap)
      Expected: −0.5 to −2 pts on applicable files.

---

## Milestones

- [x] Beat gzip-6 on all benchmark files (ZXL8, 2026-04-09)
- [x] Beat gzip-9 on all benchmark files (ZXLB, 2026-04-09)
- [x] Beat zstd-3 on all benchmark files (ZXL9, 2026-04-09)
- [x] Beat zstd-9 on kernel32 (ZXL9, 2026-04-09)
- [x] Beat zstd-9 on ALL files (2026-04-20, post C1 x64 BCJ)
- [x] Beat bzip2-9 on kernel32 and user32 (2026-04-20)
- [x] Beat bzip2-9 on ntdll (2026-04-20, post B2: 0.4244 vs 0.4346)
- [x] Beat bzip2-9 on ALL files (2026-04-20, post B2)
- [ ] Beat zstd-19 on all files                                    ← Phase 2 target
- [ ] Beat LZMA / xz -9 on all files                              ← Phase 3 target
- [ ] Beat 7-zip Ultra on all files                                ← Phase 4 target

---

## Completed Features (ZXL1 → ZXL9)

- [x] Three-way LZ matching: exact + XOR-delta + additive-delta
- [x] Entropy-weighted optimal DP parser (4-pass)
- [x] REP offsets: LRU-3, 1-byte length, post-trace substitution
- [x] Variable-length offset encoding: EXACT1/2/3, DELTA1/2/3 (ZXL5)
- [x] Separated opcode + param streams (ZXL6) — +1.1 to +1.7 pts
- [x] BCJ x86 filter: E8/E9 CALL/JMP + 0F 80..8F Jcc near jumps
- [x] 3rd match candidate: best small-offset EXACT1/DELTA1 (ZXL7)
- [x] 2-context opcode model: after-match / after-literal (ZXL8) — +0.44 to +0.70 pts
- [x] Separate length stream (lbuf) from offset/delta stream (ZXL9) — +0.72 to +0.91 pts
- [x] 16-context literal model (prev_byte >> 4)
- [x] 1 MB blocks, 2 MB window, CHAIN_DEPTH=256, 512K hash buckets

---

## What Was Tried and Reverted

- **Context-aware DP literal costs**: circular dependency, +0.23 pts regression.
- **Residual sym_cost after pass-0**: too unstable, +0.88 pts regression. Fix: moved to pass-1.
- **Run-token overhead per literal in DP**: splits runs badly, +0.97 pts regression.
- **16-context literal with 512KB blocks**: header overhead 7808 B/block exceeded savings.
- **REP blending in DP overhead**: undercounts non-REP exact match costs, regression.
- **4-context opcode model (A2)**: split after-match into after-REP/exact/delta; +1.0 pts
  regression — sparse contexts + 2KB extra header overhead outweigh any modeling gain.
- **32 literal contexts (A3)**: doubled N_LIT_CTX from 16→32; +6.5 pts regression —
  16KB extra freq table overhead per 1MB block completely dominates any gain.
- **Separate offset streams by size class (A4)**: off1/off2/off3 split; neutral result
  (+0.1–0.4 pts). Offset byte distributions too similar across size classes.
