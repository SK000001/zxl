# ZXL Roadmap

Single source of truth for where ZXL is, where it's going, and what not to retry.
Replaces the old PHASES.md (folded in here).

---

## Current state (2026-04-28, post all-AC retirement of rANS)

| File         | ZXL    | gzip-9 | zstd-9 | bzip2-9 | zstd-19 | xz-9e  |
|--------------|--------|--------|--------|---------|---------|--------|
| ntdll.dll    | 0.3928 | 0.4596 | 0.4442 | 0.4346  | 0.4013  | 0.3772 |
| kernel32.dll | 0.4020 | 0.4574 | 0.4455 | 0.4416  | 0.4024  | 0.3785 |
| user32.dll   | 0.3272 | 0.3852 | 0.3630 | 0.3651  | 0.3312  | 0.3065 |

- **Beats zstd-19 on all three PE files** (ntdll −0.85, kernel32 −0.04, user32 −0.40 pts vs zstd-19).
- Gap to xz-9e: +1.56 / +2.35 / +2.07 pts (was +3.26 / +4.51 / +3.54 before any AC; the three-step adaptive-AC retire of rANS closed roughly half the gap to xz-9e).
- Small-file ratios also improved unanimously: test.js 0.3083 (−2.30 pts vs pre-AC), test.json 0.2055 (−0.57), test.pdf 0.9465 (−0.77), test.png 0.9756 (−1.36 pts).

---

## What's shipped (condensed)

Core pipeline:
- Three-way LZ: exact + XOR-delta + additive-delta matches.
- 4-pass entropy-weighted DP optimal parser.
- Adaptive binary range coder (LZMA-style, 11-bit prob precision, MOVE_BITS=5) for all 7 entropy streams: opcode_am, opcode_al, off_lo, off_hi, delta, len, lit. Literals condition on full prev-byte context (256 contexts × 8-bit tree); the other six streams are unconditional online-learned 256-bin models. No per-block freq tables.
- 4 MB blocks, 2 MB window.

Match finder:
- Four hash chains (exact 4B, XOR-diff 4B, add-diff 4B, short 3B, long 8B) + B1 binary-tree (LZMA BT4-style, additive candidate). Chain depth 256.

Format tricks:
- LRU-5 REP offsets, variable-length offset classes (EXACT1/2/3, DELTA1/2/3), TOK_EXACT0 for 3-byte local matches.
- x86 BCJ filter, x64 RIP-relative BCJ filter, C2 IAT delta filter.
- D1 compact freq tables (bitmap + varint) — cuts per-block header ~10 KB → ~3 KB.
- **D1.5 rank-1 factored freq tables** — per-table encoder choice: ship 16 row + 16 col marginals as varints and reconstruct the 256-bin table via outer product, when that's cheaper than a full dense compact table. Analytical cost comparison picks dense vs rank-1 per table. Cut header further; won 1–3 pts on small non-PE files.
- B5 PE-section-aware block boundaries — parses PE section table and forces block splits at section starts (guarded by 512 KB min-block). Each block's freq tables specialize to one section's statistics.
- **Adaptive AC literals (2026-04-28)** — replaces the 16-context (prev_byte>>4 nibble) rANS literal sub-streams with a single LZMA-style adaptive binary range coder over 256 prev-byte contexts (8-bit tree per context, 11-bit prob precision, MOVE_BITS=5 update). Drops 16 per-block freq tables. Won −1.03 / −1.26 / −0.89 pts on PE; −0.15 to −1.74 on every small file. Phase-0 ceiling was 5.2 / 7.2 / 6.5 pts (order-1 byte cond. entropy); realised ~20% — small sub-streams' AC warm-up + byte-only context cap the immediate gain.
- **Adaptive AC offsets (2026-04-28, Step B)** — same range coder applied to off_lo + off_hi. Initially tried 256 prev-byte contexts (mirroring literal model); regressed on most files. Walked context count down through 16/8/4/2/1; ratio improved monotonically. **Final: pure unconditional adaptive AC** — single 256-bin online-learned model per stream, no cross-symbol context. At 30K-140K samples per stream, byte-pair correlations are noise that AC's online learning can't separate from signal. The win comes from online drift adaptation + dropping 2 per-block freq tables (~300 B), biggest impact on kernel32's single-block layout. Won −0.28 / −0.42 / −0.24 pts on PE on top of Step A.
- **Adaptive AC opcode/delta/lbuf — rANS fully retired (2026-04-28, Step C)** — same unconditional adaptive AC applied to opcode_am, opcode_al, delta, lbuf. Phase-0 said headroom was small (these streams were already near 0-order optimal under rANS), but Step B's tuning result generalised: dropped 4 more freq tables, online-drift adaptation still wins. Result: −0.39 / −0.48 / −0.34 pts on PE on top of Step B; ZXL now beats zstd-19 on all three PE files.
- **rANS infrastructure removed (2026-04-28, cleanup)** — deleted zxl_rans.{c,h} and the D1/D1.5 freq-table machinery (build_freqs_auto, write/read_freqs_tagged, rank1_reconstruct, write/read_compact_freqs, varint helpers, plus their constants). 498 LOC removed; ratios unchanged.

---

## Constraints we've proven experimentally

Don't forget these or we'll waste sessions re-learning them:

- **Per-block freq table overhead after D1 is ~150 B per table.** Any new rANS sub-stream at current block sizes needs **>0.3 pts modeling gain** to break even. This is why length-stream-split and N_LIT_CTX=32 both failed.
- **kernel32 (836 KB, single block) is the overhead floor.** Any table-count increase that helps ntdll tends to hurt kernel32. Can't pass this without structural change (adaptive coding, section-aware blocks, or factored freq tables).
- **Context functions must preserve x86-opcode-class clustering.** `prev>>4` is near-optimal because the top nibble segments opcode classes. Fibonacci / order-2 hashes destroyed this and regressed +0.3 to +0.5 pts.
- **Chain depth 4096 was not the bottleneck.** BT validated that depth 256 + BT matches the quality of depth 4096. Further match-finder tuning has low expected payoff.
- **Pre-filter detection patterns must be strict and self-consistent.** C2's first cut (`byte[7]==0` alone) regressed +2.1 pts by colliding with BCJ-modified instructions. The strict form (`byte[7]==0 && byte[6]==0 && byte[5]<=0x7F`, run ≥ 80) landed the win.

---

## Phase-0 instrumentation findings (2026-04-27)

All four roadmap items below were instrumented (not implemented) in
back-to-back sessions to validate their gain estimates against reality.
Results were significantly below the original estimates — all are now
considered marginal-to-negative on the existing architecture.

| Item | Roadmap est. | Measured headroom |
|---|---|---|
| Typed streams (x86 split) | −0.5 to −1.0 | ~0.5 bit 0-order gap, mostly captured by existing LZ + 16-context literals; opcode/operand entropy near-identical (6.44 vs 6.39 on ntdll). Realistic ~−0.1 to −0.4. |
| Cross-DLL dictionary | −1.0 to −2.0 | Concat-test: ntdll+kernel32 saves 12.3 KB (0.37 pts), ntdll+user32 saves 0 (user32 doesn't share much with ntdll directly). 2 MB window puts ntdll out of reach for late-position user32 anyway. All-3 concat saves 14.7 KB (0.28 pts). |
| Semi-adaptive rANS | −0.3 to −0.8 | 2-way split entropy probe: ntdll 0.09 pts, kernel32 0.16 pts, user32 0.08 pts after ~50 B/stream/delta header cost. Small text files (test.js / test.json) net-regress unless gated. |
| .reloc-driven pointer normalisation | −1.0 to −3.0 | x64 base relocations cover only 0.26–0.66% of file (827/685/617 absolute fields on ntdll/kernel32/user32). Most pointer-shaped data is IAT (caught by C2), RVAs, or RIP-relative (BCJ). Image-base subtraction yields 0-order entropy drop of ~0.8 bits on those few KB → **0.027 / 0.067 / 0.027 pts theoretical**, before paying for parser + transform + per-image-base header. Net-negative. |

**Phase-0 found one strong signal.** Probing order-1 byte conditional entropy on the live rANS streams (2026-04-28) revealed 5.2 / 7.2 / 6.5 pts of theoretical headroom on PE — larger than the gap to xz-9e. Most of it lives in the 16 literal sub-streams and the offset streams. **Step A shipped: adaptive-AC literals — see "What's shipped" above.** Step B (extend AC to off_lo/off_hi) and beyond remain.

The remaining "Further out" items: instruction-level LZ (x86 decoder, multi-week — but typed-streams probe suggests opcode-level entropy is already mostly captured), suffix-array optimal parsing (modest gain on top of BT per roadmap's own assessment).

## Roadmap — next sessions

### Step D — Context conditioning by opcode token type
**Expected:** speculative.

Step B's surprise result (cross-symbol byte context didn't help offsets) hints that the right context for offsets is *which match-token class produced this byte*, not the prior byte. EXACT1 offsets are 0-255; EXACT2 are 0-65535; etc — sharply different distributions. Threading the token class through to the AC encode point requires re-ordering: instead of separate buffered streams, AC-encode bytes inline with their type known. Phase-0 first: measure conditional entropy of offset bytes given token class.

### Step E — Bit-level context within AC encode
**Expected:** speculative.

Within the bit-tree decomposition of each byte, condition the bit-tree probabilities on additional state (e.g., for offsets, on bit position; for literals, on the partial byte built up so far inside another stream). Genuine sub-byte conditioning. Multi-week.

### ~~Session N+1 — BPE-style trained vocabulary~~ FAILED 2026-04-27 at phase-0

Phase-0 probe (top-K-N-grams over kernel32+user32, tested on ntdll):
- Naive coverage metric said 13 pts net savings (covered 736 KB / 29% of file with avg 4.3 B per match)
- L=3 and L=4 matches alone account for 7.25 pts theoretical (the patterns LZ struggles with most)

Empirical concat test (vocab dumped + prepended to ntdll, compressed with current zxl):
- vocab + ntdll → 1,103,300 bytes vs ntdll standalone 1,033,531 bytes
- Vocab-as-LZ-preload made things WORSE — preload added ~70 KB output, ntdll portion didn't shrink
- Self-trained vocab (trained on ntdll itself, tested on ntdll) also worse: 1,103,042 bytes

**Lesson:** the BPE-vocab approach is **structurally subsumed by LZ + rANS** for byte-level matching. The naive coverage probe was wildly optimistic because it assumed baseline cost is 1 B/byte literal, but real baseline is rANS-compressed LZ which already captures every repeated pattern. Vocab tokens at 2 B/match barely beat TOK_EXACT0/1 (which rANS-compress to ~2 B). Even with full TOK_VOCAB format integration the DP parser would pick LZ over vocab almost everywhere, because the underlying patterns are the same and LZ wins on within-file repetition.

Don't retry without operating at a different REPRESENTATION than raw bytes — the byte-level competition is decisively won by LZ. Vocab approach can only win if applied to a stream where LZ doesn't naturally find matches (decoded x86 instructions, post-canonicalisation tokens, etc.) → which is exactly the "pattern grammar" / "instruction-level LZ" items in "Further out".



### ~~Session N+1 — N_LIT_CTX expansion under the new overhead floor~~ FAILED 2026-04-25
Tested with D1.5 rank-1 freq tables in place. Results vs N_LIT_CTX=16 baseline:

  N_LIT_CTX=32: ntdll −0.06, kernel32 +0.07, user32 +0.10, test.js +1.29,
                test.json +0.68, test.pdf +0.78, test.png +0.60. Mixed.
  N_LIT_CTX=64: strict regression on every file (kernel32 +0.26,
                user32 +0.30, test.js +3.39, etc).

**Lesson:** D1.5 only addressed per-table header overhead. The 16-context limit was also constrained by sub-stream sample dilution — splitting literals across 32 buckets means each rANS sub-stream has half as many samples, which hurts the freq-table normalization quality even when the table itself ships compactly. Dilution effect dominates header savings beyond N_LIT_CTX=16 for the file sizes we benchmark. Branch abandoned; N_LIT_CTX stays 16. Added to "Tried and reverted" below.

---

### Session N+1 — Semantic typed streams
**Branch:** `feat/typed-streams` · **Expected:** −0.5 to −1.0 pts on PE.

Partition each block's bytes into semantic streams before LZ/rANS:
- opcode bytes (x86 instruction dispatch bytes)
- mod/rm + SIB bytes
- immediate / displacement bytes
- 8-byte pointer regions (IAT / vtable)
- 4-byte relocatable words (driven by .reloc if we parse it)
- UTF-16 string regions
- zero padding runs

Each stream gets its own LZ state and entropy model tuned to its distribution. Current pipeline averages all these together, which is why the opcode / offset / length separation we already do gives outsized wins — this is the logical completion.

Requires a minimal x86 decoder (opcode → length). Multi-week but structurally high-leverage.

---

### Session N+2 — Cross-DLL shared dictionary
**Branch:** `feat/crossdll-dict` · **Expected:** −1.0 to −2.0 pts when compressing multiple DLLs together.

ntdll / kernel32 / user32 share boilerplate: SEH prologues, import stubs, standard epilogue patterns. kernel32 forwards many exports to ntdll. When compressed together, a shared prefix dictionary (concat or learned) gives each file a warm match window instead of starting cold.

Format: add an optional "pre-shared dictionary" block that both encoder and decoder inject into the LZ window before the first block. Single-file compression unaffected; multi-file mode becomes a separate entry point.

Closest public analogue is zstd's `--train` dictionaries — but those are generic. A PE-aware dictionary (or multi-file self-training) is novel for this domain.

---

### Session N+3+ — Semi-adaptive rANS as a fallback path
**Branch:** `feat/semi-adaptive-rans` · **Expected:** −0.3 to −0.8 pts.

If low-rank freq tables don't pan out, fall back to semi-adaptive: transmit freq tables once per block as today, then mid-block emit small freq deltas every ~256 KB to track distribution drift. Captures section-boundary drift without a full rewrite to per-symbol adaptation.

Mutually exclusive with low-rank in most respects — pick whichever proves on the data.

---

## Further out — structural / research-grade

- **Instruction-level LZ.** Match on decoded instructions instead of raw bytes. Two `call DestA` with different immediates look identical at the opcode level. Factor into (opcode stream, immediate stream), LZ each separately. Needs x86 decoder.
- **Relocation-driven pointer normalization.** Parse .reloc, subtract image base from every enumerated address → pointers become small RVAs that share high bytes and compress dramatically better. No public compressor does this; .reloc is always opaque.
- **Control-flow-aware canonicalization.** Every memcpy/memset loop in a DLL looks similar but differs in register allocation. Normalize to canonical form, LZ-match canonical forms, store diffs. Academic work exists (procedural abstraction); never welded to an LZ front end.
- **Suffix-array optimal parsing.** SA-IS builds in O(n); LCP queries give the exact longest match at any position. What xz does. Modest win on top of BT but gives provable parse optimality.
- **Bit-level binary arithmetic coder.** Our rANS is byte-symbol. A bit coder conditioned on prior bits can exploit sub-byte structure (e.g., parity correlating with opcode class). Decoder cost is real; mostly worth it if we get to the xz-9e push.

---

## Deprioritized (don't retry without structural change first)

- **N_LIT_CTX ≠ 16** — overhead ceiling lifted by D1.5, but expansion still net-regresses (sub-stream sample dilution). Don't retry without changing the literal-stream segmentation strategy itself.
- **More per-block rANS stream splits** (length / opcode subdivisions) — same overhead math, same failure mode.
- **Deeper hash chains or larger hash tables** — BT already proved chains aren't the bottleneck at depth 256+.
- **Order-2 literal context via byte-pair hashes** — destroys x86 opcode-class clustering; has to be redesigned around the clustering, not against it.
- **Full per-symbol adaptive rANS as the first attempt** — complexity vs gain is worse than low-rank freq tables at current sizes. Do low-rank first, reassess.
- **BWT, PPM, DCT, neural compression** — either wrong domain (BWT/PPM shine on text) or out of scope for this codebase.

---

## Tried and reverted — condensed history

Match finder:
- **A2 4-context opcode model** (after-REP/exact/delta): +1.0 pts. Sparse contexts, overhead > gain.
- **A3 32 literal contexts**: +6.5 pts. 16 KB extra header per 1 MB block.
- **A4 offset streams split by size class**: neutral. Distributions too similar.
- **B3 8 MB window**: flat. Chain depth was the actual cap.
- **HASH_BITS 19→20 (1M buckets)**: flat. 512K was enough.
- **SHORT_DEPTH 64→256**: flat. Chain bails on offset ≥ 256 anyway.

Entropy / model:
- **Order-2 literal context (Fibonacci hash of 2-byte history)**: +0.3 to +0.5 pts. Destroyed x86 opcode-class clustering.
- **REP vs non-REP length stream split**: PE flat, small files +0.1 to +0.3. Overhead > modeling gain.
- **N_LIT_CTX 16→32 post-D1**: mixed. kernel32 +0.33 from 2.4 KB extra header at 0.29% of file.
- **Context-aware DP literal costs**: +0.23, circular dependency.
- **Run-token overhead per literal in DP**: +0.97, splits runs badly.

Filter / preprocess:
- **C2 with loose detection (`byte[7]==0`)**: +2.1 pts regression. Collided with BCJ-modified bytes.

Fixed by tightening C2 to strict 3-byte pattern + run ≥ 80.

- **C3 broader pointer-delta filter scoped to .rdata/.idata** (2026-04-26): all six tested configurations net-regressed or were flat. Tested with disjoint pattern `byte[7]==0 && byte[6] in [0x01..0x7F]` (complementary to C2's `byte[6]==0`), targeting the 60–110 KB of additional pointer-shaped 8B runs that the rdata probe identified inside .rdata sections. Best config (min_run=80, byte[5]-constancy, C3 runs last in pipeline): essentially flat (~0). Lowering min_run or removing constancy regressed every PE file (worst: ntdll +0.23, kernel32 +0.14 at min_run=16). **Lesson:** the disjoint extra-mass pointer runs aren't structurally similar enough for XOR-delta to expose redundancy. C2's strict pattern (low-VA system-DLL imports clustered to one source DLL) catches genuine same-source-DLL pointer runs; the broader pattern catches diverse function-pointer / vtable mixes whose high bytes look pointer-shaped but whose values aren't actually correlated. XOR'ing them adds entropy. Don't retry C3 without a fundamentally different transform (e.g., delta-coding for monotonic runs) or per-run "is this actually compressible after transform?" gating.
