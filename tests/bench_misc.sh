#!/usr/bin/env bash
# Benchmark ZXL vs gzip-9 on non-PE test files in this directory.
# Run from repo root: bash tests/bench_misc.sh
set -e
cd "$(dirname "$0")"
ZXL=../zxl.exe
printf "%-16s %9s %9s %9s  %s\n" "file" "orig" "ZXL" "gzip-9" "rt"
printf "%-16s %9s %9s %9s  %s\n" "----" "----" "---" "------" "--"
for f in test.*; do
  [ -f "$f" ] || continue
  case "$f" in *.zxl|*.gz|*.out) continue;; esac
  "$ZXL" c "$f" "$f.zxl" > /dev/null 2>&1
  "$ZXL" d "$f.zxl" "$f.out" > /dev/null 2>&1
  cmp -s "$f" "$f.out" && rt=OK || rt=FAIL
  gzip -9 -k -f "$f"
  orig=$(wc -c < "$f"); zxlsz=$(wc -c < "$f.zxl"); gzsz=$(wc -c < "$f.gz")
  zr=$(awk "BEGIN{printf \"%.4f\", $zxlsz/$orig}")
  gr=$(awk "BEGIN{printf \"%.4f\", $gzsz/$orig}")
  printf "%-16s %9d %9s %9s  %s\n" "$f" "$orig" "$zr" "$gr" "$rt"
  rm -f "$f.zxl" "$f.out" "$f.gz"
done
