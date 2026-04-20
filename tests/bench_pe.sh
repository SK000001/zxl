#!/usr/bin/env bash
# Canonical PE-binary benchmark. Run from repo root: bash tests/bench_pe.sh
set -e
cd "$(dirname "$0")"
ZXL=../zxl.exe
printf "%-14s %9s %9s %9s %9s  %s\n" "file" "orig" "ZXL" "gzip-9" "zstd-9" "rt"
printf "%-14s %9s %9s %9s %9s  %s\n" "----" "----" "---" "------" "------" "--"
for f in ntdll.dll kernel32.dll user32.dll; do
  [ -f "$f" ] || { echo "missing: $f"; continue; }
  "$ZXL" c "$f" "$f.zxl" > /dev/null 2>&1
  "$ZXL" d "$f.zxl" "$f.out" > /dev/null 2>&1
  cmp -s "$f" "$f.out" && rt=OK || rt=FAIL
  gzip -9 -k -f "$f"
  zstd -9 -q -f -o "$f.zst" "$f" 2>/dev/null
  orig=$(wc -c < "$f"); zxlsz=$(wc -c < "$f.zxl"); gzsz=$(wc -c < "$f.gz"); zstsz=$(wc -c < "$f.zst")
  zr=$(awk "BEGIN{printf \"%.4f\", $zxlsz/$orig}")
  gr=$(awk "BEGIN{printf \"%.4f\", $gzsz/$orig}")
  zstr=$(awk "BEGIN{printf \"%.4f\", $zstsz/$orig}")
  printf "%-14s %9d %9s %9s %9s  %s\n" "$f" "$orig" "$zr" "$gr" "$zstr" "$rt"
  rm -f "$f.zxl" "$f.out" "$f.gz" "$f.zst"
done
