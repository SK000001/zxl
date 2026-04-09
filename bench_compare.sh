#!/bin/bash
# Compare ZXL against gzip/zstd on binary files

TMP=/tmp/zxl_bench_$$
mkdir -p $TMP

bench_file() {
    local file="$1"
    local label="$2"
    local size=$(wc -c < "$file")
    echo ""
    echo "=== $label ($size bytes) ==="
    printf "%-18s %8s %8s %10s\n" "Compressor" "Ratio" "CompSz" "Cmp MB/s"
    printf "%-18s %8s %8s %10s\n" "----------" "-----" "------" "--------"

    # ZXL
    local ZXL_OUT="$TMP/out.zxl"
    local t0=$(date +%s%3N)
    ./zxl.exe c "$file" "$ZXL_OUT" > /dev/null 2>&1
    local t1=$(date +%s%3N)
    local dt=$(( t1 - t0 ))
    local csz=$(wc -c < "$ZXL_OUT")
    local ratio=$(awk "BEGIN{printf \"%.4f\", $csz/$size}")
    local spd=$(awk "BEGIN{printf \"%.1f\", $size / ($dt>0?$dt:1) / 1000.0}")
    printf "%-18s %8s %8d %10s\n" "ZXL" "$ratio" "$csz" "$spd"

    # gzip -1
    local GZ1_OUT="$TMP/out.gz1"
    t0=$(date +%s%3N)
    gzip -1 -c "$file" > "$GZ1_OUT" 2>/dev/null
    t1=$(date +%s%3N)
    dt=$(( t1 - t0 ))
    csz=$(wc -c < "$GZ1_OUT")
    ratio=$(awk "BEGIN{printf \"%.4f\", $csz/$size}")
    spd=$(awk "BEGIN{printf \"%.1f\", $size / ($dt>0?$dt:1) / 1000.0}")
    printf "%-18s %8s %8d %10s\n" "gzip -1" "$ratio" "$csz" "$spd"

    # gzip -6 (default)
    local GZ6_OUT="$TMP/out.gz6"
    t0=$(date +%s%3N)
    gzip -6 -c "$file" > "$GZ6_OUT" 2>/dev/null
    t1=$(date +%s%3N)
    dt=$(( t1 - t0 ))
    csz=$(wc -c < "$GZ6_OUT")
    ratio=$(awk "BEGIN{printf \"%.4f\", $csz/$size}")
    spd=$(awk "BEGIN{printf \"%.1f\", $size / ($dt>0?$dt:1) / 1000.0}")
    printf "%-18s %8s %8d %10s\n" "gzip -6" "$ratio" "$csz" "$spd"

    # gzip -9
    local GZ9_OUT="$TMP/out.gz9"
    t0=$(date +%s%3N)
    gzip -9 -c "$file" > "$GZ9_OUT" 2>/dev/null
    t1=$(date +%s%3N)
    dt=$(( t1 - t0 ))
    csz=$(wc -c < "$GZ9_OUT")
    ratio=$(awk "BEGIN{printf \"%.4f\", $csz/$size}")
    spd=$(awk "BEGIN{printf \"%.1f\", $size / ($dt>0?$dt:1) / 1000.0}")
    printf "%-18s %8s %8d %10s\n" "gzip -9" "$ratio" "$csz" "$spd"

    # zstd -1
    local ZST1_OUT="$TMP/out.zst1"
    t0=$(date +%s%3N)
    zstd -1 -q -o "$ZST1_OUT" "$file" 2>/dev/null
    t1=$(date +%s%3N)
    dt=$(( t1 - t0 ))
    csz=$(wc -c < "$ZST1_OUT")
    ratio=$(awk "BEGIN{printf \"%.4f\", $csz/$size}")
    spd=$(awk "BEGIN{printf \"%.1f\", $size / ($dt>0?$dt:1) / 1000.0}")
    printf "%-18s %8s %8d %10s\n" "zstd -1" "$ratio" "$csz" "$spd"

    # zstd -3 (default)
    local ZST3_OUT="$TMP/out.zst3"
    t0=$(date +%s%3N)
    zstd -3 -q -o "$ZST3_OUT" "$file" 2>/dev/null
    t1=$(date +%s%3N)
    dt=$(( t1 - t0 ))
    csz=$(wc -c < "$ZST3_OUT")
    ratio=$(awk "BEGIN{printf \"%.4f\", $csz/$size}")
    spd=$(awk "BEGIN{printf \"%.1f\", $size / ($dt>0?$dt:1) / 1000.0}")
    printf "%-18s %8s %8d %10s\n" "zstd -3" "$ratio" "$csz" "$spd"

    # zstd -9
    local ZST9_OUT="$TMP/out.zst9"
    t0=$(date +%s%3N)
    zstd -9 -q -o "$ZST9_OUT" "$file" 2>/dev/null
    t1=$(date +%s%3N)
    dt=$(( t1 - t0 ))
    csz=$(wc -c < "$ZST9_OUT")
    ratio=$(awk "BEGIN{printf \"%.4f\", $csz/$size}")
    spd=$(awk "BEGIN{printf \"%.1f\", $size / ($dt>0?$dt:1) / 1000.0}")
    printf "%-18s %8s %8d %10s\n" "zstd -9" "$ratio" "$csz" "$spd"

    # bzip2 -9
    local BZ2_OUT="$TMP/out.bz2"
    t0=$(date +%s%3N)
    bzip2 -9 -c "$file" > "$BZ2_OUT" 2>/dev/null
    t1=$(date +%s%3N)
    dt=$(( t1 - t0 ))
    csz=$(wc -c < "$BZ2_OUT")
    ratio=$(awk "BEGIN{printf \"%.4f\", $csz/$size}")
    spd=$(awk "BEGIN{printf \"%.1f\", $size / ($dt>0?$dt:1) / 1000.0}")
    printf "%-18s %8s %8d %10s\n" "bzip2 -9" "$ratio" "$csz" "$spd"

    rm -f "$ZXL_OUT" "$GZ1_OUT" "$GZ6_OUT" "$GZ9_OUT" "$ZST1_OUT" "$ZST3_OUT" "$ZST9_OUT" "$BZ2_OUT"
}

bench_file "zxl.exe" "zxl.exe (small binary, 73 KB)"
bench_file "/c/Program Files/Git/usr/bin/ssh.exe" "ssh.exe (medium binary, 925 KB)"
bench_file "/c/Windows/System32/ntdll.dll" "ntdll.dll (large binary, 2.5 MB)"
bench_file "/c/Program Files/Git/mingw64/bin/git.exe" "git.exe (large binary, 4 MB)"

rm -rf $TMP
