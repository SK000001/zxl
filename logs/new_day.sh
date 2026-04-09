#!/bin/bash
# Run this at the start of each work session to create today's log file.
# Usage: bash logs/new_day.sh

DATE=$(date +%Y-%m-%d)
LOG="$(dirname "$0")/$DATE.log"

if [ -f "$LOG" ]; then
    echo "Log for $DATE already exists: $LOG"
else
    cat > "$LOG" <<EOF
[$DATE] ZXL Compression Project
============================================================

## Session Summary

### What was done today


### Decisions made


### Problems encountered


### Status / Next steps
- [ ]

============================================================
EOF
    echo "Created log: $LOG"
fi
