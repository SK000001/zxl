# ZXL Makefile
# Targets: all, clean, test
# Detects AVX2/SSE2 support and enables them automatically.

CC      = gcc
CFLAGS  = -O3 -std=c11 -Wall -Wextra -Wpedantic \
           -march=native \
           -fomit-frame-pointer \
           -I src
LDFLAGS = -lm

ifeq ($(OS),Windows_NT)
    EXE = .exe
else
    EXE =
endif

TARGET  = zxl$(EXE)
SRCS    = src/main.c \
          src/zxl_match.c \
          src/zxl_ac.c \
          src/zxl_codec.c

OBJS    = $(SRCS:.c=.o)

.PHONY: all clean test bench

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Quick round-trip test on the binary itself
test: $(TARGET)
	./$(TARGET) t $(TARGET)

# Benchmark on the binary itself
bench: $(TARGET)
	./$(TARGET) b $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET) zxl.tmp
