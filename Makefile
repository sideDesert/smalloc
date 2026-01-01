# Compiler
CC = clang

# Project name (change this to your program name)
TARGET = build

# Source files (add your .c files here)
SRCS = main.c smalloc.c vector.c

# Object files
OBJS = $(SRCS:.c=.o)

# Detect platform
UNAME_S := $(shell uname -s)

# Common flags
CFLAGS_COMMON = -Wall -Wextra -Wshadow -std=c17

# Platform-specific sanitizer flags
ifeq ($(UNAME_S),Darwin)
    # macOS: leak sanitizer is included in address sanitizer
    SANITIZE_FLAGS = -fsanitize=address -fsanitize=undefined
else
    # Linux: can use leak sanitizer separately
    SANITIZE_FLAGS = -fsanitize=address -fsanitize=undefined -fsanitize=leak
endif

# Debug flags with sanitizers for catching segfaults early
CFLAGS_DEBUG = $(CFLAGS_COMMON) -g -O0 \
               -fno-omit-frame-pointer

# Production/Release flags
CFLAGS_RELEASE = $(CFLAGS_COMMON) -O2 \
                 -fstack-protector-strong \
                 -D_FORTIFY_SOURCE=2

# Linker flags for sanitizers (needed for debug build)
LDFLAGS_DEBUG = $(SANITIZE_FLAGS)

# Default to debug build
CFLAGS = $(CFLAGS_DEBUG)
LDFLAGS = $(LDFLAGS_DEBUG)

# Default target
all: $(TARGET)

# Debug build (explicit)
debug: CFLAGS = $(CFLAGS_DEBUG)
debug: LDFLAGS = $(LDFLAGS_DEBUG)
debug: clean $(TARGET)
	@echo "Built with debug flags and sanitizers"

# Release build
release: CFLAGS = $(CFLAGS_RELEASE)
release: LDFLAGS =
release: clean $(TARGET)
	@echo "Built with release flags"

# Link the target
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Run with sanitizer options
run: $(TARGET)
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=0 ./$(TARGET)

# Phony targets
.PHONY: all debug release clean run
