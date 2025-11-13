CC = gcc
CFLAGS_BASE = -Wall -Wextra -no-pie -fno-stack-protector
CFLAGS_DEBUG = $(CFLAGS_BASE) -O0 -g -DDEBUG
CFLAGS_RELEASE = $(CFLAGS_BASE) -O2 -DNDEBUG
CFLAGS_SANITIZE = $(CFLAGS_DEBUG) -fsanitize=address -fsanitize=undefined
LDFLAGS = -no-pie

CFLAGS ?= $(CFLAGS_DEBUG)

SRC_DIR = src
OBJ_DIR = obj
TARGET = ouroboros

SOURCES = $(SRC_DIR)/main.c \
          $(SRC_DIR)/anti_debug.c \
          $(SRC_DIR)/self_modify.c \
          $(SRC_DIR)/key_fragments.c \
          $(SRC_DIR)/aes_crypto.c

OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean rebuild debug release sanitize test help

all: debug

help:
	@echo "Ouroboros CTF Challenge - Build System"
	@echo "======================================"
	@echo "Available targets:"
	@echo "  make           - Build debug version (default)"
	@echo "  make debug     - Build with debug symbols and no optimization"
	@echo "  make release   - Build optimized version for release"
	@echo "  make sanitize  - Build with address and undefined behavior sanitizers"
	@echo "  make test      - Build and run solution script to verify"
	@echo "  make clean     - Remove build artifacts"
	@echo "  make rebuild   - Clean and rebuild"
	@echo ""

debug: CFLAGS := $(CFLAGS_DEBUG)
debug: $(TARGET)

release: CFLAGS := $(CFLAGS_RELEASE)
release: clean $(TARGET)

sanitize: CFLAGS := $(CFLAGS_SANITIZE)
sanitize: LDFLAGS += -fsanitize=address -fsanitize=undefined
sanitize: clean $(TARGET)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CC) $(LDFLAGS) $(OBJECTS) -o $(TARGET)
	@echo ""
	@echo "========================================="
	@echo "  ⚡ OUROBOROS binary created! ⚡       "
	@echo "========================================="
	@echo "Build mode: $(if $(findstring -O2,$(CFLAGS)),RELEASE,$(if $(findstring sanitize,$(CFLAGS)),SANITIZE,DEBUG))"
	@echo ""

test: $(TARGET)
	@echo "Running test with solution script..."
	@echo "yes" | python3 solution/solve.py || true
	@echo "Test completed!"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OBJ_DIR) $(TARGET)
	@echo "Clean complete!"

rebuild: clean all
