Stackless Stack Challenge Files
================================

This archive contains:

1. stackless_stack - The vulnerable x86-64 binary
2. stackless_stack.c - Source code (for analysis)

Challenge Details:
- Architecture: x86-64
- Vulnerability: Buffer overflow in mmap'd region
- Protection: NX enabled, No PIE, No canary
- Difficulty: Master Hacker

Exploitation Path:
1. Analyze the binary to find the overflow
2. Locate ROP gadgets for syscall construction
3. Build ROP chain to call mprotect
4. Change memory permissions to RWX
5. Execute shellcode to get flag

Good luck!

Flag format: VNFLAG{...}
