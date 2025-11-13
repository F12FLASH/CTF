# Ouroboros Challenge - Complete Writeup

## Table of Contents
1. [Initial Analysis](#initial-analysis)
2. [Anti-Debugging Bypass](#anti-debugging-bypass)
3. [Static Analysis](#static-analysis)
4. [Key Fragment Extraction](#key-fragment-extraction)
5. [Decryption](#decryption)
6. [Automation](#automation)

---

## Initial Analysis

### Running the Binary

First, let's try running the binary:

```bash
./ouroboros
```

Output:
```
  ╔═══════════════════════════════════════════════════════╗
  ║           ⚡ OUROBOROS CHALLENGE ⚡                   ║
  ╚═══════════════════════════════════════════════════════╝

[*] Initializing anti-debugging mechanisms...
Debugger detected via PTRACE_TRACEME!
```

The binary immediately detects and exits. This is our first obstacle.

### Binary Information

```bash
file ouroboros
```

Output:
```
ouroboros: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
for GNU/Linux 3.2.0, with debug info, not stripped
```

Key observations:
- 64-bit ELF binary
- Not stripped (symbols present - easier to analyze)
- Dynamically linked

---

## Anti-Debugging Bypass

### Method 1: LD_PRELOAD Hook

The binary uses `ptrace(PTRACE_TRACEME, ...)` to detect debuggers. We can override this function.

Create `ptrace_bypass.c`:

```c
#include <sys/types.h>

long ptrace(int request, int pid, void *addr, void *data) {
    return 0;  // Always return success
}
```

Compile as shared library:

```bash
gcc -shared -fPIC ptrace_bypass.c -o libptrace_bypass.so
```

Run with bypass:

```bash
LD_PRELOAD=./libptrace_bypass.so ./ouroboros
```

**Problem:** The binary also checks `/proc/self/status` for TracerPid!

### Method 2: Static Analysis (Recommended)

Instead of running the binary, we'll extract everything we need statically.

---

## Static Analysis

### Examining Strings

```bash
strings ouroboros | grep -i flag
```

We can find references to encryption but not the flag itself (it's encrypted).

### Disassembly

```bash
objdump -d ouroboros > disassembly.txt
```

Look for interesting functions:
- `get_fragment_0` through `get_fragment_9`
- `assemble_key`
- `aes_decrypt`

### Finding Key Fragments

The fragments are static data. Let's dump the data section:

```bash
objdump -s -j .data ouroboros
```

Or use a Python script to search for all fragments:

```python
with open('ouroboros', 'rb') as f:
    data = f.read()

fragments = [
    b'\x6b\x65\x79',  # "key"
    b'\x5f\x66\x72',  # "_fr"
    b'\x61\x67\x6d',  # "agm"
    b'\x65\x6e\x74',  # "ent"
    b'\x5f\x64\x61',  # "_da"
    b'\x74\x61\x5f',  # "ta_"
    b'\x73\x65\x63',  # "sec"
    b'\x72\x65\x74',  # "ret"
    b'\x5f\x6b\x65',  # "_ke"
    b'\x79\x21\x21'   # "y!!"
]

for i, frag in enumerate(fragments):
    offset = data.find(frag)
    print(f"Fragment {i}: {frag.hex()} at offset 0x{offset:x}")
```

---

## Key Fragment Extraction

### Understanding the Key Structure

From `key_fragments.c`, we see:

```c
static uint8_t fragment_0[] = {0x6b, 0x65, 0x79};  // 3 bytes
static uint8_t fragment_1[] = {0x5f, 0x66, 0x72};  // 3 bytes
// ... total 10 fragments × 3 bytes = 30 bytes
// + 2 null bytes = 32 bytes total
```

### Assembling the Key

```python
fragments = [
    b'\x6b\x65\x79',
    b'\x5f\x66\x72',
    b'\x61\x67\x6d',
    b'\x65\x6e\x74',
    b'\x5f\x64\x61',
    b'\x74\x61\x5f',
    b'\x73\x65\x63',
    b'\x72\x65\x74',
    b'\x5f\x6b\x65',
    b'\x79\x21\x21'
]

key = b''.join(fragments) + b'\x00\x00'
print(f"Key: {key.hex()}")
# Output: 6b65795f667261676d656e745f646174615f7365637265745f6b657921210000
```

The assembled key is: `key_fragment_data_secret_key!!\x00\x00`

---

## Decryption

### Understanding the Encryption

From `aes_crypto.c`:

```c
void simple_xor_encrypt(const uint8_t *input, size_t len, 
                        const uint8_t *key, uint8_t *output) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % 32] ^ sbox[i % 256];
    }
}
```

The "AES" is actually:
1. XOR with key (cycling every 32 bytes)
2. XOR with S-box (cycling every 256 bytes)

Since XOR is its own inverse: `decrypt = encrypt`

### Extracting Encrypted Flag

From the binary:

```bash
objdump -s -j .rodata ouroboros | grep -A5 encrypted_flag
```

Or extract from source/disassembly:

```python
encrypted_flag = bytes([
    0x6e, 0x75, 0x6f, 0x43, 0xef, 0x74, 0x3d, 0xcf,
    0x6d, 0x16, 0x70, 0x00, 0xc5, 0xc6, 0xa7, 0x72,
    0xf4, 0xb0, 0x8e, 0x6b, 0xed, 0x18, 0x50, 0xdb,
    0xc2, 0xca, 0xb5, 0xe6, 0xdf, 0xb5, 0x00, 0xf0,
    0xaf, 0xc7, 0x99, 0x4a, 0x3c, 0x2b, 0xc9, 0xc6,
    0x69, 0xa4, 0xba, 0xe3, 0x57, 0x8d, 0x3e, 0x06,
    0x18
])
```

### Implementing Decryption

```python
def decrypt_flag(encrypted, key):
    sbox = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 
        # ... (full S-box from source code)
    ])
    
    decrypted = bytearray()
    for i in range(len(encrypted)):
        decrypted.append(encrypted[i] ^ key[i % 32] ^ sbox[i % 256])
    
    return decrypted.decode('ascii')

flag = decrypt_flag(encrypted_flag, key)
print(f"Flag: {flag}")
```

### Result

```
Flag: flag{m3m0ry_dump_m4st3r_0ur0b0r0s_s3lf_m0d1fy1ng}
```

---

## Automation

The complete solution can be automated in Python. See `solution/solve.py` for the full implementation.

### Key Steps

1. **Load binary** and search for fragment patterns
2. **Extract fragments** from binary data
3. **Assemble key** by concatenating fragments
4. **Extract encrypted flag** from binary
5. **Implement decryption** algorithm
6. **Decrypt and print** the flag

### Running the Solution

```bash
python solution/solve.py
```

---

## Alternative Approaches

### Dynamic Analysis (Advanced)

If you want to extract the key from memory:

1. **Bypass ptrace** with LD_PRELOAD
2. **Attach GDB** to the process
3. **Set breakpoint** on `assemble_key` function
4. **Dump memory** after key assembly
5. **Extract key** from memory dump

Example GDB commands:

```gdb
break assemble_key
run
# After breakpoint hits
x/32xb $rdi  # Examine key buffer (first argument)
```

### Frida Hooking

Use Frida to hook functions at runtime:

```javascript
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        console.log("ptrace called, returning 0");
    },
    onLeave: function(retval) {
        retval.replace(0);
    }
});
```

---

## Lessons Learned

1. **Anti-debugging is not foolproof** - Multiple bypass methods exist
2. **Static analysis is powerful** - Often faster than dynamic analysis
3. **Custom crypto is weak** - XOR-based encryption is easily reversible
4. **Debug symbols help** - Not stripped binary made analysis easier
5. **Fragmentation adds complexity** - But doesn't prevent extraction

---

## Difficulty Analysis

**Time to Solve:** 2-4 hours for experienced CTF players

**Skills Required:**
- Binary analysis (objdump, strings, hexdump)
- Understanding of ELF format
- Python scripting
- Basic cryptography knowledge
- Linux debugging tools (optional)

**Difficulty Rating:** 7/10 (Master Hacker)

---

## Flag

```
flag{************************************}
```

Congratulations on solving Ouroboros! 🐍
