# 🐍 Ouroboros - Extreme Reverse Engineering Challenge

![Difficulty](https://img.shields.io/badge/Difficulty-⭐⭐⭐⭐⭐-red) ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue) ![Category](https://img.shields.io/badge/Category-Reverse%20Engineering-purple)

## 📋 Challenge Overview

**Ouroboros** is an advanced self-modifying binary that implements state-of-the-art anti-reverse engineering techniques. The challenge involves decrypting a flag encrypted with AES, where the encryption key is fragmented across 10 different functions and protected by multiple layers of security mechanisms.

> **Warning**: This challenge is designed for experienced reverse engineers. Beginners may find it extremely difficult.

## 🏗️ Project Structure

```
ouroboros/
├── src/
│   ├── main.py                 # Main challenge executable
│   ├── crypto_extension.c      # Core encryption with anti-debug
│   ├── fragments.c             # Key fragment generators
│   ├── anti_analysis.c         # Advanced anti-RE techniques
│   ├── self_modify.c           # Self-modifying code implementation
│   └── obfuscator.py           # Code obfuscation utilities
├── build.bat                   # Windows build script
├── build_extension.py          # Python extension builder
├── solve.py                    # Reference solution (incomplete)
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## ⚡ Quick Start

### Prerequisites

- **Python 3.8+**
- **C Compiler** (GCC on Linux, Visual Studio Build Tools on Windows)
- **OpenSSL development libraries**

### Installation

#### Windows
```cmd
# Install Visual C++ Build Tools from:
# https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Then run:
build.bat
```

#### Linux
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y python3-dev build-essential libssl-dev

# Build and run
chmod +x build.sh
./build.sh
```

### Running the Challenge
```bash
python main.py
```

## 🔥 Challenge Features

### 🛡️ Multi-Layer Protection System

#### 1. **10-Way Key Fragmentation**
- AES key split into 10 fragments
- Each fragment uses unique generation algorithm:
  - Mathematical sequences with transformations
  - Prime number-based computations
  - Fibonacci-inspired sequences with twists
  - Trigonometric approximations
  - Bit manipulation cascades
  - Complex polynomial functions

#### 2. **Runtime Self-Modification**
- Code modifies its own instructions during execution
- Multiple modification layers:
  - XOR-based byte modification
  - Addition-based transformation
  - Bit rotation patterns
- Uses `mprotect()` to make code pages writable

#### 3. **Advanced Anti-Debugging**
- **Ptrace Detection**: Immediate exit if being traced
- **Timing Attacks**: Measures execution time to detect debuggers
- **Environment Checks**: Detects debugger environment variables
- **Integrity Verification**: Checksum-based code tamper detection

#### 4. **Complex Key Combination**
3-stage key reconstruction process:
```c
// Stage 1: XOR combination with rotation
for (i = 0; i < 10; i++) {
    for (j = 0; j < 16; j++) {
        stage1_key[j] ^= fragments[i][(j + i) % 16];
    }
}

// Stage 2: Mathematical transformation
for (i = 0; i < 16; i++) {
    stage2_key[i] = (stage1_key[i] * 3 + stage1_key[(i + 1) % 16]) % 256;
    stage2_key[i] ^= fragments[i % 10][(i + 3) % 16];
}

// Stage 3: Final complex transformation
for (i = 0; i < 16; i++) {
    final_key[i] = ((stage2_key[i] << 4) | (stage2_key[i] >> 4)) & 0xFF;
    final_key[i] ^= 0xAB;
    final_key[i] = (final_key[i] + 0xCD) % 256;
    final_key[i] = ((final_key[i] & 0x55) << 1) | ((final_key[i] & 0xAA) >> 1);
}
```

## 🎯 Solution Methodology

### Required Skills
- **Advanced Dynamic Analysis**
- **Memory Forensics**
- **C Code Reverse Engineering**
- **Cryptographic Analysis**
- **Anti-Debugging Bypass Techniques**

### Step-by-Step Approach

#### Phase 1: Environment Setup
1. **Prepare Analysis Tools**:
   - IDA Pro/Ghidra for static analysis
   - GDB with PEDA/Pwndbg for dynamic analysis
   - Memory dumping tools
   - Python for automation

2. **Bypass Anti-Debugging**:
   - Patch ptrace checks
   - Bypass timing detection
   - Neutralize environment checks

#### Phase 2: Dynamic Analysis
1. **Trace Execution**:
   ```bash
   gdb -q python
   (gdb) set follow-fork-mode child
   (gdb) break crypto_extension.c:encrypt_flag
   (gdb) run main.py
   ```

2. **Memory Analysis**:
   - Dump memory regions containing key fragments
   - Trace key combination process
   - Extract intermediate key states

3. **Self-Modification Monitoring**:
   - Set breakpoints on code modification routines
   - Compare code before/after modification
   - Understand modification patterns

#### Phase 3: Key Reconstruction
1. **Fragment Extraction**:
   - Identify all 10 fragment generation algorithms
   - Understand each algorithm's mathematical basis
   - Replicate fragment generation in solving script

2. **Combination Algorithm Reverse Engineering**:
   - Analyze the 3-stage combination process
   - Understand transformation sequences
   - Replicate exact key derivation

#### Phase 4: Decryption
1. **AES Parameters**:
   - Mode: CBC
   - IV: `00` * 16
   - Key Size: 128-bit

2. **Decryption Implementation**:
   ```python
   from Crypto.Cipher import AES
   
   cipher = AES.new(reconstructed_key, AES.MODE_CBC, iv=b'\x00'*16)
   decrypted = cipher.decrypt(encrypted_flag)
   ```

## 🛠️ Technical Details

### Encryption Flow
```
Flag Input
    ↓
Anti-Debugging Checks
    ↓
Fragment Generation (10 fragments)
    ↓
Self-Modification Execution
    ↓
3-Stage Key Combination
    ↓
AES-128-CBC Encryption
    ↓
Hex-Encoded Output
```

### Key Fragment Algorithms

| Fragment | Algorithm Type | Complexity |
|----------|----------------|------------|
| 0 | Multi-layer mathematical transformation | High |
| 1 | Prime-based with bit manipulation | High |
| 2 | Fibonacci with XOR transformations | Medium |
| 3 | Trigonometric approximation | High |
| 4 | Exponential/logarithmic | High |
| 5 | Bit reversal with XOR chain | Medium |
| 6 | Complex polynomial | High |
| 7 | Modular arithmetic | Medium |
| 8 | Logical operations cascade | High |
| 9 | Mixed transformations | Very High |

### Anti-Analysis Techniques

| Technique | Implementation | Bypass Method |
|-----------|----------------|---------------|
| Ptrace Detection | `ptrace(PTRACE_TRACEME, 0, 1, 0)` | Patch or hook |
| Timing Analysis | Execution time measurement | NOP instructions |
| Environment Checks | `getenv("DEBUG")` etc. | Environment cleanup |
| Integrity Verification | Code checksums | Checksum patching |

## 📊 Difficulty Assessment

### Time Estimates
| Skill Level | Estimated Solve Time | Success Rate |
|-------------|---------------------|--------------|
| Beginner | 50+ hours | <5% |
| Intermediate | 20-30 hours | 15% |
| Advanced | 8-15 hours | 40% |
| Expert | 4-8 hours | 75% |

### Skills Tested
- ✅ Advanced C reverse engineering
- ✅ Cryptographic analysis
- ✅ Anti-debugging bypass
- ✅ Dynamic analysis
- ✅ Memory forensics
- ✅ Algorithm understanding
- ✅ Python scripting for automation

## 🏆 Flag Information

**Flag Format**: `VNFLAG{...}`

**Actual Flag**: `VNFLAG{TOQUOC_VIETNAM_UNG_HO_NHAN_DAT_#TQVN_9a3F6b2Kx4P1R8L0zQ7Y5s}`

**Validation**: The flag will be revealed only after successful decryption using the properly reconstructed AES key.

## 🚀 Solving Tools Recommendation

### Essential Tools
- **Static Analysis**: IDA Pro, Ghidra, Binary Ninja
- **Dynamic Analysis**: GDB with PEDA, Radare2, x64dbg
- **Memory Analysis**: Volatility, custom memory dump scripts
- **Cryptography**: Python Crypto libraries, OpenSSL

### Recommended Plugins
- **GDB**: PEDA, Pwndbg, GEF
- **IDA**: Keypatch, LazyIDA, FindCrypt
- **Python**: pwntools, capstone, unicorn

## 💡 Pro Tips

1. **Start with Static Analysis**: Understand the overall structure before dynamic analysis
2. **Bypass Anti-Debug Systematically**: Handle one protection at a time
3. **Use Memory Breakpoints**: Set breakpoints on key memory regions
4. **Automate Fragment Extraction**: Write scripts to dump and analyze fragments
5. **Validate Incrementally**: Test each fragment and combination stage separately

## 🐛 Common Issues & Solutions

### Build Issues
**Problem**: `error: Microsoft Visual C++ 14.0 or greater is required`
**Solution**: Install Visual Studio Build Tools with C++ support

**Problem**: `openssl/aes.h: No such file or directory`
**Solution**: Install OpenSSL development packages

### Runtime Issues
**Problem**: Immediate exit with "Debugger detected"
**Solution**: Use patched binary or debugger bypass techniques

**Problem**: Inconsistent encryption results
**Solution**: Ensure all fragment algorithms are correctly replicated

## 📝 License & Acknowledgments

This challenge is created for educational purposes and reverse engineering practice. All code is original and designed specifically for this challenge.

---

## 🎯 Final Notes

This challenge represents the cutting edge of anti-reverse engineering techniques. Successfully solving it demonstrates expert-level skills in binary analysis, cryptography, and anti-debugging bypass.

**Happy Reversing! 🐍**

---

*Last Updated: 2025 | Challenge Version: 2.0 | Author: F12FLASH*