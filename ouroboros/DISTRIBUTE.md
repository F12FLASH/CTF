# Hướng dẫn phân phối Challenge cho người giải

## 3 cách phân phối

### 📦 Option 1: Source Code (Khó nhất)

**Gửi toàn bộ thư mục source code**

Bao gồm:
```
ouroboros/
├── src/                    # C source code và Python
├── build.bat               # Build script
├── run_challenge.bat       # Run script
├── requirements.txt        # Python dependencies
├── README.md              # Challenge description
└── WINDOWS_BUILD_GUIDE.md # Build instructions
```

**Ưu điểm**:
- Người giải có thể đọc source code (tăng độ khó)
- Yêu cầu hiểu cả C và Python
- Full reverse engineering experience

**Nhược điểm**:
- Người giải phải tự build
- Cần cài đặt nhiều tools

**Phù hợp**: CTF competitions, advanced reverse engineers

---

### 🚀 Option 2: Standalone .EXE (Khuyên dùng)

**Build thành file .exe và phân phối**

#### Bước 1: Build .EXE
```cmd
cd ouroboros
build_exe.bat
```

#### Bước 2: Lấy file executable
```
dist/ouroboros_challenge.exe  (~ 15-20 MB)
```

#### Bước 3: Gửi cho người giải
Chỉ cần gửi file `.exe` này, kèm theo một file hướng dẫn đơn giản:

**challenge_info.txt**:
```
========================================
  OUROBOROS - CTF Reverse Engineering
========================================

Chạy file: ouroboros_challenge.exe

Nhiệm vụ: 
- Decrypt flag được mã hóa bằng AES
- AES key được chia thành 10 fragments
- Bypass anti-debugging protections
- Reverse engineer key combination algorithm

Flag format: VNFLAG{...}

Difficulty: ⭐⭐⭐⭐⭐
```

**Ưu điểm**:
- Dễ chạy nhất (double-click là xong)
- Không cần Python, không cần build
- Binary analysis required (harder to reverse)
- Professional CTF style

**Nhược điểm**:
- File size lớn (~15-20MB)
- Windows only

**Phù hợp**: CTF competitions, workshops, demonstrations

---

### ⚙️ Option 3: Pre-built Extensions (Trung bình)

**Build sẵn C extensions, gửi kèm Python script**

#### Bước 1: Build extensions
```cmd
cd ouroboros
build_simple.bat
```

#### Bước 2: Package files
Gửi:
```
challenge_package/
├── crypto_extension.pyd    # Compiled C extension
├── fragments.pyd           # Compiled C extension
├── anti_analysis.pyd       # Compiled C extension
├── self_modify.pyd         # Compiled C extension
├── main.py                 # Python main script
├── requirements.txt        # pycryptodome
└── README.txt             # Instructions
```

**README.txt**:
```
OUROBOROS CTF Challenge

Requirements:
- Python 3.8+

Installation:
1. pip install -r requirements.txt
2. python main.py

Flag format: VNFLAG{...}
```

**Ưu điểm**:
- Không cần build tools
- File size nhỏ hơn .exe
- Có thể xem Python code, nhưng C code đã compile

**Nhược điểm**:
- Cần Python
- Không hoàn toàn standalone

**Phù hợp**: Internal challenges, training sessions

---

## Chi tiết từng bước

### 🔨 Build .EXE chi tiết

1. **Chuẩn bị môi trường**:
```cmd
python -m pip install --upgrade pip
python -m pip install pycryptodome pyinstaller
```

2. **Build C extensions**:
```cmd
python build_extension.py build_ext --inplace
```

3. **Create executable**:
```cmd
pyinstaller --onefile ^
    --name=ouroboros_challenge ^
    --hidden-import=crypto_extension ^
    --hidden-import=fragments ^
    --hidden-import=anti_analysis ^
    --hidden-import=self_modify ^
    --add-binary="crypto_extension.pyd;." ^
    --add-binary="fragments.pyd;." ^
    --add-binary="anti_analysis.pyd;." ^
    --add-binary="self_modify.pyd;." ^
    --console ^
    main.py
```

4. **Test executable**:
```cmd
cd dist
ouroboros_challenge.exe
```

5. **Zip và gửi**:
```cmd
7z a ouroboros_challenge.zip ouroboros_challenge.exe challenge_info.txt
```

---

## Tùy chỉnh Challenge

### Thay đổi Flag
Edit `src/main.py`:
```python
flag = "VNFLAG{YOUR_CUSTOM_FLAG_HERE}"
```

### Điều chỉnh độ khó

**Dễ hơn** (demo mode):
- Set environment variable `OUROBOROS_DEMO=1`
- Bypass anti-debugging
- Bypass self-modification

**Khó hơn**:
- Xóa OUROBOROS_DEMO check trong source
- Tăng timing thresholds
- Thêm nhiều obfuscation layers

### Rebuild sau khi sửa
```cmd
build_simple.bat    # hoặc
build_exe.bat
```

---

## Testing trước khi phân phối

### Test với demo mode
```cmd
set OUROBOROS_DEMO=1
python src\main.py
```

Output mong đợi:
```
============================================================
    🐍 O U R O B O R O S  -  Advanced RE Challenge
============================================================
...
[*] Encrypted Flag: [long hex string]
[!] Security Features Active:
    • 10-Way Key Fragmentation
    • Runtime Self-Modification
    • Advanced Anti-Debugging
    ...
============================================================
```

### Test full challenge (no demo)
```cmd
set OUROBOROS_DEMO=
python src\main.py
```

Có thể sẽ exit ngay nếu anti-debugging kicks in (đây là hành vi đúng).

### Test .EXE
```cmd
cd dist
ouroboros_challenge.exe
```

---

## Package Examples

### Example 1: Competition Package (.exe)
```
ouroboros_ctf.zip
├── ouroboros_challenge.exe
└── README.txt
      "Run the exe, find the flag. No internet access needed."
```

### Example 2: Training Package (source)
```
ouroboros_training.zip
├── ouroboros/
│   ├── src/
│   ├── build.bat
│   └── ...
├── WINDOWS_BUILD_GUIDE.md
└── README.txt
      "Build yourself. Read the source if stuck."
```

### Example 3: Workshop Package (.pyd)
```
ouroboros_workshop.zip
├── *.pyd
├── main.py
├── requirements.txt
└── README.txt
      "Install Python, run main.py. No compilation needed."
```

---

## Checklist phân phối

- [ ] Test challenge chạy được trên máy clean (không có dev tools)
- [ ] Verify encrypted flag output khác nhau mỗi lần chạy (nếu có randomness)
- [ ] Kiểm tra flag format đúng (VNFLAG{...})
- [ ] Test anti-debugging features hoạt động
- [ ] Tạo README/instructions rõ ràng
- [ ] Zip files an toàn (check antivirus false positives)
- [ ] Test unzip và chạy trên máy khác
- [ ] Chuẩn bị solution/writeup (để verify)

---

## Lưu ý bảo mật

⚠️ **QUAN TRỌNG**: 

1. **Không hardcode flag trong binary**
   - Flag được generate runtime từ encryption
   - Safe to distribute

2. **Self-modifying code warning**
   - Một số antivirus có thể flag .exe/.pyd
   - Thông báo trước cho participants
   - Test trên VirusTotal trước khi phân phối

3. **Demo mode**
   - Đảm bảo OUROBOROS_DEMO không được set mặc định trong distribution
   - Hoặc remove demo code hoàn toàn trước khi build

---

## Support & Troubleshooting

Chuẩn bị FAQ cho người giải:

**Q: "Antivirus blocks the .exe"**
A: This is a false positive. The challenge uses self-modifying code for anti-debugging. You can:
   - Add exception to antivirus
   - Run in VM
   - Build from source yourself

**Q: "Program exits immediately"**
A: Anti-debugging is active. This is intentional. You need to bypass it.

**Q: "How to decrypt the flag?"**
A: That's the challenge! Hints: dynamic analysis, memory dumps, understand the 10 key fragments.

---

Chúc bạn thành công với CTF challenge! 🎯
