# Hướng dẫn Build trên Windows

## Yêu cầu hệ thống

### 1. Python 3.8 trở lên
Download từ: https://www.python.org/downloads/

**Lưu ý**: Trong quá trình cài đặt, nhớ tick "Add Python to PATH"

### 2. Microsoft Visual C++ Build Tools
Download từ: https://visualstudio.microsoft.com/visual-cpp-build-tools/

**Components cần cài đặt**:
- MSVC v143 - VS 2022 C++ x64/x86 build tools (hoặc mới hơn)
- Windows 11 SDK (hoặc Windows 10 SDK)
- C++ CMake tools for Windows

### 3. OpenSSL (optional - thường đã có trong Python)
Nếu build bị lỗi thiếu OpenSSL, download từ: https://slproweb.com/products/Win32OpenSSL.html
- Chọn phiên bản "Win64 OpenSSL v3.x.x" (Light version cũng đủ)

---

## Cách 1: Build và chạy trực tiếp Python

### Bước 1: Build C extensions
```cmd
build_simple.bat
```

Script này sẽ:
- Cài đặt `pycryptodome`
- Build các C extensions (.pyd files)

### Bước 2: Chạy challenge
```cmd
run_challenge.bat
```

Hoặc chạy thủ công:
```cmd
python src\main.py
```

---

## Cách 2: Build thành file .EXE standalone

### Bước 1: Chạy build script
```cmd
build_exe.bat
```

Script này sẽ:
1. Cài đặt dependencies (pycryptodome, pyinstaller)
2. Build C extensions
3. Package thành file .exe với PyInstaller

### Bước 2: Executable sẽ được tạo trong thư mục `dist/`
```
dist/
└── ouroboros_challenge.exe
```

### Bước 3: Chạy challenge
```cmd
cd dist
ouroboros_challenge.exe
```

---

## Xử lý lỗi thường gặp

### Lỗi: "error: Microsoft Visual C++ 14.0 or greater is required"
**Nguyên nhân**: Chưa cài đặt Visual C++ Build Tools

**Giải pháp**: 
1. Download và cài đặt Visual Studio Build Tools (link ở trên)
2. Chọn workload "Desktop development with C++"
3. Đảm bảo MSVC và Windows SDK được chọn

### Lỗi: "openssl/aes.h: No such file or directory"
**Nguyên nhân**: Thiếu OpenSSL development files

**Giải pháp**:
1. Download và cài đặt Win64 OpenSSL
2. Thêm OpenSSL vào System PATH:
   - Mặc định: `C:\Program Files\OpenSSL-Win64\bin`

### Lỗi: "Segmentation fault" khi chạy
**Nguyên nhân**: Anti-debugging và self-modifying code đang active

**Giải pháp**: Chạy với demo mode:
```cmd
set OUROBOROS_DEMO=1
python src\main.py
```

### Lỗi: "Module not found: crypto_extension"
**Nguyên nhân**: C extensions chưa được build hoặc không ở đúng folder

**Giải pháp**:
1. Chạy lại `build_simple.bat`
2. Đảm bảo các file `.pyd` nằm cùng thư mục với script

---

## Phân phối cho người giải

### Option 1: Phân phối source code
Gửi toàn bộ thư mục `ouroboros/` cùng với:
- `build_simple.bat` - để build
- `run_challenge.bat` - để chạy
- `WINDOWS_BUILD_GUIDE.md` - hướng dẫn

**Ưu điểm**: Người giải có thể phân tích source code (harder challenge)

### Option 2: Phân phối file .EXE
Chỉ gửi file `dist/ouroboros_challenge.exe`

**Ưu điểm**: 
- Dễ chạy
- Khó reverse engineer hơn (binary analysis required)
- Standalone, không cần cài Python

**Lưu ý**: File .exe khá lớn (~15-20MB) do embed Python runtime

### Option 3: Phân phối .pyd files + Python script
Gửi:
- `*.pyd` files (compiled C extensions)
- `main.py`
- `requirements.txt`

**Ưu điểm**: Cân bằng giữa dễ chạy và khó reverse

---

## Demo mode vs Full challenge

### Demo mode (OUROBOROS_DEMO=1)
- Bypass anti-debugging checks
- Bypass self-modifying code
- Dùng để test và demo

### Full challenge mode
- Kích hoạt tất cả security features:
  - Ptrace anti-debug (Linux)
  - IsDebuggerPresent check (Windows)
  - Timing attack detection
  - Self-modifying code
  - Code integrity verification

**Để tắt demo mode và kích hoạt full challenge**:
```cmd
REM Xóa environment variable
set OUROBOROS_DEMO=

REM Chạy challenge
python src\main.py
```

---

## Kiểm tra build thành công

Sau khi build, bạn nên thấy:
```
ouroboros/
├── crypto_extension.pyd
├── fragments.pyd
├── anti_analysis.pyd
├── self_modify.pyd
└── build/
    └── ... (build artifacts)
```

Chạy để test:
```cmd
python src\main.py
```

Output mong đợi:
```
============================================================
    🐍 O U R O B O R O S  -  Advanced RE Challenge
============================================================
    Self-Modifying Code • Fragmented AES • Anti-Debug
    Difficulty: ⭐⭐⭐⭐⭐ (Extreme)

[+] Initializing cryptographic core...
[+] Loading fragmented key modules...
...
[*] Encrypted Flag: [hex string]
...
```

---

## Tùy chỉnh challenge

### Thay đổi flag
Edit file `src/main.py`, dòng 44:
```python
flag = "VNFLAG{YOUR_CUSTOM_FLAG_HERE}"
```

### Tăng/giảm độ khó
- Bật/tắt demo mode
- Sửa timing thresholds trong `src/crypto_extension.c`
- Thay đổi fragment algorithms

### Recompile sau khi sửa
```cmd
build_simple.bat
```

---

## Troubleshooting

Nếu gặp vấn đề, kiểm tra:
1. ✅ Python đã cài và trong PATH: `python --version`
2. ✅ Visual C++ Build Tools đã cài
3. ✅ OpenSSL có trong system (nếu cần)
4. ✅ Chạy command prompt với quyền Administrator
5. ✅ Antivirus không block file .pyd/.exe

Nếu vẫn không được, thử:
```cmd
python -m pip install --upgrade pip setuptools wheel
python -m pip install pycryptodome --force-reinstall
```
