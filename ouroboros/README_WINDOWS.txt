========================================
  OUROBOROS CTF CHALLENGE
  Windows Build & Run Instructions
========================================

CÁC BƯỚC NHANH:

1. Chạy build.bat để build challenge
2. Chạy run_challenge.bat để chạy challenge

========================================

CHI TIẾT:

YÊU CẦU:
- Python 3.8 trở lên (https://www.python.org/downloads/)
- Microsoft Visual C++ Build Tools 
  (https://visualstudio.microsoft.com/visual-cpp-build-tools/)

CÁC FILE .BAT:

build.bat hoặc build_simple.bat
  → Build C extensions
  → Chạy file này đầu tiên!

build_exe.bat
  → Build thành file .EXE standalone
  → Cần PyInstaller
  → File .exe sẽ nằm trong thư mục dist/

run_challenge.bat
  → Chạy challenge sau khi đã build

========================================

CÁCH PHÂN PHỐI:

Option 1: Source code
  → Gửi toàn bộ thư mục ouroboros/
  → Người giải phải tự build

Option 2: File .EXE  
  → Chạy build_exe.bat
  → Gửi file dist/ouroboros_challenge.exe
  → Không cần Python, chạy trực tiếp

Option 3: Pre-built extensions
  → Build và gửi các file .pyd + main.py
  → Người giải cần Python nhưng không cần build

========================================

XỬ LÝ LỖI:

"Microsoft Visual C++ 14.0 required"
  → Cài Visual C++ Build Tools (link trên)
  → Chọn workload "Desktop development with C++"

"openssl/aes.h not found"
  → Cài Win64 OpenSSL từ:
    https://slproweb.com/products/Win32OpenSSL.html

"Segmentation fault"
  → Chạy với demo mode:
    set OUROBOROS_DEMO=1
    python src\main.py

========================================

CHALLENGE INFO:

Flag Format: VNFLAG{...}

Security Features:
  • 10-Way Key Fragmentation
  • Runtime Self-Modification
  • Advanced Anti-Debugging
  • Code Integrity Verification
  • Timing Attack Protection

Difficulty: ⭐⭐⭐⭐⭐ (Extreme)

========================================

Xem WINDOWS_BUILD_GUIDE.md để biết thêm chi tiết!
