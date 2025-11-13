# 🐍 Ouroboros - Thử Thách Reverse Engineering Nâng Cao

<div align="center">

```
  ╔═══════════════════════════════════════════════════════╗
  ║                                                       ║
  ║           ⚡ THỬ THÁCH OUROBOROS ⚡                  ║
  ║                                                       ║
  ║     Con rắn tự nuốt đuôi của chính mình...            ║
  ║     Mã tự sửa đổi tiết lộ sự thật ẩn giấu             ║
  ║                                                       ║
  ║              Độ khó: BẬC THẦY                         ║
  ║                                                       ║
  ╚═══════════════════════════════════════════════════════╝
```

**Một thử thách reverse engineering CTF cấp độ master với mã tự sửa đổi, kỹ thuật chống debug nâng cao và trích xuất khóa phân mảnh.**

[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.kernel.org/)
[![Language](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Difficulty](https://img.shields.io/badge/difficulty-Master-red.svg)](https://github.com)

</div>

---

## 🎯 Tổng Quan

Ouroboros là một thử thách reverse engineering tinh vi được thiết kế cho những người tham gia CTF nâng cao và các nhà nghiên cứu bảo mật. Được đặt tên theo biểu tượng cổ xưa của con rắn tự nuốt đuôi mình, thử thách này đại diện cho một hệ thống tự chứa, tự sửa đổi bảo vệ bí mật của nó thông qua nhiều lớp bảo vệ.

### Tính Năng Chính

- **Self-Modifying ELF Binary** - Mã tự vá chính nó khi chạy
- **Multi-Layered Anti-Debugging** - Cơ chế phát hiện nâng cao (ptrace, phân tích thời gian, kiểm tra môi trường)
- **Fragmented AES Key** - Khóa mã hóa 32 byte được chia thành 10 phần trong các hàm khác nhau
- **Custom Encryption** - Mật mã XOR với thay thế S-box của AES
- **Memory Forensics** - Yêu cầu hiểu biết sâu về bố cục bộ nhớ process
- **Linux Platform** - Binary ELF Linux native (64-bit x86-64)

---

## 📖 Mô Tả Thử Thách

Bạn được cung cấp một binary ELF 64-bit chứa một cờ đã được mã hóa. Cờ được bảo vệ bởi một thuật toán mã hóa tùy chỉnh, nhưng bản thân khóa mã hóa đã được phân mảnh thành 10 phần và phân tán qua các hàm khác nhau trong bộ nhớ.

### Nhiệm Vụ Của Bạn

1. **Vượt qua cơ chế chống debug** để phân tích binary
2. **Trích xuất 10 mảnh khóa** từ bộ nhớ (mỗi mảnh 3 byte)
3. **Lắp ráp khóa hoàn chỉnh** theo đúng thứ tự (tổng cộng 32 byte)
4. **Giải mã cờ** sử dụng khóa đã tái tạo
5. **Nộp cờ** theo định dạng: `VNFLAG{...}`

### Cấp Độ Khó

**Bậc Thầy** - Thử thách này yêu cầu:
- Kiến thức nâng cao về C/Assembly
- Hiểu biết sâu về Linux internals
- Kinh nghiệm reverse engineering
- Kiến thức cơ bản về cryptography
- Kỹ năng scripting Python

**Thời Gian Giải Ước Tính:** 2-4 giờ cho người chơi CTF có kinh nghiệm

---

## 🔧 Chi Tiết Kỹ Thuật

### Kỹ Thuật Chống Debug

Binary sử dụng nhiều lớp bảo vệ:

1. **Phát Hiện PTRACE_TRACEME**
   - Sử dụng `ptrace(PTRACE_TRACEME, ...)` để phát hiện debugger
   - Chỉ một process có thể trace tại một thời điểm
   - Thất bại nếu đang được debug

2. **Giám Sát /proc/self/status**
   - Đọc trường TracerPid để phát hiện debugger đã attach
   - Kiểm tra process tracing theo thời gian thực
   - Bảo vệ Linux đặc thù nền tảng

3. **Xử Lý SIGTRAP**
   - Cài đặt signal handler tùy chỉnh
   - Phát hiện khi debugger chặn signals
   - Xác thực cơ chế phân phối signal

4. **Phân Tích Thời Gian**
   - Đo thời gian thực thi của các phần quan trọng
   - Phát hiện slowdown do breakpoints
   - Phát hiện bất thường dựa trên ngưỡng

5. **Kiểm Tra Môi Trường**
   - Phát hiện LD_PRELOAD hooks
   - Xác thực truy cập bộ nhớ process
   - Nhận diện điều kiện runtime đáng ngờ

6. **Tự Sửa Đổi**
   - Mã chỉ tiết lộ khi chạy
   - Sử dụng `mprotect` để sửa đổi quyền trang
   - Tự động vá các hàm ẩn

### Phân Mảnh Khóa

Khóa mã hóa AES (32 byte) được phân mảnh chiến lược:

- **10 mảnh** mỗi mảnh 3 byte = 30 byte
- **2 byte padding** được thêm khi lắp ráp
- Mỗi mảnh được lưu trong một hàm riêng biệt
- Các hàm chứa mã làm nhiễu:
  - Mảng giả và dữ liệu nhiễu
  - Tính toán vòng lặp phức tạp
  - Tính toán checksum
  - Chuỗi và biến giả

### Vị Trí Các Mảnh Khóa

Mỗi mảnh là 3 byte, được lưu trong các hàm `get_fragment_0()` đến `get_fragment_9()`:

```c
Mảnh 0: 0x6b, 0x65, 0x79  // "key"
Mảnh 1: 0x5f, 0x66, 0x72  // "_fr"
Mảnh 2: 0x61, 0x67, 0x6d  // "agm"
Mảnh 3: 0x65, 0x6e, 0x74  // "ent"
Mảnh 4: 0x5f, 0x64, 0x61  // "_da"
Mảnh 5: 0x74, 0x61, 0x5f  // "ta_"
Mảnh 6: 0x73, 0x65, 0x63  // "sec"
Mảnh 7: 0x72, 0x65, 0x74  // "ret"
Mảnh 8: 0x5f, 0x6b, 0x65  // "_ke"
Mảnh 9: 0x79, 0x21, 0x21  // "y!!"
Padding: 0x00, 0x00       // Null bytes (thêm khi lắp ráp)
```

**Khóa Đã Lắp Ráp (32 bytes):**
```
Bytes: 6b 65 79 5f 66 72 61 67 6d 65 6e 74 5f 64 61 74 
       61 5f 73 65 63 72 65 74 5f 6b 65 79 21 21 00 00
ASCII: "key_fragment_data_secret_key!!" + \x00\x00
```

### Thuật Toán Mã Hóa

Cờ được mã hóa sử dụng mật mã XOR tùy chỉnh:

```c
ciphertext[i] = plaintext[i] ^ key[i % 32] ^ sbox[i % 256]
```

- **Mã hóa XOR** với lựa chọn khóa phụ thuộc vị trí
- **S-box AES** cho lớp thay thế bổ sung
- **Đảo ngược được** - cùng thao tác giải mã (XOR là nghịch đảo của chính nó)
- **Lịch trình khóa** - thao tác modulo đơn giản cho xoay khóa

---

## 🚀 Bắt Đầu Nhanh

### Yêu Cầu

- **Môi Trường Linux** (Linux native hoặc WSL2 trên Windows)
  - Binary là executable ELF Linux
  - WSL1 có thể có hạn chế với ptrace
- **Trình Biên Dịch GCC** (để build từ source)
- **Python 3.11+** (cho script giải tự động)
- **Công Cụ Make** (khuyến nghị GNU Make)

### Cài Đặt

```bash
# Clone hoặc tải repository
git clone https://github.com/F12FLASH/CTF.git
cd CTF/1.Ouroboros

# Cài đặt dependencies Python (tùy chọn, cho script giải)
pip install pwntools pycryptodome
```

### Build Thử Thách

```bash
# Build phiên bản debug (mặc định)
make

# Hoặc build phiên bản debug rõ ràng
make debug

# Build phiên bản release tối ưu
make release

# Build với sanitizers (cho phát triển)
make sanitize

# Xem tất cả tùy chọn build
make help
```

### Chạy Binary

```bash
./ouroboros
```

**Kết Quả Mong Đợi:**
```
Debugger detected via PTRACE_TRACEME!
```

Đây là hành vi mong đợi! Binary phát hiện môi trường runtime Replit. Bạn cần sử dụng phân tích tĩnh hoặc kỹ thuật bypass để giải thử thách.

---

## 🔍 Giải Quyết Thử Thách

### Cách Tiếp Cận 1: Phân Tích Tĩnh (Khuyến Nghị)

Đây là phương pháp đáng tin cậy nhất và hoạt động trong mọi môi trường.

#### Bước 1: Kiểm Tra Binary

```bash
# Kiểm tra thông tin binary
file ouroboros
readelf -h ouroboros

# Tìm chuỗi thú vị
strings ouroboros | grep -i fragment
strings ouroboros | grep -i key

# Dump section data
objdump -s -j .data ouroboros > data_dump.txt

# Disassemble binary
objdump -d ouroboros > disassembly.txt
```

#### Bước 2: Định Vị Các Mảnh Khóa

Tìm kiếm 10 hàm fragment trong disassembly:
- `get_fragment_0`
- `get_fragment_1`
- ...
- `get_fragment_9`

Mỗi hàm chứa một mảng tĩnh 3 byte. Bạn có thể:

1. **Sử dụng hex editor** để tìm kiếm các mảnh
2. **Viết script Python** để quét binary
3. **Sử dụng objdump** để kiểm tra section .data
4. **Tìm kiếm pattern** trong binary

#### Bước 3: Trích Xuất Các Mảnh

Tùy Chọn A - **Trích Xuất Thủ Công:**
```bash
# Sử dụng hex editor như xxd hoặc hexdump
xxd ouroboros | grep -A 2 "fragment"
```

Tùy Chọn B - **Script Tự Động:**
```python
with open('ouroboros', 'rb') as f:
    data = f.read()
    # Tìm kiếm pattern đã biết
    fragments = [
        b'\x6b\x65\x79',  # Fragment 0
        b'\x5f\x66\x72',  # Fragment 1
        # ... etc
    ]
```

#### Bước 4: Lắp Ráp Khóa

Nối tất cả 10 mảnh theo thứ tự và thêm 2 byte null:
```python
key = b''.join(fragments) + b'\x00\x00'
# Kết quả: b'key_fragment_data_secret_key!!\x00\x00'
```

#### Bước 5: Giải Mã Cờ

Triển khai thuật toán giải mã (dựa trên XOR):

```python
def decrypt(ciphertext, key, sbox):
    plaintext = bytearray()
    for i in range(len(ciphertext)):
        plaintext.append(ciphertext[i] ^ key[i % 32] ^ sbox[i % 256])
    return plaintext
```

### Cách Tiếp Cận 2: Phân Tích Động với LD_PRELOAD

Vượt qua kiểm tra ptrace bằng cách hook hàm.

#### Bước 1: Tạo Thư Viện Bypass

Tạo `ptrace_bypass.c`:
```c
#include <sys/types.h>

long ptrace(int request, int pid, void *addr, void *data) {
    return 0;  // Luôn trả về thành công
}
```

#### Bước 2: Biên Dịch và Sử Dụng

```bash
gcc -shared -fPIC ptrace_bypass.c -o libptrace_bypass.so
LD_PRELOAD=./libptrace_bypass.so ./ouroboros
```

**Lưu ý:** Binary cũng kiểm tra `/proc/self/status` cho TracerPid, nên điều này có thể không vượt qua hoàn toàn tất cả bảo vệ.

#### Bước 3: Dump Bộ Nhớ

```bash
# Chạy với bypass
LD_PRELOAD=./libptrace_bypass.so ./ouroboros &
PID=$!

# Dump bộ nhớ process
gcore $PID

# Hoặc sử dụng gdb với bypass
LD_PRELOAD=./libptrace_bypass.so gdb ./ouroboros
```

### Cách Tiếp Cận 3: Patching Binary

Sửa đổi binary để vô hiệu hóa kiểm tra chống debug.

```bash
# Disassemble binary
objdump -d ouroboros > disasm.txt

# Tìm các lời gọi ptrace và hàm anti_debug
# Sử dụng hex editor để NOP hóa các kiểm tra
# Hoặc patch các jump điều kiện
```

---

## 🛠️ Công Cụ Cần Thiết

### Phân Tích Tĩnh

- **objdump** - Disassembler cho binary ELF
- **readelf** - Trình phân tích file ELF và xem header
- **strings** - Trích xuất chuỗi in được từ binary
- **hexdump** / **xxd** - Trình xem và chỉnh sửa hex
- **nm** - Trình xem bảng ký hiệu
- **file** - Nhận diện loại file

### Phân Tích Động

- **gdb** - GNU Debugger với extensions GEF/PEDA
- **strace** - Trình theo dõi system call
- **ltrace** - Trình theo dõi library call
- **valgrind** - Trình gỡ lỗi và phân tích bộ nhớ
- **radare2** / **ghidra** - Nền tảng reverse engineering nâng cao

### Thư Viện Python

```bash
pip install pwntools      # Framework CTF cho khai thác
pip install pycryptodome  # Thư viện cryptography
```

### Công Cụ Khuyến Nghị

- **IDA Pro** / **Binary Ninja** - Disassembler thương mại (tùy chọn)
- **Hopper** - Disassembler macOS (tùy chọn)
- **x64dbg** - Debugger Windows (cho tham chiếu chéo)

---

## 🎓 Mục Tiêu Học Tập

Bằng cách giải thử thách này, bạn sẽ có được kinh nghiệm thực hành với:

### 1. Phân Tích Binary
- Hiểu cấu trúc file ELF và các sections
- Đọc mã assembly (x86-64)
- Phân tích mã C đã biên dịch
- Nhận diện ranh giới hàm và quy ước gọi

### 2. Kỹ Thuật Chống Debug
- Nhận diện cơ chế bảo vệ thông thường
- Hiểu hành vi syscall ptrace
- Học cách vượt qua phương pháp phát hiện
- Phân tích và phát hiện dựa trên thời gian

### 3. Mã Tự Sửa Đổi
- Cách binary tự thay đổi khi chạy
- Quyền trang bộ nhớ và `mprotect`
- Tiêm mã và vá động
- Kỹ thuật tạo mã runtime

### 4. Pháp Y Bộ Nhớ
- Trích xuất dữ liệu từ bộ nhớ process
- Hiểu bố cục bộ nhớ (.text, .data, .bss)
- Làm việc với memory dump
- Phân tích trạng thái binary runtime vs static

### 5. Phân Tích Mật Mã
- Reverse engineering thuật toán mã hóa
- Hiểu mật mã dựa trên XOR
- Làm việc với lớp thay thế (S-boxes)
- Kỹ thuật phục hồi và lắp ráp khóa

### 6. Scripting và Tự Động Hóa
- Viết script Python cho phân tích binary
- Tự động hóa tác vụ reverse engineering
- Sử dụng thư viện như pwntools
- Xây dựng công cụ phân tích tùy chỉnh

---

## 🏆 Lời Giải

Một script giải tự động hoàn chỉnh được cung cấp trong `solution/solve.py`.

### ⚠️ CẢNH BÁO SPOILER ⚠️

**KHÔNG** xem lời giải cho đến khi bạn đã tự mình thử giải thử thách! Kinh nghiệm học tập đến từ việc vật lộn với vấn đề.

### Chạy Lời Giải

```bash
python solution/solve.py
```

Script sẽ:
1. Yêu cầu xác nhận (để tránh spoiler tình cờ)
2. Trích xuất các mảnh khóa sử dụng phân tích tĩnh
3. Lắp ráp khóa mã hóa hoàn chỉnh (30 byte + 2 byte null)
4. Giải mã cờ sử dụng thuật toán XOR tùy chỉnh
5. Hiển thị cờ: `VNFLAG{TOQUOC_VIETNAM_UNG_HO_NHAN_DAT_#TQVN_9a3F6b2Kx4P1R8L0zQ7Y5s}`. Ý nghĩa: "Tổ quốc Việt Nam ủng hộ nhân dân đất nước" — thể hiện tình yêu, sự ủng hộ và niềm tin vào người Việt Nam.

### Điều Lời Giải Thể Hiện

- **Phân tích binary tĩnh** để định vị các mảnh khóa
- **Khớp pattern** trong dữ liệu binary
- **Lắp ráp khóa** từ các mảnh phân tán (10 × 3 byte + 2 padding)
- **Giải mã XOR** với thay thế S-box
- **Triển khai thuần Python** (không yêu cầu thực thi binary)

---

## 🔨 Tùy Chọn Build

Makefile cung cấp nhiều cấu hình build:

### Debug Build (Mặc Định)

```bash
make
# hoặc
make debug
```

- Tối ưu: `-O0` (không)
- Debug symbols: `-g` (bao gồm)
- Macro: `-DDEBUG`
- Tốt nhất cho: Phát triển và phân tích

### Release Build

```bash
make release
```

- Tối ưu: `-O2` (cao)
- Debug symbols: Stripped
- Macro: `-DNDEBUG`
- Tốt nhất cho: Phân phối thử thách cuối cùng

### Sanitizer Build

```bash
make sanitize
```

- Address Sanitizer: Phát hiện lỗi bộ nhớ
- Undefined Behavior Sanitizer: Bắt UB
- Tốt nhất cho: Phát triển và gỡ lỗi

### Test

```bash
make test
```

- Build binary
- Chạy script giải
- Xác minh cờ có thể giải mã

### Lệnh Khác

```bash
make clean    # Xóa artifacts build
make rebuild  # Clean và build từ đầu
make help     # Hiển thị tất cả target có sẵn
```

---

## 📚 Tài Liệu Tham Khảo

### Reverse Engineering

- [Learning Linux Binary Analysis](https://www.oreilly.com/library/view/learning-linux-binary/9781782167105/) - Hướng dẫn toàn diện về phân tích ELF
- [Practical Binary Analysis](https://nostarch.com/binaryanalysis) - Kỹ thuật và công cụ hiện đại
- [The Art of Software Security Assessment](https://www.amazon.com/Art-Software-Security-Assessment/dp/0321444426) - Tìm lỗ hổng

### Chống Debug

- [Linux Anti-Debugging Techniques](https://seblau.github.io/posts/linux-anti-debugging) - Phương pháp phát hiện
- [Analysis of Anti-Analysis](https://github.com/yellowbyte/analysis-of-anti-analysis) - Danh mục toàn diện
- [Bypassing Ptrace with LD_PRELOAD](https://dev.to/nuculabs_dev/bypassing-ptrace-calls-with-ldpreload-on-linux-12jl) - Bypass dựa trên hook

### Cryptography

- [Understanding Cryptography](https://www.crypto-textbook.com/) - Cơ bản cryptography hiện đại
- [Serious Cryptography](https://nostarch.com/seriouscrypto) - Ứng dụng thực tế
- [Applied Cryptography](https://www.schneier.com/books/applied-cryptography/) - Tài liệu tham khảo cổ điển

### Tài Nguyên CTF

- [CTF Field Guide](https://trailofbits.github.io/ctf/) - Hướng dẫn CTF toàn diện
- [CTFtime](https://ctftime.org/) - Sự kiện và writeup CTF
- [LiveOverflow](https://www.youtube.com/c/LiveOverflow) - Video khai thác binary

---

## 🤝 Đóng Góp

Thử thách này được thiết kế cho mục đích giáo dục. Đóng góp được chào đón:

- 🐛 Báo lỗi hoặc vấn đề
- 💡 Đề xuất cải tiến hoặc biến thể
- 📝 Chia sẻ writeup giải của bạn
- 🎓 Tạo nội dung giáo dục
- 🌍 Dịch tài liệu

Vui lòng mở issue hoặc pull request trên repository.

---

## 📄 Giấy Phép

Dự án này được phát hành cho mục đích giáo dục. Bạn được tự do:

- Sử dụng để học tập và giảng dạy
- Sửa đổi và tạo biến thể
- Chia sẻ với ghi công
- Sử dụng trong cuộc thi CTF

Vui lòng không:
- Tuyên bố là tác giả gốc
- Sử dụng cho mục đích độc hại
- Xóa thông báo giáo dục

---

## 🙏 Ghi Nhận

Thử thách này được lấy cảm hứng từ:
- Các thử thách reverse engineering CTF cổ điển
- Kỹ thuật chống debug thực tế được sử dụng trong malware
- Biểu tượng Ouroboros đại diện cho tự tham chiếu và chu kỳ
- Cộng đồng an ninh mạng Việt Nam

---

<div align="center">

**Chúc may mắn, và mong disassembler dẫn đường cho bạn! 🐍**

*Con rắn nuốt đuôi của chính nó, một chu kỳ vĩnh cửu của sáng tạo và hủy diệt.*

*Làm chủ thử thách, hiểu kỹ thuật, trở thành hacker.*

</div>