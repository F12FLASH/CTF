# Nền Tảng CTF - Thử Thách Stackless Stack

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)](https://www.typescriptlang.org/)

Nền tảng CTF (Capture The Flag) hiện đại, full-stack với thử thách khai thác binary nâng cao. Được xây dựng với React, Express và TypeScript.

## 🎯 Tổng Quan

Nền tảng này cung cấp **Thử Thách Stackless Stack** - một thử thách khai thác binary nâng cao kiểm tra kiến thức sâu về:
- Khai thác buffer overflow trong môi trường stack phi truyền thống
- Chuỗi ROP (Return-Oriented Programming)
- Thao tác syscall và khai thác mprotect
- Phân tích và dịch ngược binary

### Mô Tả Thử Thách

**Stackless Stack** là thử thách khai thác binary cấp độ Master Hacker với các đặc điểm:
- Binary ELF x86-64 không sử dụng stack truyền thống
- Bộ nhớ được cấp phát qua mmap() thay vì stack
- Lỗ hổng buffer overflow trong vùng nhớ mmap
- Bật bảo vệ NX (stack không thể thực thi)
- Không có PIE, không có stack canary
- Yêu cầu chuỗi ROP + syscall mprotect để vượt qua NX

**Định Dạng Flag**: `VNFLAG{...}` (được ẩn - khai thác binary để lấy flag thật!)

## ✨ Tính Năng

### Tính Năng Nền Tảng
- 🔐 **Môi Trường CTF Bảo Mật**: Giới hạn tốc độ, xác thực và làm sạch đầu vào
- 📊 **Theo Dõi Tiến Độ Thời Gian Thực**: Theo dõi số lượt giải, nộp flag và gợi ý
- 💡 **Hệ Thống Gợi Ý Tương Tác**: Gợi ý có thể mở khóa với chi phí điểm
- 📖 **Bài Giải Chi Tiết**: Hướng dẫn khai thác từng bước
- 📥 **Tải File**: Truy cập file thử thách và mã nguồn
- 🎨 **Giao Diện Hiện Đại**: Thiết kế responsive với hỗ trợ chế độ sáng/tối
- 🔒 **Quản Lý Session**: Xử lý session bảo mật với memory store

### Tính Năng Bảo Mật
- **Giới Hạn Tốc Độ**: Giới hạn theo endpoint để ngăn chặn lạm dụng
  - Nộp flag: 5 yêu cầu/phút
  - Mở khóa gợi ý: 10 yêu cầu/phút  
  - Tải file: 20 yêu cầu/phút
  - API chung: 30-60 yêu cầu/phút
- **Xác Thực Đầu Vào**: Xác thực schema Zod toàn diện
- **Làm Sạch Đầu Vào**: Bảo vệ chống tấn công injection
- **Bảo Vệ Path Traversal**: Phục vụ file bảo mật
- **Bảo Mật Session**: Cookie HTTP-only với secret có thể cấu hình
- **Secure Headers**: Helmet middleware cho bảo mật HTTP headers
- **CORS Protection**: Cấu hình CORS an toàn

## 🚀 Bắt Đầu Nhanh

### Yêu Cầu Hệ Thống

- **Node.js** >= 18.0.0
- **npm** >= 9.0.0

### Cài Đặt

1. **Clone repository**
```bash
git clone https://github.com/F12FLASH/CTF.git
cd CTF/4.Stackless Stack
```

2. **Cài đặt dependencies**
```bash
npm install
```

### Chạy Ứng Dụng

#### Chế Độ Development
```bash
npm run dev
```

Ứng dụng sẽ khả dụng tại `http://localhost:5000`

#### Chế Độ Production
```bash
npm run build
npm start
```

## 🎓 Chi Tiết Thử Thách

### Tổng Quan Khai Thác Binary

Thử thách Stackless Stack yêu cầu khai thác lỗ hổng trong binary có các đặc điểm:
1. Sử dụng mmap() để cấp phát bộ nhớ thay vì stack truyền thống
2. Chứa lỗi buffer overflow trong vùng nhớ mmap
3. Có bảo vệ NX được bật
4. Yêu cầu xây dựng chuỗi ROP để gọi syscall mprotect
5. Cần thực thi shellcode để lấy flag

### Các Bước Khai Thác

1. **Trinh Sát**: Phân tích binary với công cụ như radare2, ghidra, hoặc IDA
2. **Phát Hiện Lỗ Hổng**: Tìm buffer overflow trong vulnerable_function()
3. **Tìm ROP Gadget**: Sử dụng ROPgadget để tìm syscall gadgets
4. **Xây Dựng Chuỗi ROP**: Tạo chuỗi để gọi mprotect(addr, len, RWX)
5. **Tiêm Shellcode**: Tiêm và thực thi shellcode
6. **Lấy Flag**: Gọi win_function() hoặc đọc file flag

### Biên Dịch Binary Thử Thách

```bash
cd public/downloads
gcc -o stackless_stack stackless_stack.c -no-pie -fno-stack-protector -z noexecstack
```

Để debug:
```bash
gcc -o stackless_stack stackless_stack.c -no-pie -fno-stack-protector -z noexecstack -g
```

## 📡 Tài Liệu API

### Endpoints

#### GET `/api/challenge/:id`
Lấy thông tin thử thách (flag bị loại bỏ)


**Response**:
```json
{
  "id": "stackless-stack",
  "title": "Stackless Stack",
  "description": "...",
  "category": "pwn",
  "difficulty": "master hacker",
  "points": 500,
  "author": "F12FLASH",
  "solves": 0
}
```

#### GET `/api/hints/:challengeId`
Lấy gợi ý cho thử thách (gợi ý bị khóa hiển thị nội dung null)

#### POST `/api/unlock-hint`
Mở khóa một gợi ý cụ thể

**Giới Hạn Tốc Độ**: 10 yêu cầu/phút

**Body**:
```json
{
  "challengeId": "stackless-stack",
  "hintId": "hint-uuid"
}
```

#### POST `/api/submit-flag`
Nộp flag để xác thực

**Giới Hạn Tốc Độ**: 5 yêu cầu/phút

**Body**:
```json
{
  "challengeId": "stackless-stack",
  "flag": "VNFLAG{...}"
}
```

**Response**:
```json
{
  "correct": true,
  "message": "Chúc mừng! Flag chính xác..."
}
```

#### GET `/api/writeup/:challengeId`
Lấy các phần bài giải cho thử thách

**Giới Hạn Tốc Độ**: 30 yêu cầu/phút

#### GET `/api/download/:filename`
Tải file thử thách

**File được phép**: `stackless_stack.c`, `README.txt`

## 🐛 Xử Lý Sự Cố

### Vấn Đề Thường Gặp

**Vấn đề**: `tsx: not found`
**Giải pháp**: Chạy `npm install` để cài đặt tất cả dependencies

**Vấn đề**: Port 5000 đã được sử dụng
**Giải pháp**: Đặt biến môi trường `PORT` để sử dụng port khác

**Vấn đề**: Lỗi LSP trong IDE
**Giải pháp**: Chạy `npm install` và khởi động lại IDE/editor

**Vấn đề**: Session không được lưu
**Giải pháp**: Kiểm tra cookies đã được bật trong trình duyệt

### Chế Độ Debug

Bật logging chi tiết:
```bash
NODE_ENV=development DEBUG=* npm run dev
```

## 📝 Giấy Phép

Dự án này được cấp phép theo Giấy phép MIT.

## 👥 Credits

**Tác Giả**: F12FLASH

**Công Nghệ**:
- [React](https://react.dev/)
- [Express](https://expressjs.com/)
- [TypeScript](https://www.typescriptlang.org/)
- [shadcn/ui](https://ui.shadcn.com/)
- [TanStack Query](https://tanstack.com/query)
- [Tailwind CSS](https://tailwindcss.com/)

## 🤝 Đóng Góp

Chúng tôi hoan nghênh mọi đóng góp! Vui lòng tuân theo các hướng dẫn sau:

1. Fork repository
2. Tạo feature branch: `git checkout -b feature/tinh-nang-tuyet-voi`
3. Commit thay đổi: `git commit -m 'Thêm tính năng tuyệt vời'`
4. Push lên branch: `git push origin feature/tinh-nang-tuyet-voi`
5. Mở Pull Request

## 📧 Hỗ Trợ

Đối với vấn đề, câu hỏi hoặc đề xuất:
- Mở issue trên GitHub
- Liên hệ: loideveloper.37@gmail.com

## 🎯 Lộ Trình

- [ ] Thêm nhiều thử thách CTF
- [ ] Triển khai thi đấu theo nhóm
- [ ] Thêm bảng điểm và xếp hạng
- [ ] Hỗ trợ triển khai Docker
- [ ] Thông báo thử thách thời gian thực
- [ ] Dashboard quản trị cho quản lý thử thách

---

**Chúc Hacking Vui Vẻ! 🚀**

*"Trong CTF, luôn có một cách. Đôi khi bạn chỉ cần nhìn nó theo cách khác."*
