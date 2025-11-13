# The Undefined - CTF Pwn Challenge Platform

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.6.3-blue.svg)

**Nền tảng giáo dục CTF chuyên về khai thác Undefined Behavior trong C++**

[Tính năng](#tính-năng) • [Cài đặt](#cài-đặt) • [Hướng dẫn sử dụng](#hướng-dẫn-sử-dụng) • [Bảo mật](#bảo-mật) • [Đóng góp](#đóng-góp)

</div>

---

## 🎯 Giới thiệu

**The Undefined** là một nền tảng giáo dục CTF (Capture The Flag) tương tác, tập trung vào việc dạy và thực hành khai thác các lỗ hổng Undefined Behavior (UB) trong C++. Ứng dụng cung cấp một thử thách pwn cấp độ master, nơi người dùng phải hiểu và khai thác các loại undefined behavior khác nhau trong code C++ để giải mã flag.

### 🎓 Mục tiêu giáo dục

- Hiểu rõ về Undefined Behavior trong C++
- Kỹ thuật reverse engineering và binary analysis
- Khai thác các lỗ hổng UB để giải mã flag
- Thực hành với terminal emulator và công cụ phân tích binary

### ⭐ Độ khó

**Master Level (⭐⭐⭐⭐⭐)** - Thử thách dành cho người có kinh nghiệm với:
- C++ và compiler internals
- Binary reverse engineering
- Memory analysis và manipulation
- CTF pwn challenges

---

## ✨ Tính năng

### 🖥️ Terminal Emulator Tương tác
- Mô phỏng môi trường terminal thực tế
- Hỗ trợ các lệnh binary analysis: `file`, `checksec`, `strings`, `objdump`, `gdb`
- Giao diện terminal cybersecurity với màu sắc terminal chuẩn

### 📝 Code Viewer với Syntax Highlighting
- Hiển thị code C++ với các annotation về UB
- Syntax highlighting chuyên nghiệp
- Đánh dấu vị trí có undefined behavior

### 📚 Educational Resources
- 4 loại UB được giảng dạy chi tiết:
  - Uninitialized Memory
  - Type Punning (Strict Aliasing Violation)
  - Signed Integer Overflow
  - Memory Order / Race Conditions
- Code examples và explanation cho mỗi loại UB
- Cards tương tác với animations

### 🎯 Progress Tracking System
- Theo dõi tiến độ người dùng qua 5 bước
- Lưu trữ session-based progress
- Hiển thị timeline trực quan

### 💡 Hint System
- 4 hints được unlock dựa trên số lần thử
- Collapsible hints với animations
- Progressive difficulty hints

### 🔐 Flag Submission & Validation
- Real-time flag validation
- Rate limiting để chống brute-force
- Hiển thị số attempts và hints unlocked

---

## 💻 Yêu cầu hệ thống

### Backend
- **Node.js**: >= 18.0.0
- **npm**: >= 9.0.0
- **RAM**: >= 512MB
- **Disk Space**: >= 100MB

### Frontend
- Modern browser với hỗ trợ ES6+
- JavaScript enabled
- Recommended: Chrome, Firefox, Safari, Edge (phiên bản mới nhất)

---

## 🚀 Cài đặt

### 1. Clone Repository

```bash
git clone https://github.com/F12FLASH/CTF.git
cd CTF/12.The Undefined
```

### 2. Cài đặt Dependencies

```bash
npm install
```

Lệnh này sẽ cài đặt tất cả dependencies cần thiết cho cả frontend và backend.

### 3. Cấu hình Environment Variables (Optional)

Tạo file `.env` trong thư mục root:

```env
PORT=5000
NODE_ENV=development
```

---

## 📖 Hướng dẫn sử dụng

### Development Mode

Khởi chạy ứng dụng ở chế độ development với hot-reload:

```bash
npm run dev
```

Ứng dụng sẽ chạy tại: `http://localhost:5000`

### Production Build

#### Bước 1: Build ứng dụng

```bash
npm run build
```

#### Bước 2: Chạy production server

```bash
npm start
```

### Sử dụng nền tảng

1. **Truy cập ứng dụng**: Mở browser và truy cập `http://localhost:5000`

2. **Khám phá Challenge**:
   - Đọc thông tin về thử thách "The Undefined"
   - Tìm hiểu các loại Undefined Behavior
   - Xem code examples

3. **Phân tích Binary**:
   - Sử dụng Terminal Emulator
   - Chạy các lệnh: `file`, `checksec`, `strings`, `objdump`, `gdb`
   - Phân tích output để tìm UB patterns

4. **Xem Source Code**:
   - Đọc code C++ trong Code Viewer
   - Chú ý các vị trí được đánh dấu UB
   - Hiểu cách compiler xử lý UB

5. **Submit Flag**:
   - Nhập flag theo format: `VNFLAG{...}`
   - Submit và nhận feedback
   - Unlock hints sau mỗi lần thử

6. **Sử dụng Hints**:
   - Hints tự động unlock sau 2, 4, 6, 8 attempts
   - Click vào hint để xem nội dung
   - Sử dụng hints để tiến gần hơn đến solution

---

## 🔒 Bảo mật

### Các biện pháp bảo mật đã triển khai

#### 1. Security Headers
```javascript
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

#### 2. Input Validation
- **Zod schema validation** cho tất cả inputs
- **Session ID validation**: Regex pattern matching
- **Flag format validation**: `VNFLAG{...}` format
- **Character sanitization**: Chỉ cho phép printable ASCII characters
- **Length limits**: Max 200 characters cho flag, max 100 cho session ID

#### 3. Rate Limiting
- **Flag submission**: Maximum 20 attempts per minute per session
- **Automatic cleanup**: Old rate limit data được xóa tự động
- **429 status code**: Trả về khi vượt quá rate limit

#### 4. Request Size Limits
- **Body size limit**: 1MB cho JSON và URL-encoded data
- Chống DoS attacks thông qua large payloads

#### 5. Error Handling
- **No sensitive data exposure**: Error messages không tiết lộ thông tin nhạy cảm
- **Proper logging**: Errors được log ra console để debugging
- **Graceful degradation**: User-friendly error messages

#### 6. Session Security
- **Client-generated session IDs**: Format chuẩn với timestamp và random string
- **No authentication required**: Thích hợp cho educational demo
- **Session isolation**: Mỗi session có data riêng biệt

### Best Practices

1. **Không hardcode secrets** trong code (flag là exception vì mục đích educational)
2. **Validate all inputs** từ client
3. **Use HTTPS** trong production
4. **Regular security audits** và dependency updates
5. **Monitor rate limiting** và suspicious activities

---

## 📡 API Documentation

### Base URL
```
http://localhost:5000/api
```

### Endpoints

#### 1. Get Progress
```http
GET /api/progress/:sessionId
```

**Response:**
```json
{
  "currentStep": 0,
  "steps": [
    {
      "id": "binary-analysis",
      "title": "Binary Analysis",
      "description": "Xác định vị trí UB trong code",
      "completed": false
    }
  ],
  "startTime": 1234567890
}
```

#### 2. Update Progress
```http
POST /api/progress/:sessionId
Content-Type: application/json

{
  "currentStep": 1,
  "steps": [...],
  "startTime": 1234567890
}
```

#### 3. Get Attempts
```http
GET /api/attempts/:sessionId
```

**Response:**
```json
{
  "attempts": 5
}
```

#### 4. Submit Flag
```http
POST /api/submit-flag/:sessionId
Content-Type: application/json

{
  "flag": "VNFLAG{...}"
}
```

**Response (Success):**
```json
{
  "success": true,
  "message": "Chúc mừng! Bạn đã giải được thử thách The Undefined.",
  "attempts": 10,
  "hintsUnlocked": 4
}
```

**Response (Failure):**
```json
{
  "success": false,
  "message": "Flag không đúng. Hãy thử lại! (Attempt 5)",
  "attempts": 5,
  "hintsUnlocked": 2
}
```

#### 5. Get Hints
```http
GET /api/hints/:sessionId
```

**Response:**
```json
[
  {
    "id": "hint-1",
    "title": "Hint 1: UB Detection",
    "content": "Sử dụng công cụ static analysis...",
    "unlockAttempts": 2,
    "unlocked": true
  }
]
```

### Error Responses

**400 Bad Request:**
```json
{
  "error": "Invalid session ID format"
}
```

**429 Too Many Requests:**
```json
{
  "success": false,
  "message": "Too many attempts. Please wait before trying again.",
  "attempts": 0,
  "hintsUnlocked": 0
}
```

**500 Internal Server Error:**
```json
{
  "error": "Failed to get progress"
}
```

---

## 🎮 Thông tin thử thách

### Thông tin cơ bản
- **Tên**: The Undefined
- **Thể loại**: Pwn/Reverse Engineering
- **Độ khó**: ⭐⭐⭐⭐⭐ (Master)
- **Ngôn ngữ**: C++ với Undefined Behavior
- **Cơ chế**: Encryption sử dụng UB mỗi lần chạy

### Mô tả
Binary C++ tận dụng Undefined Behavior để mã hóa flag. Mỗi lần chạy, flag được mã hóa với key khác nhau do compiler-generated code không xác định.

### Các loại UB được sử dụng

#### 1. Uninitialized Memory
Sử dụng biến chưa được khởi tạo - giá trị không xác định.

#### 2. Type Punning
Vi phạm strict aliasing rules - truy cập memory qua các pointer types khác nhau.

#### 3. Signed Integer Overflow
Arithmetic overflow có dấu - kết quả không xác định.

#### 4. Memory Order / Race Conditions
Điều kiện tranh chấp bộ nhớ trong môi trường đa luồng.

### Kỹ thuật giải quyết

1. **Binary Analysis**: Phân tích binary để xác định UB patterns
2. **Environment Control**: Kiểm soát môi trường thực thi (ASLR, heap, stack)
3. **Reproducible Execution**: Tạo môi trường có thể tái tạo
4. **Key Extraction**: Trích xuất encryption key từ memory
5. **Flag Decryption**: Decrypt flag bằng XOR với key đã tìm được

### Công cụ cần thiết
- Ghidra / IDA Pro - Binary analysis
- GDB với PEDA/GEF - Dynamic analysis
- Compiler Explorer - Assembly analysis
- Valgrind / ASan - Memory analysis

### Flag Format
```
VNFLAG{TAM_HUYET_YEU_NUOC_VIETNAM_GIUP_XAY_DUNG_8p2R7k1M4Q9z3L6f0B5yXc}
```

---

## 🛠️ Development

### Prerequisites
- Node.js >= 18.0.0
- npm >= 9.0.0
- Git

### Development Commands

```bash
# Install dependencies
npm install

# Start development server with hot-reload
npm run dev

# Type checking
npm run check

# Build for production
npm run build

# Run production server
npm start

# Database operations (if using PostgreSQL)
npm run db:push
```

### Code Style

Dự án sử dụng TypeScript với strict mode:
- **Indentation**: 2 spaces
- **Quotes**: Single quotes
- **Semicolons**: Required
- **Line Length**: 100 characters (recommended)

### Component Structure

```typescript
// Good component structure
interface ComponentProps {
  prop1: string;
  prop2: number;
}

export function Component({ prop1, prop2 }: ComponentProps) {
  // Component logic
  return (
    <div>...</div>
  );
}
```

### Adding New Features

1. **Frontend component**: Add to `client/src/components/`
2. **Backend route**: Add to `server/routes.ts`
3. **Shared schema**: Add to `shared/schema.ts`
4. **Update types**: Run `npm run check` để verify

---

## 🔧 Troubleshooting

### Port đã được sử dụng

```bash
# Linux/Mac
lsof -ti:5000 | xargs kill -9

# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### Dependencies installation failed

```bash
# Clear cache và reinstall
rm -rf node_modules package-lock.json
npm cache clean --force
npm install
```

### TypeScript errors

```bash
# Run type checking
npm run check

# Rebuild
npm run build
```

### Application không start

1. Check Node.js version: `node --version` (>= 18.0.0)
2. Check logs trong console
3. Verify port 5000 available
4. Check environment variables

---

## 🤝 Đóng góp

Chúng tôi hoan nghênh mọi đóng góp! Để contribute:

1. **Fork repository**
2. **Create feature branch**: `git checkout -b feature/AmazingFeature`
3. **Commit changes**: `git commit -m 'Add some AmazingFeature'`
4. **Push to branch**: `git push origin feature/AmazingFeature`
5. **Open Pull Request**

### Contribution Guidelines

- Follow existing code style
- Add tests nếu có thể
- Update documentation
- Write clear commit messages

---

## 📄 License

Dự án này được phân phối dưới MIT License. Xem file `LICENSE` để biết thêm chi tiết.

---

## 👥 Authors

- **F12FLASH** - Initial work

---

## 🙏 Acknowledgments

- shadcn/ui cho UI component library
- Radix UI cho accessible primitives
- CTF community cho inspiration

---

## 📞 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/F12FLASH/CTF/issues)
- **Email**: loideveloper.37@gmail.com

---

<div align="center">

**Made with ❤️ for the CTF community**

⭐ Nếu bạn thấy project hữu ích, hãy star repo này! ⭐

</div>
