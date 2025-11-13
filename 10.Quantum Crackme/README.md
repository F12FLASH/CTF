# 🔐 Quantum Crackme - CTF Challenge Platform

<div align="center">

![Master Level](https://img.shields.io/badge/Difficulty-Master-red?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Reverse_Engineering-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Hardened-green?style=for-the-badge)
![Database](https://img.shields.io/badge/Database-PostgreSQL-336791?style=for-the-badge)

**Nền tảng CTF chuyên nghiệp với bảo mật cấp cao dành cho thử thách Reverse Engineering**

[Tính năng](#tính-năng) • [Cài đặt](#cài-đặt) • [Bảo mật](#bảo-mật) • [API](#api-endpoints)

</div>

---

## 🎯 Giới thiệu

**Quantum Crackme** là một nền tảng CTF (Capture The Flag) chuyên nghiệp được xây dựng với React, Express, và PostgreSQL. Dự án này cung cấp một thử thách Reverse Engineering cấp độ Master với hệ thống bảo mật được gia cố toàn diện.

### 🏆 Thông tin Challenge

- **Tên**: Quantum Crackme
- **Cấp độ**: ⭐⭐⭐⭐⭐ 
- **Danh mục**: Reverse Engineering / Binary Exploitation
- **Kỹ thuật**: CPUID Analysis, QEMU Emulation, Binary Patching
- **Flag Format**: `VNFLAG{...}`

### 🎓 Mục tiêu học tập

Thử thách này giúp người chơi phát triển kỹ năng:
- Phân tích mã máy và assembly
- Hiểu biết về CPU instruction sets (CPUID)
- Sử dụng QEMU emulator
- Kỹ thuật binary patching và reverse engineering
- Sử dụng các công cụ như IDA Pro, Ghidra, GDB

---

## ✨ Tính năng nổi bật

### 🔒 Bảo mật cấp cao

- **Flag Encryption & Obfuscation**: Flag được mã hóa nhiều lớp với XOR obfuscation và buffer splitting
- **Timing-Safe Comparison**: Sử dụng `timingSafeEqual` để chống timing attacks
- **Rate Limiting**: Giới hạn 10 lần thử mỗi 5 phút để chống brute force
- **IP Tracking**: Theo dõi và ghi log IP address của mọi submission
- **Input Sanitization**: Lọc và làm sạch input để chống XSS và injection attacks
- **Security Headers**: Đầy đủ headers bảo mật (CSP, X-Frame-Options, X-XSS-Protection)
- **Hash Storage**: Chỉ lưu hash của flag, không bao giờ lưu plaintext

### 💾 Database & Persistence

- **PostgreSQL Integration**: Sử dụng Neon database cho persistence
- **Drizzle ORM**: Type-safe database operations
- **Submission History**: Lưu trữ đầy đủ lịch sử các lần thử
- **Statistics Tracking**: Thống kê tổng số lần thử và thành công

### 🎨 Giao diện người dùng

- **Modern UI**: Thiết kế đẹp mắt với Tailwind CSS và shadcn/ui
- **Responsive Design**: Tương thích mọi thiết bị
- **Dark Mode**: Hỗ trợ chế độ tối/sáng
- **Matrix Background**: Hiệu ứng nền độc đáo cho cảm giác hacker
- **Real-time Updates**: Cập nhật thống kê theo thời gian thực

### ⚡ Performance & UX

- **Vite**: Build tool siêu nhanh với HMR
- **React Query**: Quản lý server state hiệu quả
- **Lazy Loading**: Tối ưu tải trang
- **Toast Notifications**: Thông báo trực quan cho mọi hành động

---

## 🛡️ Kiến trúc bảo mật

### 1. Flag Protection (Bảo vệ Flag)

```
┌─────────────────────────────────────────┐
│    Flag Encryption Layers               │
├─────────────────────────────────────────┤
│  Layer 1: Buffer Splitting              │
│  Layer 2: XOR Obfuscation               │
│  Layer 3: Custom Salt                   │
│  Layer 4: Timing-Safe Comparison        │
│  Layer 5: Hash-only Storage             │
└─────────────────────────────────────────┘
```

Flag được chia thành nhiều phần và mã hóa riêng biệt, không thể trích xuất trực tiếp từ source code.

### 2. Rate Limiting Architecture

```
Request → In-Memory Check → Database Check → Process
          (Fast)             (Persistent)      
          ↓                  ↓
          Deny if >10        Deny if >10
          in 5 min           in 5 min
```

Hai lớp bảo vệ chống brute force:
- **In-memory**: Kiểm tra nhanh, cleanup tự động
- **Database**: Persistent tracking across restarts

### 3. Security Middleware Stack

```
Request Flow:
┌──────────────┐
│   Client     │
└──────┬───────┘
       ↓
┌──────────────────────┐
│ Security Headers     │ ← X-Frame-Options, CSP, etc.
├──────────────────────┤
│ Security Logger      │ ← Log all API requests
├──────────────────────┤
│ Body Size Limiter    │ ← Max 10KB payload
├──────────────────────┤
│ Rate Limiter         │ ← 10 attempts/5 min
├──────────────────────┤
│ Input Sanitizer      │ ← Remove HTML, XSS
├──────────────────────┤
│ Business Logic       │
└──────────────────────┘
```

---

## 💻 Yêu cầu hệ thống

### Phần mềm cần thiết

- **Node.js**: v20.x hoặc cao hơn
- **PostgreSQL**: v15.x hoặc cao hơn (hoặc sử dụng Neon)
- **npm**: v9.x hoặc cao hơn

### Tài nguyên khuyến nghị

- **RAM**: Tối thiểu 2GB
- **CPU**: 2 cores trở lên
- **Disk**: 500MB cho dependencies

---

## 🚀 Cài đặt và Triển khai

### 1. Clone Repository

```bash
git clone https://github.com/F12FLASH/CTF.git
cd CTF/10.Quantum Crackme
```

### 2. Cài đặt Dependencies

```bash
npm install
```

### 3. Cấu hình Database

#### Option A: Sử dụng Replit Database (Khuyến nghị)

Database đã được tự động tạo sẵn với các biến môi trường:
- `DATABASE_URL`
- `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`

#### Option B: Database riêng

Tạo file `.env`:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/quantum_ctf
```

### 4. Push Database Schema

```bash
npm run db:push
```

### 5. Chạy Development Server

```bash
npm run dev
```

Application sẽ chạy tại `http://localhost:5000`

### 6. Build cho Production

```bash
npm run build
npm start
```

---

## 🔌 API Endpoints

### POST `/api/submissions`

Nộp flag để kiểm tra.

**Rate Limit**: 10 requests / 5 phút

**Request Body**:
```json
{
  "attemptedFlag": "VNFLAG{...}"
}
```

**Response Success**:
```json
{
  "success": true,
  "message": "🎉 Chúc mừng! Flag chính xác! Bạn đã hoàn thành thử thách này."
}
```

**Response Error**:
```json
{
  "success": false,
  "message": "❌ Flag không đúng. Hãy phân tích kỹ hơn và thử lại!"
}
```

**Rate Limit Response**:
```json
{
  "error": "Too many attempts",
  "message": "Quá nhiều lần thử. Vui lòng đợi 5 phút trước khi thử lại.",
  "retryAfter": 300
}
```

### GET `/api/submissions`

Lấy danh sách submissions (tối đa 50).

**Query Parameters**:
- `limit` (optional): Số lượng submissions (max: 100)

**Response**:
```json
[
  {
    "id": "uuid",
    "attemptedFlag": "hash...",
    "isCorrect": true,
    "submittedAt": "2025-01-12T10:30:00Z",
    "ipAddress": "192.168.1.1"
  }
]
```

### GET `/api/submissions/stats`

Lấy thống kê submissions.

**Response**:
```json
{
  "total": 42,
  "correct": 5
}
```

### GET `/api/download/binary`

Download file thông tin challenge.

**Response**: Text file với thông tin chi tiết về challenge

---

## 📖 Hướng dẫn sử dụng

### Cho Người chơi

1. **Truy cập website** tại URL của challenge
2. **Đọc thông tin** về challenge và các phương pháp giải
3. **Download binary** (nếu có) từ nút download
4. **Phân tích binary** bằng các công cụ reverse engineering
5. **Tìm flag** và nộp vào form submission
6. **Kiểm tra lịch sử** các lần thử của bạn

### Cho Admin/Organizer

1. **Deploy application** lên server
2. **Cấu hình database** với thông tin production
3. **Set environment variables**:
   ```bash
   NODE_ENV=production
   DATABASE_URL=<your-production-db>
   PORT=5000
   ```
4. **Monitor logs** để theo dõi attempts
5. **Check statistics** thường xuyên

### Development Workflow

```bash
# Start dev server with hot reload
npm run dev

# Type checking
npm run check

# Push schema changes
npm run db:push

# Build for production
npm run build

# Run production build
npm start
```

---

## 🔐 Bảo mật & Best Practices

### Security Features Checklist

- ✅ **Flag Encryption**: Multi-layer obfuscation
- ✅ **Timing-Safe Comparison**: Constant-time validation
- ✅ **Rate Limiting**: Prevent brute force (10/5min)
- ✅ **Input Sanitization**: Remove XSS vectors
- ✅ **SQL Injection Protection**: Parameterized queries via ORM
- ✅ **CSRF Protection**: Secure headers
- ✅ **XSS Protection**: CSP headers + sanitization
- ✅ **Clickjacking Protection**: X-Frame-Options: DENY
- ✅ **IP Tracking**: Log all submission attempts
- ✅ **Payload Size Limits**: Max 10KB
- ✅ **Hash-only Storage**: Never store plaintext flags
- ✅ **Security Headers**: Full suite (CSP, HSTS, etc.)

### Recommended Practices

1. **Never commit secrets** - Use environment variables
2. **Regular updates** - Keep dependencies updated
3. **Monitor logs** - Check for suspicious activity
4. **Backup database** - Regular automated backups
5. **Use HTTPS** - Always in production
6. **Strong passwords** - For database and admin access
7. **Firewall rules** - Limit database access
8. **Rate limiting** - Already implemented

### Security Monitoring

```bash
# Check for vulnerabilities
npm audit

# Fix vulnerabilities
npm audit fix

# Check security logs
tail -f /var/log/quantum-ctf/security.log
```

---

## 🐛 Troubleshooting

### Database Connection Issues

**Problem**: `DATABASE_URL must be set`

**Solution**:
```bash
# Check environment variable
echo $DATABASE_URL

# Set it if missing
export DATABASE_URL=postgresql://...
```

### Rate Limit Too Strict

**Problem**: Người chơi bị block quá nhanh

**Solution**: Điều chỉnh trong `server/routes.ts`:
```typescript
const submitRateLimit = createRateLimit({
  windowMinutes: 10,  // Tăng từ 5 lên 10 phút
  maxAttempts: 20,    // Tăng từ 10 lên 20 lần
});
```

### Port Already in Use

**Problem**: `Error: listen EADDRINUSE: address already in use :::5000`

**Solution**:
```bash
# Find and kill process using port 5000
lsof -ti:5000 | xargs kill -9

# Or change port
export PORT=3000
npm run dev
```

### Build Errors

**Problem**: TypeScript errors during build

**Solution**:
```bash
# Clean install
rm -rf node_modules package-lock.json
npm install

# Check types
npm run check
```

---

## 🤝 Đóng góp

Chúng tôi hoan nghênh mọi đóng góp! Để contribute:

1. Fork repository
2. Tạo feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

### Coding Standards

- Follow TypeScript best practices
- Write meaningful commit messages
- Add comments for complex logic
- Update README if needed
- Test thoroughly before PR

---

## 📄 License

MIT License - Xem file [LICENSE](LICENSE) để biết thêm chi tiết.

---

## 👥 Credits

- **Challenge Design**: Quantum Crackme Team
- **Frontend**: React + Tailwind CSS + shadcn/ui
- **Backend**: Express + TypeScript
- **Database**: PostgreSQL + Drizzle ORM
- **Security**: Multi-layer encryption & protection

---

## 📞 Liên hệ & Hỗ trợ

- **Issues**: [GitHub Issues](https://github.com/F12FLASH/CTF/issues)
- **Email**: loideveloper.37@gmail.com

---

<div align="center">

**Được xây dựng với ❤️ cho cộng đồng Information Security Việt Nam**

⭐ Star this repo nếu bạn thấy hữu ích!

</div>
