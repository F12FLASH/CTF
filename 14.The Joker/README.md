# 🃏 The Joker - Nền tảng Thử thách CTF Reverse Engineering

![Độ khó: Expert](https://img.shields.io/badge/Độ%20khó-Expert%20★★★★-red)
![Loại: Reverse Engineering](https://img.shields.io/badge/Loại-Reverse%20Engineering-blue)
![Bảo mật: Cao](https://img.shields.io/badge/Bảo%20mật-Cao-green)


## 🎯 Giới thiệu

**The Joker** là một nền tảng học tập tương tác dành cho các chuyên gia an ninh mạng và sinh viên, tập trung vào thử thách reverse engineering cấp độ chuyên gia. Thử thách mô phỏng một binary tinh vi sử dụng kỹ thuật anti-debugging và self-modification để xóa chính nó khỏi bộ nhớ.

### 🎪 Câu chuyện thử thách

"The Joker" là một binary như một "trò đùa" - nó hiển thị flag cho người dùng nhưng ngay lập tức sử dụng kỹ thuật ptrace anti-debugging và memory wiping để xóa chính nó, tạo nên cuộc chạy đua gay cấn giữa reverse engineer và các cơ chế phòng thủ.

## ✨ Đặc điểm nổi bật

### 📚 Nội dung giáo dục toàn diện
- **Tài liệu chi tiết**: Hướng dẫn đầy đủ về kỹ thuật reverse engineering
- **4 phương pháp giải quyết**: GDB Scripting, Memory Tracing, LD_PRELOAD, Binary Patching
- **Code ví dụ**: Syntax highlighting cho C, Python, Bash, GDB
- **Hỗ trợ tiếng Việt**: Giao diện và tài liệu hoàn toàn bằng tiếng Việt

### 🔐 Bảo mật cao cấp
- **Mã hóa flag**: Flag được mã hóa và làm rối nhiều lớp
- **Rate limiting**: Giới hạn số lần thử flag để chống brute force
- **Constant-time comparison**: Chống timing attacks
- **Input sanitization**: Lọc và làm sạch input nguy hiểm
- **Security headers**: Bảo vệ chống XSS, clickjacking, MIME sniffing

### 🎨 Giao diện người dùng
- **Theme tối chuyên nghiệp**: Màu matrix green đặc trưng của cybersecurity
- **Responsive design**: Tương thích mọi thiết bị
- **Progress tracking**: Theo dõi tiến độ học tập tự động
- **Confetti animation**: Hiệu ứng chúc mừng khi giải đúng
- **Sidebar navigation**: Điều hướng dễ dàng giữa các phần

## 🛠 Công nghệ sử dụng

### Frontend
- **React 18** với TypeScript - UI framework hiện đại
- **Vite** - Build tool nhanh chóng
- **Tailwind CSS** - Utility-first CSS framework
- **Shadcn UI** - Component library với Radix primitives
- **TanStack Query** - State management và data fetching
- **Wouter** - Lightweight router
- **React Hook Form** + **Zod** - Form validation
- **React Syntax Highlighter** - Code highlighting
- **Canvas Confetti** - Celebration animations

### Backend
- **Node.js** với **Express** - Server framework
- **TypeScript** - Type safety
- **Drizzle ORM** - Type-safe database toolkit
- **Zod** - Runtime validation
- **Custom security middleware** - Rate limiting, sanitization

### Bảo mật
- **Multi-layer flag encryption** - Base64 obfuscation
- **SHA-256 hashing** - Privacy protection
- **Constant-time comparison** - Timing attack prevention
- **Rate limiting** - Brute force protection
- **Input sanitization** - XSS protection
- **Security headers** - Multiple attack vector protection

## 💻 Yêu cầu hệ thống

- **Node.js**: 20.x trở lên
- **npm**: 10.x trở lên
- **Trình duyệt**: Chrome, Firefox, Safari, Edge (phiên bản mới nhất)
- **RAM**: Tối thiểu 2GB
- **Dung lượng ổ cứng**: 500MB

## 📦 Cài đặt

### Bước 1: Clone repository

```bash
git clone https://github.com/F12FLASH/CTF.git
cd CTF/14.The Joker
```

### Bước 2: Cấu hình environment variables

```bash
# Copy file .env.example thành .env
cp .env.example .env

# Chỉnh sửa .env và set flag của bạn
# CTF_FLAG=YOUR_ACTUAL_FLAG_HERE
```

**LƯU Ý QUAN TRỌNG**: File `.env` chứa flag thực và sẽ được tự động ignore bởi git. Không bao giờ commit file này!

### Bước 3: Cài đặt dependencies

```bash
npm install
```

### Bước 4: Khởi động ứng dụng

```bash
npm run dev
```

Ứng dụng sẽ chạy tại `http://localhost:5000`

## 🚀 Sử dụng

### Chế độ Development

```bash
npm run dev
```

Khởi động cả backend Express server và Vite dev server với hot module replacement (HMR).

### Kiểm tra TypeScript

```bash
npm run check
```

Chạy TypeScript compiler để kiểm tra lỗi type.

### Build cho Production

```bash
npm run build
```

Build frontend với Vite và backend với esbuild.

### Chạy Production

```bash
npm run start
```

Khởi động server production (sau khi đã build).

### Database Migration

```bash
npm run db:push
```

Đẩy schema database lên Neon (nếu sử dụng database).

## 🔒 Tính năng bảo mật

### 1. Flag Protection (Bảo vệ Flag)

Flag được bảo vệ bằng phương pháp hash-based validation:

- **Zero-knowledge validation**: Server chỉ lưu hash SHA-256 của flag, không bao giờ lưu plaintext
- **Environment variable**: Flag thực được lưu trong biến môi trường `CTF_FLAG` (không có trong code)
- **Constant-time comparison**: Sử dụng `timingSafeEqual` để ngăn chặn timing attacks
- **Hash-only storage**: Submissions chỉ lưu hash một phần, không lưu flag gốc

```typescript
// Flag được validate qua hash comparison
// Không thể trích xuất flag từ source code
// Xem server/flag-encryption.ts để biết chi tiết
```

Để cài đặt flag tùy chỉnh trong production:
```bash
export CTF_FLAG="YOUR_CUSTOM_FLAG_HERE"
```

### 2. Rate Limiting

Hệ thống rate limiting tinh vi:

- **Flag submission**: 5 lần thử/phút, block 10 phút nếu vượt quá
- **General API**: 100 requests/phút, block 1 phút nếu vượt quá
- **IP-based tracking**: Theo dõi theo địa chỉ IP
- **Automatic cleanup**: Tự động xóa entries cũ

### 3. Input Sanitization

Mọi input đều được làm sạch:

- XSS pattern removal
- Script tag filtering
- Event handler removal
- Trim whitespace

### 4. Security Headers

Headers bảo vệ toàn diện:

- `X-Frame-Options: DENY` - Chống clickjacking
- `X-Content-Type-Options: nosniff` - Chống MIME sniffing
- `X-XSS-Protection: 1; mode=block` - XSS protection
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy` - Kiểm soát resource loading

### 5. Request Size Limiting

- Max request size: 100KB
- Ngăn chặn payload quá lớn
- Bảo vệ server khỏi memory exhaustion

## 👨‍💻 Hướng dẫn phát triển

### Thêm Component mới

```bash
# Tạo component trong client/src/components/
touch client/src/components/new-component.tsx
```

### Thêm API Endpoint mới

```typescript
// Trong server/routes.ts
app.get("/api/new-endpoint", async (req, res) => {
  // Logic của bạn
  res.json({ data: "..." });
});
```

### Thêm Middleware bảo mật

```typescript
// Trong server/security-middleware.ts
export function customSecurityMiddleware(req, res, next) {
  // Logic bảo mật
  next();
}

// Sử dụng trong server/index.ts
app.use(customSecurityMiddleware);
```

### Code Style

- **TypeScript strict mode**: Enabled
- **ESLint**: Tuân theo quy tắc mặc định
- **Prettier**: Tự động format
- **Naming convention**:
  - Components: PascalCase (`FlagSubmission`)
  - Files: kebab-case (`flag-submission.tsx`)
  - Functions: camelCase (`submitFlag`)
  - Constants: UPPER_SNAKE_CASE (`CORRECT_FLAG`)

## 🌐 Triển khai

### Manual Deployment

```bash
# Build application
npm run build

# Set environment variable
export NODE_ENV=production
export PORT=5000

# Start server
npm start
```

### Environment Variables

- `NODE_ENV`: `development` hoặc `production`
- `PORT`: Port để chạy server (default: 5000)
- `CTF_FLAG`: Flag chính xác cho thử thách (bắt buộc cho production)
  - Trong development: Mặc định là demo flag
  - Trong production: Phải được set để bảo mật
- `DATABASE_URL`: PostgreSQL connection string (nếu dùng database)

**Lưu ý bảo mật**: Không bao giờ commit `CTF_FLAG` vào Git. Sử dụng file `.env` hoặc secrets manager.

## 🎓 Giải pháp thử thách

Platform cung cấp 4 phương pháp giải quyết thử thách "The Joker":

### 1. GDB Scripting (★★★★)
Sử dụng GDB script tự động để dump memory trước khi binary tự xóa.

### 2. Memory Tracing (★★★★)
Viết custom tracer program với ptrace để monitor process.

### 3. LD_PRELOAD Hook (★★★)
Hook ptrace function để bypass anti-debugging check.

### 4. Binary Patching
Sửa đổi binary trực tiếp để disable protection mechanisms.

### Kỹ năng cần thiết:
- Thành thạo GDB và debugging
- Hiểu biết sâu về process memory layout
- Kinh nghiệm với anti-debugging bypass
- Kỹ năng binary analysis và manipulation
- Kiến thức về system calls và process management

## 🤝 Đóng góp

Chúng tôi hoan nghênh mọi đóng góp! Để đóng góp:

1. Fork repository
2. Tạo branch mới (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Mở Pull Request

### Quy tắc đóng góp:

- Viết code rõ ràng và có comment
- Tuân theo code style hiện tại
- Thêm tests nếu có thể
- Update documentation khi cần thiết
- Đảm bảo code pass TypeScript checks

## 📄 Giấy phép

MIT License - Xem file [LICENSE](LICENSE) để biết thêm chi tiết.

## 🙏 Lời cảm ơn

- **Shadcn UI** - Component library tuyệt vời
- **Radix UI** - Accessible primitives
- **Cộng đồng CTF Việt Nam** - Inspiration và support

## 📞 Liên hệ

Nếu bạn có câu hỏi hoặc đề xuất, vui lòng:
- Mở issue trên GitHub
- Email: loideveloper.37@gmail.com

---

**Được xây dựng với ❤️ cho cộng đồng Cybersecurity Việt Nam**

🎯 Happy Hacking! 🔐
