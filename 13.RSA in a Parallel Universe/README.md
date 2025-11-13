# 🔐 RSA in a Parallel Universe - CTF Cryptography Challenge

<div align="center">

![Difficulty](https://img.shields.io/badge/Difficulty-Master-red?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Cryptography-blue?style=for-the-badge)
![Technology](https://img.shields.io/badge/Technology-Gaussian_Integers-green?style=for-the-badge)

**Một biến thể cực kỳ phức tạp của RSA hoạt động trên vành số phức Gaussian (ℤ[i])**

[Tính năng](#-tính-năng) • [Cài đặt](#-cài-đặt) • [Sử dụng](#-sử-dụng) • [Lý thuyết](#-lý-thuyết-toán-học) • [Bảo mật](#-bảo-mật)

</div>

---

## 🎯 Giới thiệu

**RSA in a Parallel Universe** là một nền tảng học tập CTF (Capture The Flag) chuyên sâu về mật mã học, tập trung vào việc giảng dạy các khái niệm RSA nâng cao sử dụng số nguyên Gaussian (ℤ[i]).

### Điểm nổi bật

- 🧮 **Gaussian Integers**: RSA trên không gian số phức thay vì số nguyên thông thường
- 🎓 **Học tập tương tác**: Công cụ calculator, solver từng bước và hệ thống gợi ý
- 🔐 **Mã hóa thực tế**: Triển khai đầy đủ RSA trên Gaussian integers
- 🌐 **Responsive UI**: Giao diện đẹp, hiện đại với dark/light mode
- 🛡️ **Bảo mật cao**: Rate limiting, helmet security headers, environment-based configuration

### Dành cho ai?

- Sinh viên và học viên muốn tìm hiểu sâu về mật mã học
- CTF players muốn nâng cao kỹ năng cryptography
- Giáo viên và người hướng dẫn cần công cụ giảng dạy
- Nhà nghiên cứu bảo mật quan tâm đến biến thể RSA

---

## ✨ Tính năng

### 🎯 Core Features

#### 1. Gaussian Integer Calculator
- **Phép toán cơ bản**: Cộng, nhân các số phức Gaussian
- **Tính Norm**: N(a + bi) = a² + b²
- **GCD Algorithm**: Extended Euclidean algorithm cho Gaussian integers
- **Real-time results**: Kết quả hiển thị ngay lập tức với KaTeX rendering

#### 2. RSA Solver từng bước
- **5 bước giải quyết**: Từ phân tích modulus đến giải mã
- **Công thức toán học**: Hiển thị đẹp với KaTeX
- **Progress tracking**: Đánh dấu các bước đã hoàn thành
- **Visual feedback**: UI thay đổi theo tiến độ

#### 3. Progressive Hint System
- **3 mức độ hints**: Beginner, Intermediate, Advanced
- **Unlock từng bước**: Mở khóa hints khi cần
- **Session persistence**: Lưu tiến độ trong localStorage
- **API sync**: Đồng bộ với server

#### 4. Code Playground
- **Syntax highlighting**: Prism.js cho Python code
- **Sample code**: Mẫu code để giải quyết thử thách
- **Copy functionality**: Sao chép code dễ dàng

#### 5. Flag Submission
- **Real-time validation**: Kiểm tra flag ngay lập tức
- **Attempt tracking**: Lưu lại tất cả các lần thử
- **IP logging**: Theo dõi để phân tích và chống abuse
- **Rate limiting**: Bảo vệ khỏi brute force attacks

### 🎨 UI/UX Features

- ⚡ **Hero Section**: Banner ấn tượng với gradient và animations
- 🎭 **Dark/Light Mode**: Tự động lưu preference
- 📱 **Fully Responsive**: Hoạt động mượt mà trên mọi thiết bị
- 🎯 **Tab Navigation**: Chuyển đổi nhanh giữa các công cụ
- 🎪 **Smooth Animations**: Transitions mượt mà, professional
- 🎨 **Modern Design**: Shadcn/ui components với Tailwind CSS

---

## 💻 Yêu cầu hệ thống

### Môi trường phát triển

```plaintext
Node.js: >= 18.0.0
npm: >= 9.0.0
RAM: >= 2GB
Disk Space: >= 500MB
```

### Trình duyệt hỗ trợ

- Chrome/Edge >= 90
- Firefox >= 88
- Safari >= 14
- Opera >= 76

---

## 🚀 Cài đặt

### Bước 1: Clone Repository

```bash
git clone https://github.com/F12FLASH/CTF.git
cd CTF/13. RSA in a Parallel Universe
```

### Bước 2: Cài đặt Dependencies

```bash
npm install
```

### Bước 3: Cấu hình Environment Variables

Tạo file `.env` từ template:

```bash
cp .env.example .env
```

Chỉnh sửa file `.env`:

```env
# Challenge flag (BẮT BUỘC cho production)
CTF_FLAG=VNFLAG{TU_HAO_DAN_TOC_VIETNAM_TRUYEN_THONG_BAT_TU_5R9k2P1m7Q4z3L6f0B8yXc}

# Database (tùy chọn, mặc định dùng in-memory)
# DATABASE_URL=postgresql://user:password@localhost:5432/ctf_db

# Server config
NODE_ENV=development
PORT=5000

# Rate limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
FLAG_SUBMIT_RATE_LIMIT=10
```

### Bước 4: Chạy Development Server

```bash
npm run dev
```

Ứng dụng sẽ chạy tại: `http://localhost:5000`

---

## 📖 Sử dụng

### Cho Người chơi CTF

#### 1. Khám phá Challenge

- Đọc kỹ mô tả challenge ở trang chủ
- Tìm hiểu về Gaussian Integers và RSA
- Xem các phương pháp giải quyết được gợi ý

#### 2. Sử dụng Tools

**Calculator**: Tính toán các phép toán Gaussian
```
Ví dụ: (3 + 2i) + (1 + 4i) = 4 + 6i
       (3 + 2i) × (1 + 4i) = -5 + 14i
       N(3 + 2i) = 13
```

**Solver**: Theo dõi các bước giải
- Phân tích modulus n
- Tính norm của prime factors
- Tính φ(n)
- Tìm khóa bí mật d
- Giải mã ciphertext

**Hints**: Mở khóa từng gợi ý
- Beginner: Cơ bản về Gaussian integers
- Intermediate: Kỹ thuật phân tích
- Advanced: Thuật toán chi tiết

#### 3. Submit Flag

```
Format: VNFLAG{...}
```

Nhập flag và nhấn Submit. Hệ thống sẽ kiểm tra và thông báo kết quả.

### Cho Giáo viên / Organizers

#### Tùy chỉnh Challenge

1. **Thay đổi Flag**:
```bash
# Trong .env
CTF_FLAG=VNFLAG{YOUR_CUSTOM_FLAG_HERE}
```

2. **Điều chỉnh Rate Limiting**:
```bash
FLAG_SUBMIT_RATE_LIMIT=5  # Giảm xuống 5 lần/15 phút
```

3. **Thêm Database**:
```bash
DATABASE_URL=postgresql://...
npm run db:push
```

#### Monitor Activity

Xem logs để theo dõi:
```bash
# Server logs hiển thị:
# - Flag submission attempts
# - IP addresses
# - Success/failure rates
```

---

## 📚 Lý thuyết toán học

### Gaussian Integers

**Định nghĩa**: Số phức có dạng `a + bi` với a, b ∈ ℤ

**Tính chất**:
- Vành giao hoán với đơn vị
- Miền Euclid (có thuật toán division)
- Miền phân tích duy nhất (unique factorization domain)

### Gaussian Primes

Số phức Gaussian nguyên tố:

1. **Số nguyên tố dạng 4k+3**: 3, 7, 11, 19, 23, ...
2. **Số có norm là prime dạng 4k+1**: 
   - 1+i, 2+i, 3+2i, 4+i, ...
3. **1+i và associates**: 1+i, 1-i, -1+i, -1-i

### Norm Function

```
N(a + bi) = a² + b²
```

Tính chất:
- N(zw) = N(z) × N(w) (multiplicative)
- N(z) = 0 ⟺ z = 0
- N(z) = 1 ⟺ z là unit

### RSA trên Gaussian Integers

#### Key Generation

1. Chọn Gaussian primes p, q
2. n = p × q
3. φ(n) = N(p-1) × N(q-1)
4. Chọn e: gcd(N(e), φ(n)) = 1
5. d = e⁻¹ mod φ(n)

#### Encryption/Decryption

```
Encrypt: c = m^e mod n
Decrypt: m = c^d mod n
```

### Phương pháp giải

#### 1. Factorization Attack

```python
# Bước 1: Tính N(n)
N_n = n.real**2 + n.imag**2

# Bước 2: Phân tích N(n) thành các prime factors
# Bước 3: Tìm Gaussian primes từ prime factors
# Bước 4: Tái tạo p và q
```

#### 2. Euler's Totient

```python
phi_n = (N(p) - 1) * (N(q) - 1)
d = pow(e, -1, phi_n)
```

#### 3. Decryption

```python
m = pow(c, d, n)  # Trong ℤ[i]
```

---

## 🏗️ Kiến trúc hệ thống

### Technology Stack

#### Frontend
- **React 18**: UI library
- **TypeScript**: Type safety
- **Vite**: Build tool & dev server
- **TanStack Query**: Data fetching & caching
- **Wouter**: Lightweight routing
- **Shadcn/ui**: Component library
- **Tailwind CSS**: Styling
- **KaTeX**: Math rendering
- **Prism.js**: Code highlighting

#### Backend
- **Express.js**: Web framework
- **TypeScript**: Type safety
- **Helmet**: Security headers
- **Express Rate Limit**: DDoS protection
- **Zod**: Schema validation
- **Drizzle ORM**: Database toolkit

#### DevOps
- **tsx**: TypeScript execution
- **esbuild**: Production bundling
- **ESLint**: Code linting
- **PostCSS**: CSS processing

---

## 🛡️ Bảo mật

### Security Features

#### 1. Rate Limiting

**General API Rate Limit**:
- 100 requests / 15 minutes per IP
- Applies to all `/api/*` endpoints

**Flag Submission Rate Limit**:
- 10 attempts / 15 minutes per IP
- Stricter limit to prevent brute force
- Success không tính vào limit

#### 2. Security Headers (Helmet)

```javascript
helmet({
  contentSecurityPolicy: production only,
  crossOriginEmbedderPolicy: false,
})
```

Headers được set:
- X-DNS-Prefetch-Control
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- X-Download-Options
- X-Permitted-Cross-Domain-Policies

#### 3. Environment-based Configuration

- Flag được load từ `process.env.CTF_FLAG`
- Không hardcode sensitive data
- Warning khi chạy production mà thiếu env vars

#### 4. Input Validation

- Zod schemas validate tất cả inputs
- Type checking với TypeScript
- Sanitize user inputs

#### 5. IP Logging

- Track IP address của mỗi submission
- Analytics và abuse detection
- Privacy-conscious (không lưu PII khác)

### Best Practices

1. **Luôn set CTF_FLAG trong production**
```bash
export CTF_FLAG="your-secure-flag-here"
```

2. **Sử dụng HTTPS trong production**
```bash
# Với reverse proxy như nginx
server {
    listen 443 ssl;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ...
}
```

3. **Monitor logs thường xuyên**
```bash
# Check for suspicious activity
tail -f logs/app.log | grep "flag/submit"
```

4. **Backup database định kỳ**
```bash
# Nếu dùng PostgreSQL
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d).sql
```

---

## 🔧 Phát triển

### Development Workflow

1. **Start dev server**:
```bash
npm run dev
```

2. **Make changes**: Code tự động reload với HMR

3. **Check types**:
```bash
npm run check
```

4. **Build for production**:
```bash
npm run build
```

### Thêm Features mới

#### Thêm API Endpoint

1. Định nghĩa schema trong `shared/schema.ts`
2. Thêm storage method trong `server/storage.ts`
3. Tạo route trong `server/routes.ts`
4. Gọi API từ frontend với TanStack Query

#### Thêm UI Component

1. Tạo component trong `client/src/components/`
2. Sử dụng Shadcn components từ `@/components/ui`
3. Style với Tailwind CSS
4. Thêm data-testid cho testing

### Database Migration

Nếu muốn chuyển sang PostgreSQL:

1. **Setup database**:
```bash
# Tạo Neon database hoặc local PostgreSQL
export DATABASE_URL="postgresql://..."
```

2. **Push schema**:
```bash
npm run db:push
```

3. **Update storage** trong `server/storage.ts`:
```typescript
// Replace MemStorage with DrizzleStorage
```

---

## 🚢 Triển khai

### Docker Deployment

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 5000
CMD ["npm", "start"]
```

```bash
docker build -t rsa-ctf .
docker run -p 5000:5000 \
  -e CTF_FLAG="your-flag" \
  -e NODE_ENV=production \
  rsa-ctf
```

### VPS Deployment

1. **Clone & Install**:
```bash
git clone <repo>
cd rsa-parallel-universe
npm install
npm run build
```

2. **Setup PM2**:
```bash
npm install -g pm2
pm2 start npm --name "rsa-ctf" -- start
pm2 startup
pm2 save
```

3. **Nginx Reverse Proxy**:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## ❓ FAQ

### Câu hỏi thường gặp

**Q: Làm sao để thay đổi flag?**
A: Set environment variable `CTF_FLAG` trong file `.env` hoặc hosting platform.

**Q: Tại sao không dùng database mặc định?**
A: In-memory storage đơn giản cho development và small-scale CTF. Nếu cần persistence, dùng PostgreSQL.

**Q: Làm sao customize rate limiting?**
A: Chỉnh sửa các biến trong `.env`:
- `RATE_LIMIT_MAX_REQUESTS`
- `FLAG_SUBMIT_RATE_LIMIT`

**Q: Challenge này có phù hợp cho beginners?**
A: Không, đây là challenge Master level. Cần kiến thức về:
- Lý thuyết số
- Số phức
- RSA cryptography
- Thuật toán phân tích

**Q: Có solution script không?**
A: Không public solution để giữ tính thử thách. Hints có thể giúp bạn giải quyết.

**Q: Làm sao để tắt hint system?**
A: Comment out hoặc remove `<HintSystem />` component trong `home.tsx`.

---

## 🤝 Đóng góp

Chúng tôi hoan nghênh mọi đóng góp!

### Quy trình

1. Fork repository
2. Tạo feature branch: `git checkout -b feature/AmazingFeature`
3. Commit changes: `git commit -m 'Add AmazingFeature'`
4. Push to branch: `git push origin feature/AmazingFeature`
5. Mở Pull Request

### Guidelines

- Follow existing code style
- Add tests cho features mới
- Update documentation
- Ensure all tests pass
- Write clear commit messages

### Bug Reports

Mở issue với:
- Mô tả chi tiết bug
- Steps to reproduce
- Expected vs actual behavior
- Screenshots (nếu có)
- Environment info (OS, browser, Node version)

---

## 📝 Giấy phép

MIT License - xem [LICENSE](LICENSE) để biết thêm chi tiết.

---

## 🙏 Acknowledgments

- **Vietnamese CTF Community** - Cảm hứng và support
- **Shadcn** - Amazing UI components
- **Mathematical Cryptography researchers** - Lý thuyết

---

## 📞 Liên hệ

- **Issues**: https://github.com/F12FLASH/CTF/issues
- **Email**: loideveloper.37@gmail.com


---

<div align="center">

**Được xây dựng với ❤️ bởi Vietnamese CTF Community**

⭐ Star repo nếu bạn thấy hữu ích!

</div>
