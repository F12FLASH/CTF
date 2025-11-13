# 🕳️ The Black Hole - Vietnamese CTF Challenge Platform

[🇻🇳 Tiếng Việt](#tiếng-việt) | [🇬🇧 English](#english)

---

## English

### 📖 Overview

**The Black Hole** is a professional Capture The Flag (CTF) challenge platform focused on advanced binary exploitation (pwn) techniques. Designed with inspiration from platforms like HackTheBox and TryHackMe, it features a stunning cybersecurity aesthetic with Vietnamese cultural elements and full bilingual support (English/Vietnamese).

This educational platform enables security enthusiasts to master sophisticated exploitation techniques through:
- 🖥️ Interactive code editors with syntax highlighting
- 🔬 Binary simulators for testing exploits
- 📚 Step-by-step exploitation guides
- 🎯 Secure flag validation with encryption
- 🔐 One-time flag reveal system

### ✨ Features

#### 🎓 Educational Content
- **Master-level Challenge**: "The Black Hole" featuring seccomp sandbox bypass
- **Detailed Exploitation Guides**: 5-step walkthrough with Python code examples
- **Interactive Binary Simulator**: Test format string payloads and observe GOT overwrites
- **Downloadable Binary**: Simulated binary file with exploitation hints
- **Bilingual Support**: Seamless switching between English and Vietnamese

#### 🛡️ Security & Performance
- **Encrypted Flag Storage**: AES-256-GCM encryption for flag protection
- **Bcrypt Hashing**: Secure flag validation with constant-time comparison
- **One-Time Reveal Tokens**: 5-minute expiration, single-use tokens
- **Rate Limiting**: Protection against brute-force attacks
  - General API: 100 requests per 15 minutes
  - Submissions: 10 attempts per minute
- **Security Headers**: Helmet.js for HTTP security (CSP, HSTS)
- **Input Validation**: Comprehensive Zod schema validation
- **PostgreSQL Database**: Persistent data storage with Drizzle ORM

#### 🎨 Modern Tech Stack
- **Frontend**: React 18 + TypeScript + Vite
- **Backend**: Express.js + TypeScript
- **Database**: PostgreSQL with Neon serverless
- **UI**: shadcn/ui + Radix UI + Tailwind CSS
- **State Management**: TanStack React Query v5
- **Encryption**: Node.js Crypto (AES-256-GCM)
- **Hashing**: bcrypt with salt rounds 12

### 🚀 Quick Start

#### Prerequisites

- Node.js 18+ or 20+
- PostgreSQL database
- npm or yarn

#### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/F12FLASH/CTF.git
   cd CTF/8.The Black Hole
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   
   Create `.env` file with these required variables:
   ```env
   # Database Connection
   DATABASE_URL=postgresql://user:password@host:port/database
   
   # Application Configuration
   NODE_ENV=development
   PORT=5000
   
   # Security - Flag Management (KEEP SECRET!)
   BLACK_HOLE_FLAG=VNFLAG{your_custom_flag_here}
   FLAG_ENCRYPTION_KEY=<64-character-hex-string>
   
   # Rate Limiting (Optional - defaults provided)
   RATE_LIMIT_WINDOW_MS=900000
   RATE_LIMIT_MAX_REQUESTS=100
   SUBMISSION_RATE_LIMIT_WINDOW_MS=60000
   SUBMISSION_RATE_LIMIT_MAX_REQUESTS=10
   ```
   
   **Generate FLAG_ENCRYPTION_KEY**:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

4. **Initialize the database**
   ```bash
   npm run db:push
   ```

5. **Start the development server**
   ```bash
   npm run dev
   ```

6. **Access the application**
   ```
   http://localhost:5000
   ```

### 🔧 Available Scripts

- **`npm run dev`** - Start development server (frontend + backend with hot reload)
- **`npm run build`** - Build for production
- **`npm run start`** - Start production server
- **`npm run check`** - Run TypeScript type checking
- **`npm run db:push`** - Push database schema changes

### 🏗️ Architecture

#### Security Architecture

**Flag Protection Flow**:
```
1. Flag stored as:
   ├── flagHash (bcrypt, salt rounds 12)
   └── encryptedFlag (AES-256-GCM with server key)

2. Flag submission:
   ├── User submits flag → POST /api/submissions
   ├── Server validates with bcrypt.compare() [constant-time]
   └── If correct: Generate one-time reveal token (5min TTL)

3. Flag reveal:
   ├── User requests reveal → POST /api/reveal-flag
   ├── Server validates token (one-time use, not expired)
   ├── Decrypts flag with AES-256-GCM
   └── Returns flag to user (token consumed)
```

**Database Schema**:

```typescript
// Challenges Table
challenges {
  id: varchar (PK)
  name: text
  nameVi: text
  category: text
  difficulty: text
  description: text
  descriptionVi: text
  flagHash: text              // bcrypt hash
  encryptedFlag: text         // AES-256-GCM encrypted
  seccompRules: text[]
  vulnerabilities: text[]
  protections: text[]
  environment: text[]
  skills: text[]
  solvers: varchar
  successRate: varchar
}

// Submissions Table
submissions {
  id: varchar (PK, UUID)
  challengeId: varchar
  isCorrect: boolean
  submittedAt: timestamp
  // Note: No flag stored for security
}

// Reveal Tokens Table
revealTokens {
  id: varchar (PK, UUID)
  token: text (unique)        // 64-char hex token
  challengeId: varchar
  used: boolean
  expiresAt: timestamp        // 5 minutes from creation
  createdAt: timestamp
}

// Users Table
users {
  id: varchar (PK, UUID)
  username: text (unique)
  password: text
}
```

#### API Endpoints

| Method | Endpoint | Description | Rate Limit | Security |
|--------|----------|-------------|------------|----------|
| `GET` | `/api/challenge/:id` | Get challenge details (no flag) | 100/15min | Input validation |
| `POST` | `/api/submissions` | Submit flag for validation | 10/min | Bcrypt verify, token generation |
| `POST` | `/api/reveal-flag` | Reveal flag with valid token | N/A | One-time token, AES decryption |

**Security Features**:
- ✅ Flag never exposed in plaintext
- ✅ Constant-time comparison prevents timing attacks  
- ✅ One-time reveal tokens with expiration
- ✅ Rate limiting prevents brute force
- ✅ Input validation with Zod schemas
- ✅ Helmet.js security headers (CSP, HSTS)
- ✅ No flag in logs or API responses

### 🎯 Challenge: The Black Hole

#### Technical Details

- **Category**: Binary Exploitation (Pwn)
- **Difficulty**: Master Hacker
- **Binary**: ELF 64-bit (simulated)
- **Protections**: 
  - Seccomp filter (only read, write, exit allowed)
  - No executable stack
  - No ASLR bypass needed for GOT
- **Vulnerabilities**: Format string bug
- **Unique Aspect**: No traditional stack for exploitation

#### Exploitation Strategy

This challenge requires creative exploitation of a heavily restricted binary:

1. **Address Leakage** (Format String)
   - Use `%p` format specifiers to leak memory addresses
   - Target: libc base, binary base, stack pointers
   - Calculate offsets for ROP gadgets

2. **Syscall Gadget Discovery**
   - Find `syscall; ret` gadget in libc
   - Locate register control gadgets (pop rax, pop rdi, etc.)
   - Calculate gadget addresses from libc base

3. **GOT Overwrite** (Format String Write-What-Where)
   - Identify exit@GOT address (binary_base + 0x4028)
   - Use format string `%n` to write syscall gadget address
   - Craft precise payload with correct offsets

4. **Shellcode Preparation**
   - Use allowed read() syscall to stage shellcode
   - Write to writable memory region
   - Prepare `/bin/sh` string or flag read code

5. **Execution Trigger**
   - Call exit() to trigger overwritten GOT entry
   - Syscall gadget executes with controlled registers
   - Execute desired syscall (execve or open/read/write)

#### Interactive Components

**Binary Simulator**:
- Terminal-like interface for testing exploits
- Simulates format string vulnerability
- Shows GOT overwrite visualization
- Guides users through exploitation steps
- **Security Note**: Does NOT reveal actual flag

**Code Editor**:
- Tabbed interface (Python/C)
- Pre-loaded with exploitation templates
- Syntax highlighting with Prism.js
- Example payloads for each exploitation step

**Downloadable Binary**:
- Simulated binary file with hints
- Architecture and compilation details
- Exploitation strategy overview
- **Note**: Educational simulation, not actual binary

### 🔐 Security Best Practices

#### Production Deployment Checklist

**Environment Setup**:
- ✅ Set `NODE_ENV=production`
- ✅ Generate strong `FLAG_ENCRYPTION_KEY` (64-char hex)
- ✅ Use unique, complex challenge flags
- ✅ Enable HTTPS with valid SSL certificate
- ✅ Configure `DATABASE_URL` with SSL enabled
- ✅ Set appropriate rate limits for your traffic

**Server Configuration**:
- ✅ Use reverse proxy (nginx/Caddy) for HTTPS termination
- ✅ Enable firewall (allow only 443/80)
- ✅ Set up process manager (PM2/systemd)
- ✅ Configure log rotation
- ✅ Enable database backups
- ✅ Monitor for suspicious activity

**Security Hardening**:
- ✅ Never commit `.env` or secrets to git
- ✅ Rotate encryption keys periodically
- ✅ Monitor rate limit violations
- ✅ Review database queries for optimization
- ✅ Implement logging for security events
- ✅ Set up error tracking (Sentry/similar)

#### Manual Deployment (VPS/Cloud)

```bash
# Build the application
npm run build

# Set production environment
export NODE_ENV=production
export DATABASE_URL="postgresql://..."
export BLACK_HOLE_FLAG="VNFLAG{...}"
export FLAG_ENCRYPTION_KEY="..."

# Start server
npm start
```

### 🤝 Contributing

We welcome contributions! Please follow these guidelines:

**Code Standards**:
- TypeScript with strict mode
- ESLint + Prettier for code formatting
- Meaningful commit messages
- Test security changes thoroughly

**Pull Request Process**:
1. Fork the repository
2. Create feature branch (`feature/amazing-feature`)
3. Make your changes with tests
4. Ensure `npm run check` passes
5. Submit PR with clear description

### 📝 License

This project is licensed under the MIT License.

### 🙏 Acknowledgments

- **shadcn/ui** - Beautiful, accessible React components
- **Radix UI** - Unstyled, accessible primitives
- **Drizzle ORM** - Type-safe database queries
- **TanStack Query** - Powerful data synchronization

---

## Tiếng Việt

### 📖 Tổng quan

**The Black Hole (Lỗ Đen)** là nền tảng thử thách Capture The Flag (CTF) chuyên nghiệp tập trung vào kỹ thuật khai thác binary (pwn) nâng cao. Nền tảng có giao diện an ninh mạng ấn tượng với yếu tố văn hóa Việt Nam và hỗ trợ song ngữ hoàn chỉnh.

### ✨ Tính năng Chính

#### 🛡️ Bảo mật Nâng cao
- **Mã hóa Flag**: AES-256-GCM bảo vệ flag trong database
- **Hash Bcrypt**: Xác thực flag an toàn với so sánh thời gian cố định
- **Token Hiển thị Một lần**: Hết hạn sau 5 phút, chỉ sử dụng 1 lần
- **Rate Limiting**: Bảo vệ chống tấn công brute-force
- **Input Validation**: Xác thực toàn diện với Zod schemas

#### 🎓 Nội dung Giáo dục
- **Thử thách Cấp Master**: Bypass seccomp sandbox
- **Hướng dẫn Chi tiết**: 5 bước với code Python
- **Mô phỏng Binary**: Test payload và quan sát GOT overwrite
- **Tải Binary**: File binary mô phỏng với gợi ý khai thác
- **Song ngữ**: Chuyển đổi Tiếng Việt/Tiếng Anh

### 🚀 Cài đặt Nhanh

#### Yêu cầu Hệ thống

- Node.js 18+ hoặc 20+
- PostgreSQL database
- npm hoặc yarn

#### Các Bước Cài đặt

1. **Clone repository**
   ```bash
   git clone https://github.com/F12FLASH/CTF.git
   cd CTF/8.The Black Hole
   ```

2. **Cài đặt dependencies**
   ```bash
   npm install
   ```

3. **Cấu hình biến môi trường**
   
   Tạo file `.env`:
   ```env
   # Kết nối Database
   DATABASE_URL=postgresql://user:password@host:port/database
   
   # Cấu hình Ứng dụng
   NODE_ENV=development
   PORT=5000
   
   # Bảo mật - Quản lý Flag (GIỮ BÍ MẬT!)
   BLACK_HOLE_FLAG=VNFLAG{flag_tùy_chỉnh_của_bạn}
   FLAG_ENCRYPTION_KEY=<chuỗi-hex-64-ký-tự>
   ```
   
   **Tạo FLAG_ENCRYPTION_KEY**:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

4. **Khởi tạo database**
   ```bash
   npm run db:push
   ```

5. **Khởi động server**
   ```bash
   npm run dev
   ```

6. **Truy cập ứng dụng**
   ```
   http://localhost:5000
   ```

### 🎯 Thử thách: The Black Hole

#### Chi tiết Kỹ thuật

- **Thể loại**: Khai thác Binary (Pwn)
- **Độ khó**: Master Hacker
- **Lỗ hổng**: Format string, Memory corruption
- **Bảo vệ**: Seccomp sandbox, No executable stack
- **Đặc điểm**: Không có stack truyền thống

#### Kỹ thuật Khai thác

1. **Rò rỉ Địa chỉ**: Format string để leak memory
2. **Tìm Syscall Gadget**: Phân tích ROP gadgets
3. **Ghi đè GOT**: Format string write-what-where
4. **Chuẩn bị Shellcode**: Sử dụng syscall được phép
5. **Kích hoạt Thực thi**: GOT hijacking qua exit()

#### Thành phần Tương tác

**Binary Simulator**:
- Giao diện terminal để test exploit
- Mô phỏng lỗ hổng format string
- Hiển thị GOT overwrite
- Hướng dẫn từng bước khai thác
- **Lưu ý**: KHÔNG hiển thị flag thật

**Code Editor**:
- Giao diện tab (Python/C)
- Template exploitation sẵn có
- Syntax highlighting
- Ví dụ payload cho mỗi bước

### 🔐 Best Practices Bảo mật

#### Checklist Triển khai Production

**Cấu hình Môi trường**:
- ✅ Đặt `NODE_ENV=production`
- ✅ Tạo `FLAG_ENCRYPTION_KEY` mạnh (64-char hex)
- ✅ Sử dụng flag phức tạp, độc nhất
- ✅ Bật HTTPS với SSL certificate
- ✅ Cấu hình `DATABASE_URL` với SSL
- ✅ Đặt rate limit phù hợp

**Cấu hình Server**:
- ✅ Sử dụng reverse proxy (nginx/Caddy)
- ✅ Bật firewall (chỉ cho phép 443/80)
- ✅ Cài đặt process manager (PM2/systemd)
- ✅ Cấu hình log rotation
- ✅ Bật database backups
- ✅ Giám sát hoạt động đáng ngờ
---

<div align="center">

**Made with ❤️ for the Vietnamese cybersecurity community**

**Được tạo với ❤️ cho cộng đồng an ninh mạng Việt Nam**

</div>
