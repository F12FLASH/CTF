# 🎯 GraphQL Apocalypse - CTF Challenge

<div align="center">

![Difficulty](https://img.shields.io/badge/Độ_Khó-CỰC_KHÓ-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Bảo_Mật-Nâng_Cao-green?style=for-the-badge)

**Thử thách bảo mật GraphQL với lỗ hổng Type Confusion**

[📖 Hướng Dẫn](#hướng-dẫn-cài-đặt) • [🎮 Cách Chơi](#cách-chơi) • [💡 Giải Pháp](#hướng-dẫn-giải-chi-tiết) • [🔒 Bảo Mật](#tính-năng-bảo-mật)

</div>

---

## 🎮 Giới Thiệu

**GraphQL Apocalypse** là một thử thách Capture The Flag (CTF) chuyên về bảo mật GraphQL. Người chơi phải khai thác lỗ hổng **Type Confusion** để truy cập vào dữ liệu được bảo vệ và lấy được flag.

### 🎯 Mục Tiêu

- Khám phá GraphQL schema thông qua introspection
- Tìm các mutation ẩn không được ghi lại
- Khai thác lỗ hổng type confusion trong input handling
- Lấy flag từ cơ sở dữ liệu

### 🏆 Flag

```
VNFLAG{[REDACTED]}
```

⚠️ **Lưu ý:** Flag và access code đã được mã hóa và nhúng trực tiếp trong source code. Bạn cần giải thử thách GraphQL để lấy flag!

---

## ✨ Tính Năng

### 🎨 Giao Diện

- ⚡ **Terminal-inspired UI** với hiệu ứng Cyberpunk
- 🌙 **Dark Mode** tối ưu cho đôi mắt
- 📱 **Responsive Design** hoạt động trên mọi thiết bị
- 🎭 **Animations** mượt mà và chuyên nghiệp

### 🔧 Chức Năng

- 📝 **Query Editor** với syntax highlighting
- 🔍 **Schema Explorer** với introspection queries
- 📊 **Real-time Response Viewer**
- 🎯 **Flag Submission System**
- 💡 **Hệ thống gợi ý thông minh**

### 🔒 Bảo Mật

- 🛡️ **Helmet.js** - Security headers
- 🚦 **Rate Limiting** - Chống brute force  
- 🔐 **Input Validation** - Sanitization với validator.js
- 🔑 **Bcrypt Hashing** - Mã hóa access code
- 🌐 **CORS Configuration** - Kiểm soát truy cập
- 🔒 **Code Obfuscation** - Mã hóa flag và secrets trong code

---

## 🛠️ Công Nghệ Sử Dụng

### Frontend

```
⚛️  React 18.3.1          - UI Framework
🎨  Tailwind CSS 3.4      - Styling
📦  Vite 5.4              - Build Tool
🔄  TanStack Query 5.60   - Data Fetching
🎭  Framer Motion 11.13   - Animations
🎯  Wouter 3.3            - Routing
🧩  Shadcn UI             - Component Library
```

### Backend

```
🚀  Express 4.21          - Server Framework
📊  GraphQL 16.12         - API Query Language
🔧  TypeScript 5.6        - Type Safety
🛡️  Helmet                - Security Headers
🚦  Express Rate Limit    - Rate Limiting
🔐  Bcrypt               - Password Hashing
✅  Validator.js          - Input Validation
🌐  CORS                  - Cross-Origin Resource Sharing
```

### DevOps & Tools

```
📝  TSX                   - TypeScript Execution
🔨  ESBuild              - Fast Bundler
📋  Drizzle ORM          - Database ORM (configured)
🎨  Lucide React         - Icon Library
```

---

## 📥 Hướng Dẫn Cài Đặt

### Yêu Cầu Hệ Thống

- Node.js >= 18.0.0
- npm >= 9.0.0
- Hệ điều hành: Linux, macOS, hoặc Windows

### Cài Đặt Nhanh

```bash
# 1. Clone repository
git clone https://github.com/F12FLASH/CTF.git
cd CTF/7.GraphQL Apocalypse

# 2. Cài đặt dependencies
npm install

# 3. Tạo file .env từ template (tùy chọn)
cp .env.example .env

# 4. Khởi động development server
npm run dev
```

**Lưu ý:** Flag và access code đã được mã hóa và nhúng trực tiếp trong code. Không cần cấu hình thêm!

### Truy Cập Ứng Dụng

Mở trình duyệt và truy cập: **http://localhost:5000**

---

## 🎮 Cách Chơi

### Bước 1: Khám Phá Schema

Sử dụng GraphQL introspection để tìm hiểu về schema:

```graphql
query {
  __schema {
    types {
      name
      kind
      description
    }
  }
}
```

### Bước 2: Tìm Mutation Type

Khám phá các mutation có sẵn:

```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        description
      }
    }
  }
}
```

### Bước 3: Kiểm Tra Mutation Ẩn

Tìm mutation `unlockSecretVault`:

```graphql
query {
  __type(name: "Mutation") {
    fields {
      name
      description
      args {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

### Bước 4: Phân Tích Input Type

Xem cấu trúc của `AccessKey`:

```graphql
query {
  __type(name: "AccessKey") {
    name
    kind
    inputFields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

### Bước 5: Khai Thác Type Confusion

Thử các cách khác nhau để truyền `accessKey`. Mutation này có lỗ hổng type confusion - nó chấp nhận nhiều định dạng input khác nhau.

### Bước 6: Lấy Flag

Khi tìm được cách đúng, mutation sẽ trả về flag. Nộp flag để hoàn thành thử thách!

---

## 📚 Kiến Thức Cần Có

### GraphQL Basics

- **Query**: Lấy dữ liệu từ server
- **Mutation**: Thay đổi dữ liệu trên server
- **Type System**: Hệ thống kiểu dữ liệu của GraphQL
- **Introspection**: Khám phá schema tự động

### Security Concepts

- **Type Confusion**: Lỗ hổng khi hệ thống xử lý sai kiểu dữ liệu
- **Input Validation**: Kiểm tra và làm sạch dữ liệu đầu vào
- **Introspection Abuse**: Lạm dụng introspection để thu thập thông tin

### Recommended Reading

- [GraphQL Official Docs](https://graphql.org/learn/)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL Security Best Practices](https://escape.tech/blog/graphql-security/)

---

## 💡 Hướng Dẫn Giải Chi Tiết

<details>
<summary><strong>⚠️ SPOILER ALERT - Nhấn để xem lời giải</strong></summary>

### 🔍 Bước 1: Khám Phá Schema

Đầu tiên, chúng ta cần biết schema có những gì:

```graphql
query IntrospectionQuery {
  __schema {
    types {
      name
      kind
    }
    queryType {
      name
    }
    mutationType {
      name
    }
  }
}
```

**Kết quả quan trọng:**
- Có `mutationType` tồn tại
- Có các type: `Query`, `Mutation`, `User`, `ServerInfo`, `SecretData`, `AccessKey`

### 🎯 Bước 2: Liệt Kê Tất Cả Mutation

```graphql
query GetAllMutations {
  __type(name: "Mutation") {
    fields {
      name
      description
      args {
        name
        type {
          name
          kind
          ofType {
            name
          }
        }
      }
    }
  }
}
```

**Phát hiện:**
- Mutation `ping` - có vẻ bình thường
- Mutation `unlockSecretVault` - 🚨 ĐÂY RỒI! Có description gợi ý về type confusion

### 🔎 Bước 3: Phân Tích AccessKey Input Type

```graphql
query InspectAccessKey {
  __type(name: "AccessKey") {
    name
    kind
    description
    inputFields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

**Phát hiện:**
- `code`: String
- `value`: Int  
- `data`: String

Tất cả đều **optional** (nullable)! Điều này đáng ngờ.

### 🧪 Bước 4: Thử Nghiệm Type Confusion

#### Thử 1: Truyền code trực tiếp

```graphql
mutation {
  unlockSecretVault(accessKey: { code: "TEST" }) {
    flag
    message
  }
}
```

❌ Không hoạt động - nhưng không báo lỗi!

#### Thử 2: Thử value

```graphql
mutation {
  unlockSecretVault(accessKey: { value: 123 }) {
    flag
    message
  }
}
```

❌ Vẫn không hoạt động

#### Thử 3: Thử data field

```graphql
mutation {
  unlockSecretVault(accessKey: { data: "test" }) {
    flag
    message
  }
}
```

❌ Không hoạt động

### 💡 Bước 5: Hiểu Type Confusion Vulnerability

Đọc kỹ description:
- "Type confusion vulnerability: String vs Int vs **Object**"
- Có thể `data` field chấp nhận JSON string?

Xem resolver code (nếu có source code) hoặc thử nghiệm:

```javascript
// Resolver có thể parse JSON trong data field
if (accessKey.data) {
  try {
    const parsed = JSON.parse(accessKey.data);
    if (parsed.secret) {
      accessCode = parsed.secret;
    }
  } catch {
    accessCode = accessKey.data;
  }
}
```

### 🎯 Bước 6: Khai Thác Thành Công

Dựa trên phân tích description của mutation và AccessKey type, bạn cần suy ra access code đúng. 

**Gợi ý:**
- Description nhắc đến "type confusion vulnerability"
- Access code thường liên quan đến tên lỗ hổng
- Thử kết hợp các từ khóa liên quan

```graphql
mutation ExploitVault {
  unlockSecretVault(accessKey: { code: "[YOUR_ACCESS_CODE_HERE]" }) {
    flag
    message
  }
}
```

**✅ THÀNH CÔNG!**

**Response:**
```json
{
  "data": {
    "unlockSecretVault": {
      "flag": "VNFLAG{...flag_content...}",
      "message": "Quyền truy cập được cấp! Bạn đã khai thác thành công lỗ hổng type confusion."
    }
  }
}
```

### 📝 Bước 7: Nộp Flag

1. Copy flag từ response (định dạng: `VNFLAG{...}`)
2. Click nút "Nộp Flag" trên header
3. Paste flag vào form
4. Submit

**CHÚC MỪNG! Bạn đã hoàn thành thử thách!**

### 🧠 Các Cách Khai Thác Khác

**Cách 2: Sử dụng data field với JSON**

```graphql
mutation {
  unlockSecretVault(
    accessKey: { 
      data: "{\"secret\":\"[ACCESS_CODE]\"}" 
    }
  ) {
    flag
    message
  }
}
```

**Cách 3: Brute force (không khuyến khích - có rate limit)**

```graphql
mutation {
  unlockSecretVault(accessKey: { code: "GUESS_HERE" }) { flag }
}
# Thử nhiều giá trị khác nhau - lưu ý có rate limiting
```

### 📊 Luồng Khai Thác Hoàn Chỉnh

```
1. Introspection → Tìm mutationType
2. List Mutations → Phát hiện unlockSecretVault  
3. Inspect AccessKey → Tìm các field: code, value, data
4. Read Description → Hiểu về type confusion
5. Test Input → Thử các cách truyền accessKey
6. Analyze Hints → Suy luận access code từ gợi ý
7. Exploit → Truyền access code đúng
8. Get Flag → Copy flag từ response
9. Submit → Nộp flag và hoàn thành
```

</details>

---

## 🔒 Tính Năng Bảo Mật

### 🛡️ Security Headers (Helmet.js)

```typescript
helmet({
  contentSecurityPolicy: isDevelopment ? false : undefined,
  crossOriginEmbedderPolicy: false,
})
```

### 🚦 Rate Limiting

```typescript
// Mặc định: 100 requests / 15 phút
windowMs: 900000,
max: 100
```

### 🔐 Password Hashing

```typescript
// Bcrypt với salt rounds = 10
const hash = bcrypt.hashSync(password, 10);
```

### ✅ Input Validation

```typescript
// Validator.js cho flag submission
validator.trim(flag)
length: 1-200 characters
```

### 🌐 CORS Configuration

```typescript
cors({
  origin: config.corsOrigin,
  credentials: true
})
```

---

## ⚙️ Cấu Hình

### Environment Variables

Tạo file `.env` từ `.env.example`:

```env
# Server Configuration
NODE_ENV=development
PORT=5000

# Security
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
SESSION_SECRET=your-super-secret-session-key-change-this-in-production

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS
CORS_ORIGIN=*
```

### Build Commands

```bash
# Development
npm run dev

# Production Build
npm run build

# Production Start
npm start

# Type Checking
npm run check

# Database Push (nếu sử dụng database)
npm run db:push
```

---

## 📡 API Documentation

### GraphQL Endpoint

**URL:** `POST /api/graphql`

**Content-Type:** `application/json`

### Queries

#### 1. Hello Query

```graphql
query {
  hello
}
```

**Response:**
```json
{
  "data": {
    "hello": "Chào mừng đến với GraphQL Apocalypse..."
  }
}
```

#### 2. Get Users

```graphql
query {
  users {
    id
    username
  }
}
```

#### 3. Get Flag (Restricted)

```graphql
query {
  flag
}
```

**Response:**
```json
{
  "data": {
    "flag": "[REDACTED - Access Denied]"
  }
}
```

#### 4. Server Info

```graphql
query {
  serverInfo {
    version
    endpoint
    introspectionEnabled
  }
}
```

### Mutations

#### 1. Ping

```graphql
mutation {
  ping(message: "Hello")
}
```

#### 2. Unlock Secret Vault (Hidden)

```graphql
mutation {
  unlockSecretVault(accessKey: { code: "[ACCESS_CODE]" }) {
    flag
    message
  }
}
```

⚠️ **Lưu ý:** Bạn cần tự tìm access code đúng thông qua khai thác type confusion vulnerability.

### REST Endpoint

#### Submit Flag

**URL:** `POST /api/submit-flag`

**Request:**
```json
{
  "flag": "VNFLAG{...}"
}
```

**Success Response:**
```json
{
  "success": true,
  "message": "Chúc mừng! Bạn đã hoàn thành thử thách..."
}
```

**Error Response:**
```json
{
  "success": false,
  "message": "Flag không chính xác..."
}
```

---

## 🤝 Đóng Góp

Chúng tôi hoan nghênh mọi đóng góp! Nếu bạn muốn cải thiện dự án:

1. Fork repository
2. Tạo branch mới (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Tạo Pull Request

### Coding Standards

- TypeScript strict mode
- ESLint + Prettier
- Conventional Commits
- Comprehensive comments
- Unit tests (khuyến khích)

---

## 📄 License

MIT License - Xem file [LICENSE](LICENSE) để biết thêm chi tiết.

---

## 👨‍💻 Tác Giả

Phát triển với ❤️ bởi F12FLASH.

---

## 🙏 Credits

- **Shadcn UI** - Component Library
- **Radix UI** - Primitive Components
- **Lucide** - Icon Library
- **GraphQL Tools** - Schema Building
- **Express GraphQL** - GraphQL Middleware

---

## 📞 Liên Hệ & Hỗ Trợ

- 🐛 **Bug Reports:** [GitHub Issues](https://github.com/F12FLASH/CTF/issues)
- 📧 **Email:** loideveloper.37@gmail.com


---

<div align="center">

**⭐ Nếu thấy hữu ích, hãy cho dự án một ngôi sao! ⭐**

Made with 💜 and ☕

</div>
