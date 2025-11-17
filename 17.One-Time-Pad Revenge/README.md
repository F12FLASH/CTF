# 🔐 One-Time-Pad Revenge - Nền Tảng Thử Thách CTF Mật Mã

<div align="center">

**Nền tảng giáo dục tương tác để học các kỹ thuật phân tích mật mã nâng cao**

[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)
[![Node.js](https://img.shields.io/badge/Node.js-43853D?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express.js-404D59?style=for-the-badge)](https://expressjs.com/)

</div>

---

## 🎯 Giới Thiệu

**One-Time-Pad Revenge** là một nền tảng CTF (Capture The Flag) tương tác chuyên sâu về mật mã học, tập trung vào việc khai thác lỗ hổng bảo mật khi sử dụng One-Time-Pad (OTP) không đúng cách.

### Vấn Đề Mật Mã Được Mô Phỏng

Ứng dụng mô phỏng một lỗ hổng bảo mật phổ biến trong thực tế: **tái sử dụng key trong hệ thống mã hóa OTP**. Thay vì sử dụng key ngẫu nhiên hoàn toàn (yêu cầu cơ bản của OTP), hệ thống sử dụng key được tạo từ `SHA256(flag)`, dẫn đến việc nhiều bản mã được mã hóa với cùng một key.

### Mục Tiêu Học Tập

- Hiểu nguyên lý hoạt động của One-Time-Pad
- Nắm vững kỹ thuật tấn công XOR analysis
- Thực hành phân tích thống kê trên ciphertext
- Áp dụng known-plaintext attack để khôi phục keystream
- Phát triển tư duy phân tích mật mã

---

## ✨ Tính Năng Chính

### 🔧 Công Cụ Mã Hóa & Phân Tích

1. **Mô Phỏng Mã Hóa OTP**
   - Mã hóa văn bản với key tùy chỉnh hoặc ngẫu nhiên
   - Hiển thị trực quan quá trình XOR
   - Xuất ciphertext dưới dạng hex

2. **Tạo Dữ Liệu Thử Thách**
   - Tạo từ 1-1000 bản mã mã hóa với cùng key
   - Key được tạo từ SHA256(flag)
   - Tải xuống tập dữ liệu để phân tích offline

3. **Tải Lên & Quản Lý Ciphertext**
   - Tải lên qua drag-and-drop hoặc nhập thủ công
   - Hỗ trợ tải lên hàng loạt file
   - Kiểm tra định dạng hex tự động
   - Xóa toàn bộ dữ liệu để bắt đầu lại

### 📊 Phân Tích Chuyên Sâu

1. **Phân Tích Thống Kê**
   - Tính entropy của ciphertext
   - Phân tích tần suất byte
   - Tính độ dài key
   - Trung bình giá trị byte
   - Biểu đồ trực quan

2. **Phân Tích Cặp XOR**
   - So sánh hai ciphertext bất kỳ
   - Tìm patterns lặp lại trong XOR result
   - Hex dump định dạng chuẩn
   - Sắp xếp patterns theo tần suất

3. **Tấn Công Văn Bản Rõ Đã Biết**
   - Nhập prefix văn bản đã biết (vd: `VNFLAG{`)
   - Khôi phục keystream tự động
   - Tính độ tin cậy dựa trên consensus
   - Hiển thị recovered plaintext

4. **Xác Minh Flag**
   - Kiểm tra flag đã khôi phục
   - So sánh SHA256 hash
   - Thông báo kết quả chi tiết

### 📚 Hướng Dẫn Giáo Dục

- Giải thích từng bước phương pháp tấn công
- Ví dụ minh họa cụ thể
- Tips và lưu ý quan trọng
- Hướng dẫn sử dụng công cụ

---

## 🏗️ Kiến Trúc Hệ Thống

```
┌─────────────────────────────────────────────────────────┐
│                    Client (React/Vite)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Components  │  │  TanStack    │  │   Shadcn/ui  │  │
│  │   (TypeScript│  │   Query      │  │   + Tailwind │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└────────────────────────┬────────────────────────────────┘
                         │ HTTPS/REST API
┌────────────────────────┴────────────────────────────────┐
│                  Server (Node.js/Express)               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Routes     │  │    Crypto    │  │   Security   │  │
│  │   (REST API) │  │    Utils     │  │   Middleware │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │         In-Memory Storage (Map-based)            │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 💻 Yêu Cầu Hệ Thống

### Phần Mềm Yêu Cầu

- **Node.js**: >= 18.x
- **npm**: >= 9.x hoặc **yarn**: >= 1.22

### Hệ Điều Hành Hỗ Trợ

- ✅ Windows 10/11
- ✅ macOS 12+
- ✅ Linux (Ubuntu 20.04+, Debian 11+)

---

## 🚀 Hướng Dẫn Cài Đặt

### 1. Clone Repository

```bash
git clone https://github.com/F12FLASH/CTF.git
cd CTF/17.One-Time-Pad Revenge
```

### 2. Cài Đặt Dependencies

```bash
npm install
```

### 3. Cấu Hình Biến Môi Trường (Tùy Chọn)

Tạo file `.env` trong thư mục gốc:

```env
# Port của server (mặc định: 5000)
PORT=5000

# Key mã hóa flag (tùy chọn, có giá trị mặc định)
FLAG_ENCRYPTION_KEY=your_secure_encryption_key_here

# Allowed origins cho CORS (tùy chọn)
ALLOWED_ORIGINS=https://your-domain.com
```

### 4. Chạy Ứng Dụng

#### Development Mode

```bash
npm run dev
```

Server sẽ chạy tại: `http://localhost:5000`

#### Production Build

```bash
npm run build
npm start
```

### 5. Mở Trình Duyệt

Truy cập `http://localhost:5000` để sử dụng ứng dụng.

---

## 📖 Hướng Dẫn Sử Dụng

### Bước 1: Tạo Dữ Liệu Thử Thách

1. Tìm card **"Tạo Dữ Liệu Thử Thách"**
2. Nhập số lượng ciphertext (khuyến nghị: 1000)
3. Nhấn **"Tạo Bản Mã"**
4. Đợi hệ thống tạo xong (có thể mất vài giây)

### Bước 2: Phân Tích Thống Kê

1. Mở section **"Phân Tích Thống Kê"**
2. Nhấn **"Chạy Phân Tích"**
3. Quan sát:
   - Tổng số bản mã
   - Độ dài key (bytes)
   - Entropy trung bình
   - Biểu đồ tần suất byte

### Bước 3: Phân Tích XOR

1. Trong section **"Phân Tích Cặp XOR"**:
2. Chọn hai chỉ số ciphertext (vd: 0 và 1)
3. Nhấn **"Phân Tích XOR"**
4. Xem XOR result và patterns phát hiện được

### Bước 4: Known Plaintext Attack

1. Biết rằng plaintext bắt đầu bằng `"This is the secret message"`
2. Hoặc biết flag format: `VNFLAG{`
3. Nhập prefix đã biết vào **"Tấn Công Văn Bản Rõ Đã Biết"**
4. Nhấn **"Thực Thi Tấn Công"**
5. Hệ thống sẽ khôi phục keystream với độ tin cậy

### Bước 5: Khôi Phục Flag

1. Từ keystream đã khôi phục, XOR với ciphertext để lấy plaintext
2. Plaintext chứa flag ở cuối
3. Nhập flag vào **"Xác Minh Flag"**
4. Nhận kết quả và chúc mừng nếu đúng!

---

## 🎓 Chi Tiết Thử Thách CTF

### Lý Thuyết

#### One-Time-Pad (OTP)

One-Time-Pad là phương pháp mã hóa **bất khả phá** nếu sử dụng đúng cách:

```
Ciphertext = Plaintext ⊕ Key
Plaintext = Ciphertext ⊕ Key
```

**Yêu cầu để an toàn:**
1. Key phải dài ít nhất bằng plaintext
2. Key phải ngẫu nhiên hoàn toàn
3. **Key CHỈ được sử dụng MỘT LẦN duy nhất**

#### Lỗ Hổng Tái Sử Dụng Key

Khi cùng một key được dùng cho nhiều plaintext:

```
C₁ = P₁ ⊕ K
C₂ = P₂ ⊕ K

C₁ ⊕ C₂ = (P₁ ⊕ K) ⊕ (P₂ ⊕ K) = P₁ ⊕ P₂
```

XOR hai ciphertext loại bỏ key, chỉ còn lại XOR của hai plaintext!

### Phương Pháp Tấn Công

#### 1. Statistical Analysis

Phân tích tần suất byte để:
- Xác định độ dài key
- Đánh giá entropy
- Phát hiện patterns

#### 2. XOR Analysis

XOR hai ciphertext để tìm:
- Patterns lặp lại
- Vị trí có thể chứa dữ liệu đặc biệt
- Byte có tần suất cao

#### 3. Known Plaintext Attack

Nếu biết một phần plaintext:

```
Known_Plaintext ⊕ Ciphertext = Keystream
```

Sau đó:

```
Keystream ⊕ Other_Ciphertext = Other_Plaintext
```

### Cấu Trúc Challenge

```
Plaintext: "This is the secret message encrypted with OTP using key derived from flag. VNFLAG{...}"
Key: SHA256(flag)
Ciphertext: Plaintext ⊕ Key
```

**Mục tiêu:** Khôi phục flag từ tập ciphertexts được tạo.

---

## 📡 API Documentation

### Base URL

```
http://localhost:5000/api
```

### Endpoints

#### POST `/api/encrypt`

Mã hóa plaintext bằng OTP.

**Request:**
```json
{
  "plaintext": "Hello World",
  "key": "optional_hex_key"
}
```

**Response:**
```json
{
  "ciphertext": "hex_string",
  "key": "hex_string",
  "keyHash": "sha256_hash"
}
```

#### POST `/api/ciphertexts/upload`

Tải lên ciphertext.

**Request:**
```json
{
  "data": "hex_ciphertext_string"
}
```

**Response:**
```json
{
  "id": "uuid",
  "data": "hex_string",
  "size": 256,
  "uploadedAt": "2025-01-15T10:00:00.000Z"
}
```

#### GET `/api/ciphertexts`

Lấy danh sách tất cả ciphertexts.

**Response:**
```json
[
  {
    "id": "uuid",
    "data": "hex_string",
    "size": 256,
    "uploadedAt": "2025-01-15T10:00:00.000Z"
  }
]
```

#### DELETE `/api/ciphertexts`

Xóa tất cả ciphertexts.

**Response:**
```json
{
  "message": "All ciphertexts cleared"
}
```

#### POST `/api/analysis/statistical`

Chạy phân tích thống kê.

**Response:**
```json
{
  "totalCiphertexts": 1000,
  "keyLength": 128,
  "entropy": 7.92,
  "byteFrequency": [...],
  "averageByteValue": 127.5
}
```

#### GET `/api/analysis/statistical`

Lấy kết quả phân tích thống kê.

#### POST `/api/analysis/xor`

Phân tích XOR hai ciphertext.

**Request:**
```json
{
  "index1": 0,
  "index2": 1
}
```

**Response:**
```json
{
  "pairIndex1": 0,
  "pairIndex2": 1,
  "xorResult": "hex_string",
  "patterns": [
    {
      "position": 10,
      "value": "20",
      "frequency": 15
    }
  ]
}
```

#### GET `/api/analysis/xor`

Lấy tất cả phân tích XOR.

#### POST `/api/attack/known-plaintext`

Thực hiện known plaintext attack.

**Request:**
```json
{
  "knownPrefix": "VNFLAG{"
}
```

**Response:**
```json
{
  "recoveredKeystream": "hex_string",
  "confidence": 100.0,
  "matchedCiphertexts": 1000,
  "recoveredPlaintext": "VNFLAG{..."
}
```

#### GET `/api/attack/keystream`

Lấy kết quả keystream recovery.

#### POST `/api/flag/verify`

Xác minh flag.

**Request:**
```json
{
  "flag": "VNFLAG{your_flag_here}"
}
```

**Response:**
```json
{
  "valid": true,
  "providedHash": "sha256_hash",
  "expectedHash": "sha256_hash",
  "message": "Congratulations! You've successfully solved..."
}
```

#### POST `/api/challenge/generate`

Tạo dữ liệu challenge.

**Request:**
```json
{
  "count": 1000
}
```

**Response:**
```json
{
  "message": "Successfully generated 1000 ciphertexts",
  "count": 1000,
  "keyHash": "sha256_of_key",
  "plaintextHint": "This is the secret message encrypted..."
}
```

#### GET `/api/ciphertexts/download`

Tải xuống tất cả ciphertexts dưới dạng text file.

---

## 🔒 Bảo Mật

### Các Tính Năng Bảo Mật Được Triển Khai

1. **Rate Limiting**
   - 100 requests/60s cho general API
   - 50 requests/60s cho mỗi endpoint cụ thể
   - Tracking theo IP address

2. **Input Validation**
   - Zod schema validation cho tất cả request
   - Hex string validation
   - Integer range validation
   - Input sanitization với giới hạn độ dài

3. **Security Headers**
   - `Strict-Transport-Security` (HSTS)
   - `Content-Security-Policy` (CSP)
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `X-XSS-Protection`
   - `Referrer-Policy: strict-origin-when-cross-origin`

4. **CORS Configuration**
   - Hỗ trợ ALLOWED_ORIGINS từ environment
   - Credential handling an toàn

5. **Flag Protection**
   - Flag được mã hóa bằng AES-256-CBC
   - Key được derive bằng scrypt
   - Không lưu trữ flag plaintext trong code

6. **Data Limits**
   - Tối đa 1000 ciphertexts
   - Ciphertext size tối đa 100KB
   - Plaintext size tối đa 50KB
   - Request body limit 1MB

### Best Practices

- ✅ Tất cả input được validate trước khi xử lý
- ✅ Error messages không lộ thông tin nhạy cảm
- ✅ Rate limiting để chống DoS
- ✅ HTTPS khuyến nghị trong production
- ✅ Environment variables cho sensitive data

### Lưu Ý Khi Deploy

1. **Đặt FLAG_ENCRYPTION_KEY mạnh:**
   ```bash
   FLAG_ENCRYPTION_KEY=$(openssl rand -hex 32)
   ```

2. **Cấu hình HTTPS:**
   - Sử dụng reverse proxy (Nginx, Apache)
   - Certificate từ Let's Encrypt

3. **Giới hạn CORS:**
   ```env
   ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
   ```

4. **Monitor và Logging:**
   - Theo dõi request rates
   - Log các failed attempts
   - Alert trên suspicious activities

---

## 🛠️ Công Nghệ Sử Dụng

### Frontend

- **React 18** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool & dev server
- **TanStack Query** - Server state management
- **Wouter** - Routing
- **shadcn/ui** - UI components
- **Radix UI** - Headless UI primitives
- **Tailwind CSS** - Styling
- **Framer Motion** - Animations
- **Recharts** - Data visualization

### Backend

- **Node.js** - Runtime
- **Express.js** - Web framework
- **TypeScript** - Type safety
- **Zod** - Schema validation
- **Node Crypto** - Cryptographic operations

### DevOps & Tools

- **tsx** - TypeScript execution
- **esbuild** - Bundling
- **Drizzle ORM** - Database ORM (ready for future use)

---

## 🤝 Đóng Góp

Chúng tôi hoan nghênh mọi đóng góp! Để đóng góp:

### Quy Trình

1. Fork repository
2. Tạo branch mới (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Mở Pull Request

### Coding Standards

- Sử dụng TypeScript
- Follow ESLint rules
- Viết tests cho features mới
- Update documentation
- Commit messages rõ ràng

### Báo Lỗi

Sử dụng GitHub Issues với template:

```markdown
**Mô tả lỗi:**
[Mô tả chi tiết]

**Các bước tái hiện:**
1. Làm gì...
2. Click vào đâu...
3. Xem lỗi...

**Kết quả mong đợi:**
[Điều bạn mong đợi xảy ra]

**Screenshots:**
[Nếu có]

**Môi trường:**
- OS: [e.g. Windows 11]
- Browser: [e.g. Chrome 120]
- Node version: [e.g. 20.10.0]
```

---

## 📄 Giấy Phép

Dự án được phát hành dưới giấy phép **MIT License**.

```
MIT License

Copyright (c) 2025 One-Time-Pad Revenge Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Lời Cảm Ơn

- Cảm ơn cộng đồng CTF Việt Nam
- Cảm ơn các contributors
- Cảm ơn các thư viện open-source được sử dụng

---

## 📞 Liên Hệ & Hỗ Trợ

- **Issues:** [GitHub Issues](https://github.com/F12FLASH/CTF/issues)
- **Email:** loideveloper.37@gmail.com

---

<div align="center">

**Được xây dựng với ❤️ cho cộng đồng học tập mật mã học Việt Nam**

⭐ Nếu dự án hữu ích, hãy cho chúng tôi một star!

</div>
