# 🎯 The Mimic - CTF Reverse Engineering Challenge

<div align="center">

![Difficulty](https://img.shields.io/badge/Difficulty-Master%20Hacker-red?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Reverse%20Engineering-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Hardened-green?style=for-the-badge)

*Một thử thách CTF về reverse engineering, mã hóa XOR và kỹ thuật hooking*

</div>

## 🎮 Giới Thiệu

**The Mimic** là một thử thách CTF (Capture The Flag) nâng cao tập trung vào reverse engineering và mã hóa. Thử thách mô phỏng một chương trình nhị phân tự dịch sang WebAssembly (WASM) với cơ chế mã hóa flag sử dụng XOR và key rotation động.

### Mục Tiêu

Người chơi phải:
1. Hiểu cách hoạt động của mã hóa XOR với key rotation
2. Hook hàm `time()` để đóng băng việc thay đổi key
3. Capture encryption key khi đã đóng băng
4. Giải mã flag và submit để hoàn thành thử thách

## ✨ Tính Năng

### Tính Năng Chính

- **🔐 Mã Hóa XOR Nâng Cao**: Flag được mã hóa bằng XOR với key xoay vòng mỗi 10ms
- **⏰ Time Hooking**: Mô phỏng kỹ thuật hooking hàm `time()` để freeze key rotation
- **🖥️ WASM Sandbox Simulator**: Mô phỏng quá trình biên dịch và thực thi WASM
- **💡 Hệ Thống Gợi Ý**: 4 gợi ý được sắp xếp theo thứ tự độ khó
- **📊 Thống Kê Thời Gian Thực**: Theo dõi rotation count, hook status, và submission attempts

### Tính Năng Bảo Mật

- **🛡️ AES-256-GCM Encryption**: Flag được mã hóa mạnh mẽ với AES-256-GCM
- **🔒 SHA-256 Hashing**: Verification sử dụng hash thay vì so sánh plaintext
- **⚡ Rate Limiting**: Giới hạn request để chống brute force
- **🔍 Input Sanitization**: Validate và sanitize tất cả user input
- **📝 Security Headers**: Đầy đủ security headers (X-Frame-Options, CSP, etc.)
- **🎯 Session Isolation**: Mỗi session có state riêng biệt

## 🚀 Cài Đặt

### Yêu Cầu Hệ Thống

- Node.js >= 18.x
- npm >= 9.x

### Cài Đặt Dependencies

\`\`\`bash
git clone https://github.com/F12FLASH/CTF.git
cd CTF/6.The Mimic
npm install
\`\`\`

### Chạy Ứng Dụng

**Development Mode:**
\`\`\`bash
npm run dev
\`\`\`

**Production Mode:**
\`\`\`bash
npm run build
npm start
\`\`\`

Ứng dụng sẽ chạy tại: `http://localhost:5000`

### Environment Variables (Tùy Chọn)

Tạo file `.env` để cấu hình:

\`\`\`env
# Port (mặc định: 5000)
PORT=5000

# Flag Encryption Key (khuyến nghị thay đổi trong production)
FLAG_ENCRYPTION_KEY=your_secure_master_key_here
\`\`\`

## 📖 Cách Sử Dụng

### Bước 1: Bắt Đầu Thử Thách

1. Mở trình duyệt và truy cập `http://localhost:5000`
2. Click nút **"Begin Challenge"**
3. Hệ thống sẽ:
   - Khởi tạo WASM sandbox
   - Bắt đầu mã hóa flag với key rotation
   - Hiển thị encrypted flag

### Bước 2: Quan Sát Hệ Thống

- **WASM Sandbox**: Xem quá trình compilation và execution logs
- **Encryption Monitor**: Theo dõi encrypted flag và rotation count
- **Time Hook Interface**: Kiểm soát time hooking

### Bước 3: Hook Time

1. Click nút **"Hook time()"**
2. Hệ thống sẽ freeze key rotation
3. Encryption key sẽ được hiển thị
4. Rotation count ngừng tăng

### Bước 4: Giải Mã Flag

1. Copy encrypted flag từ Encryption Monitor
2. Copy encryption key đã capture được
3. Sử dụng XOR để decrypt (có thể dùng endpoint `/api/verify-decryption`)
4. Submit flag với format `VNFLAG{...}`

### Bước 5: Submit Flag

1. Nhập flag đã giải mã vào ô input
2. Click **"Submit Flag"**
3. Nếu đúng, bạn sẽ nhận được thông báo thành công và flag chính thức


### API Endpoints

| Endpoint | Method | Mô Tả |
|----------|--------|-------|
| `/api/start-challenge` | POST | Khởi tạo challenge mới |
| `/api/challenge-data` | GET | Lấy encrypted flag và state |
| `/api/hook-time` | POST | Hook/unhook time() function |
| `/api/get-frozen-key` | GET | Lấy frozen encryption key |
| `/api/submit-flag` | POST | Submit flag để kiểm tra |
| `/api/verify-decryption` | POST | Verify XOR decryption |
| `/api/hints` | GET | Lấy danh sách hints |
| `/api/hints/:id/reveal` | POST | Reveal một hint |
| `/api/stats` | GET | Lấy thống kê |
| `/api/health` | GET | Health check |

## 🔒 Bảo Mật

### Cơ Chế Bảo Mật Đã Triển Khai

#### 1. **Flag Encryption (AES-256-GCM)**
- Flag được **pre-encrypted offline** bằng AES-256-GCM
- **Chỉ lưu ciphertext** trong source code - không có plaintext flag
- Master key được derive từ environment variable hoặc default key
- Sử dụng authenticated encryption (GCM mode) để đảm bảo integrity
- IV và authentication tag được lưu cùng ciphertext

#### 2. **Hash-Based Verification (SHA-256)**
- Flag không bao giờ được so sánh trực tiếp dưới dạng plaintext
- Sử dụng SHA-256 hash để verify
- Chống timing attacks

#### 3. **Rate Limiting**
- Submit flag: 10 requests/phút
- General endpoints: 100 requests/phút
- Auto cleanup expired entries

#### 4. **Input Validation & Sanitization**
- Zod schema validation cho tất cả inputs
- Maximum length limits
- Regex validation cho IDs
- HTML/SQL injection prevention

#### 5. **Security Headers**
\`\`\`javascript
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
\`\`\`

#### 6. **Session Isolation**
- Mỗi IP có challenge state riêng
- Key rotation độc lập cho mỗi session
- Cleanup khi process terminate

### Best Practices

✅ **Đã Làm:**
- Encrypted flag storage
- Rate limiting
- Input sanitization
- Security headers
- Hash-based verification
- Session isolation

⚠️ **Khuyến Nghị Production:**
- Sử dụng HTTPS
- Thay đổi `FLAG_ENCRYPTION_KEY` trong environment
- Re-encrypt flag với production key
- Deploy với PostgreSQL thay vì in-memory storage
- Thêm CORS configuration
- Implement proper authentication nếu cần
- Rotate keys định kỳ

🔐 **Cách Pre-Encrypt Flag Mới:**
\`\`\`javascript
// Chạy script này offline để encrypt flag mới
const crypto = require('crypto');
const flag = 'YOUR_NEW_FLAG_HERE';
const masterKey = crypto.createHash('sha256')
  .update(process.env.FLAG_ENCRYPTION_KEY || 'default')
  .digest();
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
let encrypted = cipher.update(flag, 'utf8', 'hex');
encrypted += cipher.final('hex');
const tag = cipher.getAuthTag();
console.log(JSON.stringify({
  iv: iv.toString('hex'),
  encrypted,
  tag: tag.toString('hex')
}));
\`\`\`

## 🎓 Hướng Dẫn Giải Chi Tiết

### Phương Pháp 1: Sử Dụng UI (Dễ - Khuyến Nghị Cho Beginners)

#### Bước 1: Khởi Động Challenge
\`\`\`
1. Click "Begin Challenge"
2. Đợi WASM compilation hoàn thành (100%)
3. Quan sát encrypted flag và rotation count
\`\`\`

#### Bước 2: Hook Time Function
\`\`\`
1. Click nút "Hook time()"
2. Chờ message "TIME HOOK DETECTED!"
3. Xem key được capture: VD: "a1b2c3d4e5f6..."
4. Copy encryption key này
\`\`\`

#### Bước 3: Giải Mã Flag
\`\`\`javascript
// Sử dụng endpoint verify-decryption
POST /api/verify-decryption
{
  "encryptedFlag": "<encrypted_flag_from_monitor>",
  "key": "<frozen_key_from_hook>"
}

// Response sẽ trả về flag đã decrypt
\`\`\`

#### Bước 4: Submit
\`\`\`
1. Copy flag từ response (format: VNFLAG{...})
2. Paste vào ô "Submit Flag"
3. Click "Submit Flag"
4. Nhận thông báo thành công!
\`\`\`

### Phương Pháp 2: Manual XOR Decryption (Trung Bình)

#### Hiểu Về XOR Encryption

XOR (exclusive OR) là một phép toán bit với tính chất:
\`\`\`
A XOR B = C
C XOR B = A  (symmetric property)
\`\`\`

Vì vậy, để decrypt:
\`\`\`
encrypted_flag XOR key = original_flag
\`\`\`

#### Python Script Để Decrypt

\`\`\`python
import base64

def xor_decrypt(encrypted_b64, key):
    # Decode base64
    encrypted = base64.b64decode(encrypted_b64)
    
    # XOR từng byte
    result = ""
    for i in range(len(encrypted)):
        char_code = encrypted[i] ^ ord(key[i % len(key)])
        result += chr(char_code)
    
    return result

# Sử dụng
encrypted_flag = "YOUR_ENCRYPTED_FLAG_HERE"  # Từ /api/challenge-data
key = "YOUR_FROZEN_KEY_HERE"  # Từ /api/get-frozen-key

flag = xor_decrypt(encrypted_flag, key)
print(f"Flag: {flag}")
\`\`\`

#### JavaScript/Node.js Script

\`\`\`javascript
function xorDecrypt(encryptedB64, key) {
  const encrypted = Buffer.from(encryptedB64, 'base64');
  let result = '';
  
  for (let i = 0; i < encrypted.length; i++) {
    const charCode = encrypted[i] ^ key.charCodeAt(i % key.length);
    result += String.fromCharCode(charCode);
  }
  
  return result;
}

// Sử dụng
const encryptedFlag = "YOUR_ENCRYPTED_FLAG_HERE";
const key = "YOUR_FROZEN_KEY_HERE";

const flag = xorDecrypt(encryptedFlag, key);
console.log("Flag:", flag);
\`\`\`

### Phương Pháp 3: Advanced - Direct API Interaction (Khó)

#### Sử dụng curl/Postman

\`\`\`bash
# 1. Start challenge
curl -X POST http://localhost:5000/api/start-challenge \\
  -H "Content-Type: application/json"

# 2. Hook time
curl -X POST http://localhost:5000/api/hook-time \\
  -H "Content-Type: application/json" \\
  -d '{"hook": true}'

# 3. Get frozen key
curl http://localhost:5000/api/get-frozen-key

# 4. Get encrypted flag
curl http://localhost:5000/api/challenge-data

# 5. Verify decryption
curl -X POST http://localhost:5000/api/verify-decryption \\
  -H "Content-Type: application/json" \\
  -d '{"encryptedFlag": "BASE64_ENCRYPTED", "key": "FROZEN_KEY"}'

# 6. Submit flag
curl -X POST http://localhost:5000/api/submit-flag \\
  -H "Content-Type: application/json" \\
  -d '{"submittedFlag": "VNFLAG{...}"}'
\`\`\`

### Phương Pháp 4: Expert - Reverse Engineering (Chuyên Gia)

#### Phân Tích Source Code

1. **Đọc `/server/routes.ts`**: Hiểu logic backend
2. **Tìm encryption algorithm**: XOR với key rotation
3. **Phát hiện vulnerability**: Time hooking mechanism
4. **Exploit**: Hook time để freeze key

#### Debugging với Browser DevTools

\`\`\`javascript
// Mở Console trong DevTools
// Monitor API calls
const originalFetch = window.fetch;
window.fetch = function(...args) {
  console.log('API Call:', args);
  return originalFetch.apply(this, args);
};
\`\`\`

## 🛠️ Kỹ Thuật Sử Dụng

### 1. XOR Encryption/Decryption

**Tại sao XOR?**
- Symmetric: Encrypt và decrypt dùng cùng key
- Nhanh: Phép toán bit rất efficient
- Educational: Dễ hiểu cho CTF

**Weaknesses:**
- Dễ bị crack nếu biết plaintext
- Key reuse tạo ra vulnerabilities
- Cần key distribution an toàn

### 2. Time Hooking

**Khái Niệm:**
Hooking là kỹ thuật chặn và thay đổi hành vi của system calls/functions

**Trong Challenge:**
- Hàm `time()` thường trả về Unix timestamp hiện tại
- Khi hook, ta "freeze" nó về một giá trị cố định
- Key generation phụ thuộc time → freeze time = freeze key

**Real-World Application:**
- Anti-debugging techniques
- Malware analysis
- Game hacking
- DRM bypass

### 3. Key Rotation

**Tại Sao Rotation:**
- Tăng security bằng cách thay đổi key thường xuyên
- Giảm window of exposure nếu key bị compromise
- Chống replay attacks

**Trong Challenge:**
- Key thay đổi mỗi 10ms (100 lần/giây)
- Tạo time pressure cho attacker
- Yêu cầu hooking để capture stable key

### 4. WASM (WebAssembly)

**Mô Phỏng Trong Challenge:**
- Binary → WASM translation
- Sandbox execution
- Reverse engineering workflow

**Real CTF Application:**
- WASM binary analysis
- Decompilation challenges
- Browser exploit development

## 📊 Thống Kê & Monitoring

### Xem Thống Kê

\`\`\`bash
curl http://localhost:5000/api/stats
\`\`\`

**Response:**
\`\`\`json
{
  "totalAttempts": 42,
  "solves": 5,
  "successRate": 11.9
}
\`\`\`

### Health Check

\`\`\`bash
curl http://localhost:5000/api/health
\`\`\`

## 🐛 Troubleshooting

### Lỗi Thường Gặp

**1. "Time must be hooked to access the frozen key"**
- **Nguyên nhân**: Chưa hook time
- **Giải pháp**: Click nút "Hook time()" trước

**2. "Too many requests"**
- **Nguyên nhân**: Rate limiting
- **Giải pháp**: Đợi 1 phút rồi thử lại

**3. Flag không decrypt đúng**
- **Nguyên nhân**: Key bị thay đổi (chưa hook time)
- **Giải pháp**: Hook time trước khi lấy key

**4. "Invalid submission format"**
- **Nguyên nhân**: Thiếu header Content-Type
- **Giải pháp**: Thêm `-H "Content-Type: application/json"`

## 🎯 Flag Format

\`\`\`
VNFLAG{...}
\`\`\`

- Prefix: `VNFLAG{`
- Content: Vietnamese pride message + random suffix
- Suffix: `}`

## 🤝 Đóng Góp

Contributions are welcome! Để đóng góp:

1. Fork repository
2. Tạo feature branch
3. Commit changes
4. Push và tạo Pull Request

## 📜 License

MIT License - xem file LICENSE để biết thêm chi tiết

## 🌟 Credits

- **Design**: Material Design + Terminal/Hacker aesthetics
- **Fonts**: Inter, JetBrains Mono, Orbitron (Google Fonts)
- **UI Framework**: shadcn/ui (Radix UI primitives)
- **Security**: AES-256-GCM, SHA-256, Rate Limiting

## 📞 Support
- Mở Issue trên GitHub
- Email: loideveloper.37@gmail.com

---

<div align="center">

**🎊 Chúc Bạn Thành Công Với Thử Thách! 🎊**

Made with ❤️ for the Vietnamese CTF Community

</div>
