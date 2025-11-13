# 🚀 SSRF đến Sao Hỏa - Thử thách CTF Bảo mật Web

<div align="center">

![Độ khó](https://img.shields.io/badge/Độ_khó-⭐⭐⭐⭐⭐-red?style=for-the-badge)
![Điểm](https://img.shields.io/badge/Điểm-500-orange?style=for-the-badge)
![Loại](https://img.shields.io/badge/Loại-Web_Security-blue?style=for-the-badge)
![Lỗ hổng](https://img.shields.io/badge/Lỗ_hổng-SSRF-critical?style=for-the-badge)

**Một ứng dụng web thử thách CTF tương tác tập trung vào việc dạy và minh họa lỗ hổng Server-Side Request Forgery (SSRF) cùng các kỹ thuật vượt qua bảo mật.**

[Bắt đầu](#-cài-đặt) •
[Mục tiêu](#-mục-tiêu) •
[Kỹ thuật](#-kỹ-thuật-vượt-qua) •
[Bảo mật](#-tính-năng-bảo-mật)

</div>

---

## 🎯 Giới thiệu

**SSRF đến Sao Hỏa** là một thử thách CTF cấp độ chuyên gia được thiết kế để giáo dục người dùng về lỗ hổng Server-Side Request Forgery (SSRF) thông qua trải nghiệm thực hành tương tác. Ứng dụng mô phỏng một tình huống thực tế nơi hệ thống lọc URL được triển khai nhưng có thể bị vượt qua bằng các kỹ thuật khác nhau.

### 🌟 Điểm nổi bật

- ✅ Giao diện người dùng đẹp mắt với chủ đề Sao Hỏa
- ✅ Phản hồi và xác thực theo thời gian thực
- ✅ Nhiều kỹ thuật vượt qua để khám phá
- ✅ Môi trường học tập an toàn và được kiểm soát
- ✅ Hướng dẫn và gợi ý tiến trình
- ✅ Payload mẫu để bắt đầu nhanh

---

## 🎯 Mục tiêu

Mục tiêu chính của thử thách này là:

1. **Vượt qua** hệ thống lọc tên miền được triển khai
2. **Truy cập** endpoint được bảo vệ tại `http://localhost:1337`
3. **Lấy được** cờ (flag) từ máy chủ flag

### 🏆 Tiêu chí Thành công

Thử thách được coi là hoàn thành khi bạn thành công lấy được flag có định dạng:

```
VNFLAG{...}
```

---

## ✨ Tính năng

### Cho Người dùng

- **🎨 Giao diện Tương tác**: UI hiện đại với chủ đề Sao Hỏa và hiệu ứng terminal
- **⚡ Xác thực Thời gian thực**: Phản hồi tức thời về tính hợp lệ của URL
- **📊 Hiển thị Chi tiết**: Xem phản hồi HTTP hoàn chỉnh, headers và thời gian
- **💡 Hướng dẫn Tiến trình**: Gợi ý và payload mẫu để giúp bạn học
- **📈 Theo dõi Tiến độ**: Lịch sử các lần thử SSRF của bạn

### Cho Nhà phát triển

- **🔒 Bảo mật Mạnh mẽ**: Rate limiting, input sanitization, security headers
- **🛡️ Phân tách Client/Server**: Kiến trúc bảo mật rõ ràng
- **📝 TypeScript**: Type safety hoàn toàn trên cả client và server
- **🎯 Validation Schema**: Schema validation dùng chung với Zod
- **🔧 Hot Reload**: Môi trường development nhanh chóng với Vite

---

## 🛠️ Công nghệ Sử dụng

### Frontend

- **React 18** - Thư viện UI
- **TypeScript** - Type safety
- **Vite** - Build tool và dev server
- **TanStack Query** - Quản lý server state
- **Wouter** - Lightweight routing
- **Tailwind CSS** - Utility-first styling
- **shadcn/ui** - Component library
- **Radix UI** - Accessible primitives

### Backend

- **Node.js** - JavaScript runtime
- **Express** - Web framework
- **TypeScript** - Type safety
- **Zod** - Schema validation
- **Custom Security Middleware** - Rate limiting, headers, sanitization

### Tools & Infrastructure

- **ESBuild** - Bundling
- **PostCSS** - CSS processing
- **Drizzle ORM** - Database toolkit (tùy chọn)

---

## 📦 Cài đặt

### Yêu cầu

- **Node.js** 18.x hoặc cao hơn
- **npm** 8.x hoặc cao hơn

### Các bước Cài đặt

1. **Clone repository**

```bash
git clone https://github.com/F12FLASH/CTF.git
cd CTF/11.SSRF to Mars
```

2. **Cài đặt dependencies**

```bash
npm install
```

3. **Khởi động development server**

```bash
npm run dev
```

4. **Mở trình duyệt**

Truy cập `http://localhost:5000` để bắt đầu thử thách!

### Scripts Có sẵn

```bash
npm run dev      # Khởi động development server
npm run build    # Build production
npm start        # Chạy production server
npm run check    # Type checking với TypeScript
```

---

## 🎮 Sử dụng

### Bước 1: Khám phá Giao diện

- Đọc mô tả thử thách và hiểu mục tiêu
- Xem qua các tab **Tổng quan**, **Kỹ thuật**, **Mục tiêu**, và **Gợi ý**
- Làm quen với các payload mẫu được cung cấp

### Bước 2: Thử nghiệm

1. Nhập URL vào **Trình Fetch URL**
2. Nhấn nút **FETCH** để gửi request
3. Xem kết quả trong panel **Phản hồi**
4. Phân tích tại sao URL bị chặn hoặc được phép

### Bước 3: Khai thác

- Thử các kỹ thuật vượt qua khác nhau
- Sử dụng payload mẫu như điểm khởi đầu
- Thử nghiệm với các biểu diễn IP khác nhau
- Sử dụng thủ thuật DNS và IPv6
- Giám sát phản hồi để điều chỉnh chiến lược

### Bước 4: Lấy Flag

Khi vượt qua thành công bộ lọc:

1. Fetch `http://localhost:1337/flag`
2. Sao chép flag từ phản hồi
3. Submit và hoàn thành thử thách!

---

## 🛡️ Cơ chế Bảo vệ

Ứng dụng triển khai các cơ chế bảo vệ mạnh mẽ (cố ý để lại một số lỗ hổng cho mục đích giáo dục):

### 1. User-Agent Authentication

- Flag server chỉ chấp nhận requests từ challenge server
- Kiểm tra User-Agent header: `SSRF-to-Mars-CTF/1.0`
- Từ chối tất cả requests trực tiếp từ browser/curl
- **Mục đích**: Ngăn chặn direct access, buộc phải bypass SSRF filter

### 2. Lọc Localhost & Loopback

Các biểu diễn localhost bị chặn:

```
- localhost (keyword)
- 127.0.0.1
- 127.0.0.0/8 (toàn bộ dải)
- 0.0.0.0
- ::1 (IPv6 loopback)
- ::ffff:127.0.0.1 (IPv4-mapped IPv6)
```

### 3. Lọc DNS Tricks

Các domain tricks phổ biến bị chặn:

```
- localtest.me
- lvh.me
- nip.io
- xip.io
- sslip.io
- *.local domains
```

### 4. Lọc IP Encoding

Các biểu diễn IP thay thế bị chặn:

```
- Decimal: 2130706433 (và toàn bộ dải 127.0.0.0/8)
- Hexadecimal: 0x7f000001, 0x7f.0x0.0x0.0x1
- Octal: 0177.0.0.1, 017700000001
- URL encoding: %xx trong hostname
```

### 5. Lọc Private IP Ranges

Chặn tất cả dải IP private:

```
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16
```

### 6. Chặn Redirect

- `redirect: 'manual'` - Không tự động follow redirects
- **Mục đích**: Ngăn chặn open redirect bypass technique

### 7. Validation & Sanitization

- Phân tích URL nghiêm ngặt
- Loại bỏ ký tự đặc biệt: @, \, URL encoding
- Giới hạn độ dài: 2048 ký tự

---

## 🎯 Kỹ thuật Vượt qua

⚠️ **Lưu ý**: Bộ lọc đã được nâng cấp mạnh mẽ! Nhiều kỹ thuật phổ biến đã bị chặn.

### ❌ Kỹ thuật BỊ CHẶN

Các techniques sau **KHÔNG còn hoạt động**:

```
✗ http://[::1]:1337/                    # IPv6 loopback - BỊ CHẶN
✗ http://2130706433:1337/               # Decimal IP - BỊ CHẶN
✗ http://0x7f000001:1337/               # Hex IP - BỊ CHẶN
✗ http://0177.0.0.1:1337/               # Octal IP - BỊ CHẶN
✗ http://127.1:1337/                    # Shortened - BỊ CHẶN
✗ http://localtest.me:1337/             # DNS tricks - BỊ CHẶN
✗ http://lvh.me:1337/                   # DNS tricks - BỊ CHẶN
✗ http://[::ffff:127.0.0.1]:1337/       # IPv4-mapped IPv6 - BỊ CHẶN
✗ http://external.com → 302 → localhost # Redirect - BỊ CHẶN
```

### ✅ Kỹ thuật CÓ THỂ HOẠT ĐỘNG

Thử thách này yêu cầu các kỹ thuật **nâng cao hơn**:

### 1. IPv6 Variations (⭐⭐⭐⭐⭐)

Thử các biểu diễn IPv6 khác chưa bị chặn:

```
http://[::ffff:7f00:1]:1337/flag
http://[0:0:0:0:0:ffff:7f00:1]:1337/flag
```

**Gợi ý**: IPv4-mapped IPv6 có nhiều cách biểu diễn khác nhau.

### 2. DNS Rebinding (⭐⭐⭐⭐⭐)

Kỹ thuật nâng cao sử dụng TOCTOU (Time-Of-Check Time-Of-Use):

- Thiết lập DNS server riêng với TTL thấp
- Lần đầu resolve về IP hợp lệ (pass filter)
- Lần thứ 2 resolve về 127.0.0.1 (khi fetch thực sự)

**Yêu cầu**: Kiểm soát DNS records hoặc dịch vụ rebinding.

### 3. Protocol Tricks (⭐⭐⭐⭐⭐)

Khai thác các đặc điểm của protocol parsing:

```
# Thử các variations khác của URL parsing
# Research: URL parser quirks, WHATWG URL Standard
```

### 4. Creative Solutions (⭐⭐⭐⭐⭐)

Tìm các cách bypass chưa được liệt kê:

- Nghiên cứu cách Node.js parse URL
- Thử các edge cases của URL specification
- Khai thác sự khác biệt giữa filter và actual fetch

**💡 Hint**: Filter là lexical (kiểm tra chuỗi), không resolve DNS. Có cách nào để lợi dụng điều này không?

---

## 🔐 Tính năng Bảo mật

Mặc dù đây là thử thách CTF, ứng dụng vẫn triển khai các biện pháp bảo mật thực tế:

### Rate Limiting

- **Giới hạn**: 20 requests mỗi 60 giây
- **Scope**: Mỗi địa chỉ IP
- **Response**: HTTP 429 khi vượt quá giới hạn

### Security Headers

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: [Chính sách hạn chế]
```

### Input Sanitization

- Loại bỏ ký tự điều khiển
- Giới hạn độ dài input (2048 ký tự)
- Trim whitespace
- Type validation với Zod

### Request Safety

- Timeout: 5 giây cho mỗi fetch request
- Size limit: 1MB cho request body
- AbortController để hủy requests
- Redirect: Manual (không auto-follow redirects)

### Client-side Security

- React tự động escape output (XSS protection)
- Không sử dụng dangerouslySetInnerHTML
- Syntax highlighting an toàn với preserved escaping

---

### Luồng Dữ liệu

```
User Input → Client Validation → API Request → Rate Limiting 
→ Input Sanitization → SSRF Filter → URL Fetch → Response
```

### Endpoints

#### POST /api/fetch

Endpoint chính để thử SSRF payloads.

**Request:**
```json
{
  "url": "http://example.com"
}
```

**Response:**
```json
{
  "success": true,
  "status": "success",
  "message": "Request successful!",
  "response": "...",
  "statusCode": 200,
  "headers": {...},
  "timing": 123
}
```

#### GET /api/attempts

Lấy lịch sử các lần thử SSRF (dùng cho debug).

---

## 🎓 Mục đích Giáo dục

Thử thách này được thiết kế để dạy:

### Khái niệm Bảo mật

- **SSRF Vulnerabilities**: Hiểu cách và tại sao SSRF xảy ra
- **Filter Bypass**: Học các kỹ thuật vượt qua các biện pháp bảo vệ không đầy đủ
- **Network Protocols**: Hiểu sâu về IPv4, IPv6, DNS
- **Defense in Depth**: Tầm quan trọng của bảo vệ nhiều lớp

### Kỹ năng Thực hành

- **Penetration Testing**: Phương pháp tiếp cận có hệ thống để khai thác
- **Protocol Knowledge**: IPv4, IPv6, DNS resolution
- **Creative Problem Solving**: Tìm cách vượt qua hạn chế
- **Tool Usage**: Sử dụng công cụ web developer hiệu quả

### Secure Coding

- **Proper Input Validation**: Cách validate input đúng cách
- **Allowlist vs Blocklist**: Hiểu ưu/nhược điểm của mỗi approach
- **Defense Mechanisms**: Triển khai bảo vệ hiệu quả
- **Security Headers**: Tầm quan trọng của HTTP security headers

---

## 🤝 Đóng góp

Đóng góp luôn được chào đón! Nếu bạn muốn cải thiện thử thách này:

1. Fork repository
2. Tạo feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit thay đổi (`git commit -m 'Add some AmazingFeature'`)
4. Push lên branch (`git push origin feature/AmazingFeature`)
5. Mở Pull Request

### Ý tưởng Đóng góp

- Thêm kỹ thuật vượt qua mới
- Cải thiện UI/UX
- Thêm nhiều hints
- Tối ưu hóa performance
- Sửa bugs
- Cải thiện tài liệu

---

## 📝 Ghi chú Quan trọng

⚠️ **Lưu ý**: Ứng dụng này được thiết kế cho mục đích giáo dục. Các lỗ hổng được triển khai là **CỐ Ý** để minh họa lỗ hổng SSRF. **KHÔNG** triển khai code này trong môi trường production!

### Tuyên bố Trách nhiệm

- Thử thách này chỉ dành cho mục đích học tập
- Luôn lấy permission trước khi test bảo mật
- Sử dụng kiến thức có trách nhiệm và đạo đức
- Tác giả không chịu trách nhiệm cho việc lạm dụng

---

## 📜 Giấy phép

Dự án này được cấp phép theo giấy phép MIT - xem file LICENSE để biết chi tiết.

---

## 🙏 Cảm ơn

- Cộng đồng bảo mật - Vì đã chia sẻ kiến thức và kỹ thuật

---

## 📞 Liên hệ & Hỗ trợ

Nếu bạn có câu hỏi hoặc cần hỗ trợ: loideveloper.37@gmail.com


---

<div align="center">

**Chúc may mắn với thử thách! 🚀🔴**

Made with ❤️ for the cybersecurity community

</div>
