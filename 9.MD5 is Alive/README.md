# MD5 vẫn Tồn tại - Thử thách Mật mã CTF

[![Bảo mật](https://img.shields.io/badge/bảo_mật-tăng_cường-xanh.svg)](https://github.com)
[![Giấy phép](https://img.shields.io/badge/giấy_phép-MIT-xanh.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-xanh.svg)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18.3-61dafb.svg)](https://react.dev/)

Một thử thách mật mã CTF giáo dục minh họa các lỗ hổng băm MD5 thông qua nền tảng web tương tác. Tìm hiểu về phân tích mật mã MD5, tấn công mở rộng độ dài và khai thác va chạm băm trong môi trường thực hành.

![Cấp độ Thử thách: Master Hacker](https://img.shields.io/badge/Cấp_độ-Master%20Hacker-đỏ.svg)
![Danh mục: Mật mã học](https://img.shields.io/badge/Danh_mục-Mật_mã_học-tím.svg)

## Tổng quan Thử thách

**MD5 vẫn Tồn tại** dạy các khái niệm bảo mật mật mã quan trọng bằng cách khai thác các điểm yếu cố hữu của MD5:

- **Lỗ hổng**: Tấn công Mở rộng Độ dài MD5 & Tấn công Va chạm
- **Định dạng**: `MD5(FLAG + "||" + user_input)`
- **Xác thực**: Chỉ so sánh 4 byte đầu tiên (8 ký tự hex)
- **Độ dài Flag**: 64 byte
- **Truy cập Oracle**: Có sẵn truy vấn băm không giới hạn

### Cách thức Hoạt động

1. Gửi bất kỳ đầu vào nào đến oracle MD5
2. Máy chủ tính toán `MD5(FLAG + "||" + your_input)`
3. Nhận toàn bộ băm, nhưng chỉ 4 byte được xác thực
4. Khai thác lỗ hổng để khôi phục flag

### Mục tiêu Học tập

- Hiểu cấu trúc nội bộ MD5 và cấu trúc Merkle-Damgård
- Thực hiện tấn công mở rộng độ dài
- Khai thác lỗ hổng so sánh băm một phần
- Tối ưu hóa tấn công sinh nhật để tìm va chạm
- Kỹ thuật phân tích mật mã thực tế

## Bắt đầu Nhanh

### Yêu cầu

- **Node.js** 18+ và npm
- Trình duyệt web hiện đại (Chrome, Firefox, Safari, Edge)

### Cài đặt

```bash
# Clone repository
git clone https://github.com/F12FLASH/CTF.git
cd CTF/9.MD5 is Alive

# Cài đặt dependencies
npm install

# Thiết lập biến môi trường (tùy chọn)
cp .env.example .env
# Chỉnh sửa .env và đặt giá trị FLAG của bạn

# Khởi động máy chủ phát triển
npm run dev
```

Ứng dụng sẽ có sẵn tại `http://localhost:5000`

## Kiến trúc

### Công nghệ Sử dụng

#### Frontend
- **React 18** với TypeScript
- **Vite** để phát triển và xây dựng nhanh
- **TanStack Query** để quản lý trạng thái máy chủ
- **Shadcn/ui** cho components UI hiện đại
- **Tailwind CSS** cho kiểu dáng responsive
- **Wouter** cho định tuyến phía client

#### Backend
- **Express.js** với TypeScript
- **Module crypto Node.js** để băm MD5
- **Zod** để xác thực schema
- **Helmet** cho security headers
- **express-rate-limit** để bảo vệ API
- **CORS** để chia sẻ tài nguyên chéo nguồn


## Tính năng Bảo mật

### Bảo mật Tối đa: Hệ thống Flag Mã hóa

Ứng dụng này triển khai **mã hóa cấp độ quân sự** để bảo vệ FLAG:

- **Mã hóa AES-256-GCM**: Mã hóa xác thực với Galois/Counter Mode
- **Dẫn xuất Khóa Scrypt**: Dẫn xuất khóa an toàn từ mật khẩu
- **Làm rối Đa lớp**: Làm rối XOR bổ sung cho bảo vệ sâu
- **So sánh Thời gian Cố định**: Ngăn chặn tấn công thời gian trong xác thực flag
- **Giải mã Thời gian Chạy**: Flag được mã hóa khi lưu trữ, chỉ giải mã trong bộ nhớ

#### Thiết lập Nhanh

```bash
# Tạo khóa mã hóa
tsx scripts/encrypt-flag.ts --generate-key

# Mã hóa flag của bạn
tsx scripts/encrypt-flag.ts "FLAG_CỦA_BẠN" "KHÓA_MÃ_HÓA_CỦA_BẠN"

# Thêm vào .env
ENCRYPTION_KEY=<khóa-hex-64-ký-tự-của-bạn>
ENCRYPTED_FLAG=<đầu-ra-đã-mã-hóa>
```

Xem [SECURITY.md](SECURITY.md) để biết tài liệu mã hóa đầy đủ.

### Các Lớp Bảo mật Bổ sung

- **Giới hạn Tốc độ**:
  - 30 truy vấn băm mỗi phút (cụ thể cho /api/hash)
  - 10 lần thử flag mỗi 5 phút (cụ thể cho /api/validate-flag)
  - 100 yêu cầu mỗi 15 phút mỗi IP (dự phòng API chung)

- **Bảo vệ CORS**: Nguồn được phép có thể cấu hình, linh hoạt trong phát triển
- **Security Headers**: Helmet.js với HSTS, bảo vệ XSS, tùy chọn khung
- **Xác thực Đầu vào**: Xác thực schema Zod trên tất cả endpoints
- **Ẩn thông tin Nhạy cảm**: Log tự động ẩn băm và flag
- **Xử lý Lỗi**: Xử lý lỗi đúng cách không rò rỉ stack trace
- **Trust Proxy**: Hỗ trợ triển khai reverse proxy

### Biến Môi trường

Tạo file `.env` trong thư mục gốc dự án:

```env
# Đề xuất: Flag Mã hóa
ENCRYPTION_KEY=khóa-mã-hóa-hex-64-ký-tự-của-bạn
ENCRYPTED_FLAG=flag-đã-mã-hóa-và-làm-rối-của-bạn
OBFUSCATION_KEY=khóa-làm-rối-tùy-chỉnh-của-bạn

# Dự phòng: Flag Rõ (không khuyến nghị cho production)
FLAG=VNFLAG{TO_QUOC_GHI_CONG_VOI_NHAN_DAN_VIETNAM_9m2K7p1R4q8L3z6F0b5yXc}

# Bảo mật
ALLOWED_ORIGINS=http://localhost:5000,https://yourdomain.com

# Máy chủ
PORT=5000
NODE_ENV=development
```

**Quan trọng**: Không bao giờ commit file `.env` vào hệ thống quản lý phiên bản. Luôn sử dụng biến môi trường trong production.

## Tài liệu API

### Endpoints

#### `POST /api/hash`

Tính toán băm MD5 của FLAG nối với đầu vào người dùng.

**Yêu cầu:**
```json
{
  "input": "test123"
}
```

**Phản hồi:**
```json
{
  "input": "test123",
  "fullHash": "a1b2c3d4e5f6...",
  "first4Bytes": "a1b2c3d4",
  "timestamp": 1699999999999
}
```

**Giới hạn Tốc độ**: 30 yêu cầu mỗi phút

---

#### `GET /api/stats`

Lấy thống kê thử thách.

**Phản hồi:**
```json
{
  "totalQueries": 42,
  "totalAttempts": 5,
  "solved": false
}
```

---

#### `POST /api/validate-flag`

Gửi flag để xác thực.

**Yêu cầu:**
```json
{
  "flag": "VNFLAG{...}"
}
```

**Phản hồi:**
```json
{
  "correct": true,
  "message": "Chúc mừng! Bạn đã khai thác thành công lỗ hổng MD5!"
}
```

**Giới hạn Tốc độ**: 10 yêu cầu mỗi 5 phút

## Phát triển

### Scripts Có sẵn

```bash
# Máy chủ phát triển với hot reload
npm run dev

# Kiểm tra kiểu
npm run check

# Build cho production
npm run build

# Khởi động máy chủ production
npm start

# Bảo mật: Tạo khóa mã hóa
tsx scripts/encrypt-flag.ts --generate-key

# Bảo mật: Mã hóa flag
tsx scripts/encrypt-flag.ts "FLAG_CỦA_BẠN" "KHÓA_MÃ_HÓA"

# Migrations cơ sở dữ liệu (nếu sử dụng PostgreSQL)
npm run db:push
```

### Quy trình Phát triển

1. Thực hiện thay đổi mã
2. Vite tự động hot-reload frontend
3. Máy chủ khởi động lại khi có thay đổi backend
4. Kiểm tra trong trình duyệt tại `localhost:5000`

### Chất lượng Mã

- **TypeScript**: Kiểm tra kiểu nghiêm ngặt được bật
- **ESLint**: Linting mã (được cấu hình qua package.json)
- **Prettier**: Định dạng mã
- **Zod**: Xác thực thời gian chạy

## Phương pháp Tấn công

### Công cụ Đề xuất

1. **HashPump**: Công cụ tấn công mở rộng độ dài MD5
   ```bash
   # Ví dụ sử dụng
   hashpump -s a1b2c3d4 -d "dữ_liệu_gốc" -a "phần_mở_rộng" -k 64
   ```

2. **Scripts Tùy chỉnh**: Tự động hóa quá trình tấn công
   ```python
   # Ví dụ Python để tìm va chạm
   import hashlib
   import itertools
   
   def find_collision():
       # Triển khai ở đây
       pass
   ```

3. **Hashcat / John the Ripper**: Công cụ bẻ khóa mật khẩu

### Các Giai đoạn Tấn công

#### Giai đoạn 1: Thu thập Băm
- Gửi các đầu vào khác nhau đến oracle
- Thu thập đầu ra băm
- Phân tích mẫu trong 4 byte đầu tiên

#### Giai đoạn 2: Tấn công Va chạm
- Khai thác điểm yếu xác thực 4-byte
- Sử dụng nghịch lý sinh nhật để tìm va chạm
- Ước tính ~2^16 lần thử cho tỷ lệ thành công 50%

#### Giai đoạn 3: Mở rộng Độ dài
- Áp dụng kỹ thuật mở rộng độ dài MD5
- Tính toán băm mới từ các băm hiện có
- Tận dụng cấu trúc tin nhắn đã biết

#### Giai đoạn 4: Khôi phục Flag
- Kết hợp dữ liệu va chạm và mở rộng
- Thu hẹp dần các khả năng flag
- Gửi flag cuối cùng để xác thực

### Tài nguyên

- [Tấn công Mở rộng Độ dài MD5 Giải thích](https://crypto.stackexchange.com/)
- [Tài liệu HashPump](https://github.com/bwall/HashPump)
- [Hiểu Cấu trúc Merkle-Damgård](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction)

## Quốc tế hóa

Nền tảng hỗ trợ nhiều ngôn ngữ:

- Tiếng Anh
- Tiếng Việt

Ngôn ngữ có thể được chuyển đổi qua menu điều hướng.

## Giám sát & Gỡ lỗi

### Log Máy chủ

Log tự động ẩn thông tin nhạy cảm:

```
POST /api/hash 200 in 5ms :: {"input":"test","fullHash":"[REDACTED]","first4Bytes":"a1b2","timestamp":1699999999}
```

### Theo dõi Thống kê

- Tổng truy vấn băm
- Tổng lần thử gửi flag
- Trạng thái giải quyết thử thách
- Theo dõi theo phiên (trong bộ nhớ)

## Triển khai

### Build Production

```bash
# Build ứng dụng
npm run build

# Khởi động máy chủ production
NODE_ENV=production npm start
```

### Thiết lập Môi trường

Đảm bảo các biến môi trường này được đặt trong production:

```env
NODE_ENV=production
FLAG=<flag-production-của-bạn>
ALLOWED_ORIGINS=https://yourdomain.com
PORT=5000
```

### Danh sách Kiểm tra Bảo mật

- Đặt giá trị FLAG mạnh, duy nhất
- Cấu hình ALLOWED_ORIGINS
- Bật HTTPS trong production
- Xem lại cấu hình giới hạn tốc độ
- Thiết lập giám sát và ghi log
- Kiểm toán bảo mật định kỳ

## Đóng góp

Đóng góp được chào đón! Vui lòng làm theo các hướng dẫn sau:

1. Fork repository
2. Tạo nhánh tính năng (`git checkout -b feature/tính-năng-tuyệt-vời`)
3. Commit thay đổi của bạn (`git commit -m 'Thêm tính năng tuyệt vời'`)
4. Đẩy đến nhánh (`git push origin feature/tính-năng-tuyệt-vời`)
5. Mở Pull Request

### Tiêu chuẩn Mã

- Tuân theo thực hành TypeScript tốt nhất
- Viết thông báo commit có ý nghĩa
- Thêm tests cho tính năng mới
- Cập nhật tài liệu khi cần

## Giấy phép

Dự án này được cấp phép theo Giấy phép MIT - xem file [LICENSE](LICENSE) để biết chi tiết.

## Ghi nhận

- **HackTheBox** và **TryHackMe** cho cảm hứng nền tảng CTF
- **OWASP** cho thực hành bảo mật tốt nhất
- **Shadcn/ui** cho components UI đẹp
- Cộng đồng mật mã học cho tài nguyên giáo dục

## Tuyên bố Miễn trừ

Ứng dụng này được thiết kế **chỉ cho mục đích giáo dục**. Nó minh họa các lỗ hổng mật mã thực tế để giúp nhà phát triển hiểu các khái niệm bảo mật. Không bao giờ sử dụng MD5 cho các ứng dụng bảo mật trong môi trường production.

**Điểm chính:**
- Sử dụng SHA-256 hoặc SHA-3 để băm mật mã
- Luôn xác thực toàn bộ băm, không bao giờ một phần
- Triển khai các hàm dẫn xuất khóa đúng cách (PBKDF2, Argon2)
- Tuân theo thực hành mật mã tốt nhất hiện tại

## Hỗ trợ

- **Vấn đề**: [GitHub Issues](https://github.com/F12FLASH/CTF/issues)
- **Email**: loideveloper.37@gmail.com

---

**Được tạo ra với sự quan tâm cho cộng đồng an ninh mạng**

*Hãy nhớ: Thử thách này cho thấy lý do tại sao MD5 không còn an toàn. Luôn sử dụng các thuật toán băm hiện đại, an toàn trong production!*