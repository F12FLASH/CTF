# Tài liệu Bảo mật

## Hệ Thống Mã Hóa Flag

Thử thách CTF này triển khai hệ thống bảo mật nhiều lớp để bảo vệ flag ngay cả khi máy chủ bị xâm nhập.

### Các Lớp Bảo mật

1. **Mã hóa AES-256-GCM**: Mã hóa xác thực cấp độ quân sự
2. **Dẫn xuất Khóa**: Dẫn xuất khóa từ mật khẩu sử dụng Scrypt
3. **Làm rối**: Lớp bảo vệ bổ sung sử dụng XOR
4. **So sánh Thời gian Cố định**: Ngăn chặn tấn công thời gian trong xác thực flag
5. **Giải mã Thời gian Chạy**: Flag được mã hóa khi lưu trữ, chỉ giải mã trong bộ nhớ

## Hướng dẫn Thiết lập

### Bước 1: Tạo Khóa Mã hóa

```bash
tsx scripts/encrypt-flag.ts --generate-key
```

Lệnh này tạo ra một khóa hex an toàn 64 ký tự. Lưu trữ khóa này một cách an toàn.

### Bước 2: Mã hóa Flag

```bash
tsx scripts/encrypt-flag.ts "VNFLAG{FLAG_CUA_BAN}" "khoa-ma-hoa-cua-ban-tu-buoc-1"
```

Tùy chọn: Thêm khóa làm rối tùy chỉnh:
```bash
tsx scripts/encrypt-flag.ts "VNFLAG{FLAG_CUA_BAN}" "khoa-ma-hoa-cua-ban" "khoa-lam-roi-tuy-chinh"
```

### Bước 3: Thiết lập Biến Môi trường

Thêm vào file `.env` của bạn:

```env
ENCRYPTION_KEY=khoa-hex-64-ky-tu-cua-ban
ENCRYPTED_FLAG=ket-qua-da-ma-hoa-va-lam-roi-dang-base64
OBFUSCATION_KEY=khoa-lam-roi-cua-ban  # Tùy chọn, mặc định là "default-obfuscation"
```

## Nguyên lý Hoạt động

### Quy trình Mã hóa

```
Flag Gốc
    ↓
[Mã hóa AES-256-GCM]
    ↓
salt:iv:authTag:ciphertext
    ↓
[Làm rối XOR]
    ↓
ENCRYPTED_FLAG (Base64)
```

### Quy trình Giải mã Thời gian Chạy

```
ENCRYPTED_FLAG
    ↓
[Gỡ rối XOR]
    ↓
salt:iv:authTag:ciphertext
    ↓
[Giải mã AES-256-GCM với ENCRYPTION_KEY]
    ↓
Flag Đã Giải mã (chỉ trong bộ nhớ)
```

## Tính năng Bảo mật

### 1. AES-256-GCM
- **Mã hóa**: AES-256 trong chế độ Galois/Counter Mode
- **Xác thực**: Thẻ xác thực tích hợp ngăn chặn giả mạo
- **IV**: Vector khởi tạo ngẫu nhiên 16 byte cho mỗi lần mã hóa
- **Salt**: Salt ngẫu nhiên 16 byte cho dẫn xuất khóa

### 2. Dẫn xuất Khóa (Scrypt)
- **Thuật toán**: Scrypt với tham số có thể cấu hình
- **Độ dài Salt**: 16 byte
- **Độ dài Khóa**: 32 byte (256 bit)
- **Mục đích**: Dẫn xuất khóa mã hóa từ mật khẩu

### 3. Lớp Làm rối
- **Phương pháp**: XOR với mẫu khóa lặp lại
- **Mục đích**: Lớp bảo vệ bổ sung
- **Lưu ý**: Không an toàn về mật mã, chỉ tăng độ phức tạp

### 4. So sánh Thời gian Cố định
- **Phương pháp**: Tích lũy XOR theo bit
- **Mục đích**: Ngăn chặn tấn công thời gian
- **Triển khai**: Không trả về sớm khi không khớp

## Chế độ Dự phòng

Nếu `ENCRYPTION_KEY` hoặc `ENCRYPTED_FLAG` không được thiết lập, hệ thống sẽ chuyển sang sử dụng biến môi trường `FLAG` trực tiếp.

**CẢNH BÁO QUAN TRỌNG**:

Chế độ dự phòng **KHÔNG AN TOÀN** cho sử dụng production vì:

1. **Flag lưu ở dạng rõ**: Giá trị FLAG được lưu trữ không mã hóa trong `process.env.FLAG`
2. **Lộ biến môi trường**: Bất kỳ ai có quyền truy cập biến môi trường đều có thể đọc flag
3. **Dump bộ nhớ process**: Flag hiển thị trong bộ nhớ process
4. **File log**: Biến môi trường có thể xuất hiện trong log hệ thống
5. **Xâm nhập máy chủ**: Truy cập máy chủ = xâm nhập flag ngay lập tức

**Chế độ dự phòng CHỈ NÊN sử dụng cho**:
- Phát triển và kiểm thử cục bộ
- Trình diễn giáo dục
- Môi trường không phải production

**Đối với production, LUÔN LUÔN sử dụng chế độ mã hóa** với `ENCRYPTION_KEY` và `ENCRYPTED_FLAG`.

## Thực hành Tốt nhất

1. **Không bao giờ commit** `.env` vào hệ thống quản lý phiên bản
2. **Sử dụng khóa mã hóa mạnh** (tối thiểu 64 ký tự hex)
3. **Luân chuyển khóa định kỳ** trong production
4. **Lưu trữ khóa riêng biệt** với dữ liệu mã hóa
5. **Sử dụng khóa khác nhau** cho các môi trường khác nhau
6. **Giám sát log truy cập** để phát hiện hoạt động đáng ngờ

## Xem xét Bảo mật

### Những gì Hệ thống Bảo vệ

- Lộ mã nguồn
- Rò rỉ biến môi trường
- Truy cập máy chủ bởi người dùng trái phép
- Tấn công thời gian trong xác thực flag
- Tìm kiếm flag đơn giản trong file

### Những gì Hệ thống KHÔNG Bảo vệ

- Dump bộ nhớ khi máy chủ đang chạy (flag ở trong RAM)
- Tấn công cấp độ kernel
- Truy cập vật lý vào máy chủ đang chạy
- Lộ khóa (nếu ENCRYPTION_KEY bị đánh cắp)

## Tuân thủ

Hệ thống mã hóa này tuân theo:
- Hướng dẫn mật mã OWASP
- Khuyến nghị của NIST về độ dài khóa
- Thực hành tốt nhất trong ngành về quản lý bí mật

## Khắc phục Sự cố

### Lỗi Giải mã Flag

**Lỗi**: `Flag decryption failed. Check ENCRYPTION_KEY and ENCRYPTED_FLAG.`

**Giải pháp**:
1. Xác minh `ENCRYPTION_KEY` khớp với khóa được sử dụng để mã hóa
2. Xác minh `ENCRYPTED_FLAG` đầy đủ và không bị cắt ngắn
3. Xác minh `OBFUSCATION_KEY` khớp (nếu sử dụng khóa tùy chỉnh)
4. Kiểm tra vấn đề mã hóa biến môi trường

### Sử dụng Flag Mặc định

**Cảnh báo**: `CRITICAL: ENCRYPTION_KEY not set. Using fallback FLAG.`

**Giải pháp**:
1. Thiết lập biến môi trường `ENCRYPTION_KEY`
2. Thiết lập biến môi trường `ENCRYPTED_FLAG`
3. Làm theo hướng dẫn thiết lập ở trên

## Kiểm toán Bảo mật

Lần kiểm toán cuối: Tháng 11, 2024
Kiểm toán viên: Đội ngũ Bảo mật Nội bộ
Trạng thái: Đã phê duyệt cho sử dụng giáo dục CTF

## Báo cáo Vấn đề Bảo mật

Nếu bạn phát hiện lỗ hổng bảo mật, vui lòng gửi email tới: loideveloper.37@gmail.com

Không tạo issue GitHub công khai cho lỗ hổng bảo mật.