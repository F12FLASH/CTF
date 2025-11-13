# 🔐 Schrödinger's RSA - Thử Thách Mật Mã Học Cao Cấp

## 📋 Tổng Quan

**Cấp độ khó:** 🔴 Master Hacker  
**Danh mục:** Cryptography (Mật mã học)  
**Tác giả:** F12FLASH 

Chào mừng đến với **Schrödinger's RSA** - một nghịch lý lượng tử trong mật mã học cổ điển. Thử thách này khám phá ranh giới giữa những gì có vẻ đúng và những gì thực sự đúng trong mã hóa RSA.

---

## 🎯 Mục Tiêu

Giải mã cờ (flag) được mã hóa và lấy được thông điệp bí mật.

**Flag format:** `VNFLAG{...}`

---

## 📖 Mô Tả Thử Thách

Bạn đã chặn được một thông điệp được mã hóa bằng RSA. Gói tin chứa:

- **Khóa công khai (Public Key):** `(n, e)` trong đó `n` được cho là tích của hai số nguyên tố `p` và `q`
- **Số mũ công khai:** `e = 65537` (số mũ RSA tiêu chuẩn)
- **Flag đã mã hóa:** `c = pow(flag, e, n)`

### Quy trình RSA chuẩn:

1. Phân tích `n` thành `p × q`
2. Tính `φ(n) = (p-1)(q-1)`
3. Tìm số mũ bí mật `d`
4. Giải mã: `flag = pow(c, d, n)`

### 🌀 Điểm Đặc Biệt:

Giống như con mèo Schrödinger vừa sống vừa chết, trạng thái của `n` tồn tại trong một siêu vị trí lượng tử. Các số nguyên tố `p` và `q` vừa tồn tại vừa không tồn tại đồng thời. 

**Cho đến khi bạn quan sát bản chất thực sự của `n`, bạn không thể giải mã được thông điệp!**

---

### ⚠️ CẢNH BÁO SPOILER QUAN TRỌNG

File `solver.py` chứa lời giải hoàn chỉnh với giải thích chi tiết từng bước. **ĐỪNG đọc file này** nếu bạn muốn tự giải quyết thử thách! File này chỉ dùng cho mục đích giáo dục và để xác minh thử thách có thể giải được.

---

## 🚀 Bắt Đầu

### Yêu Cầu Hệ Thống

- Python 3.11 trở lên
- Thư viện pycryptodome

### Cài Đặt

```bash
# Clone repo
git clone https://github.com/F12FLASH/CTF.git
cd CTF/2.SchrodingerRSA

# Cài đặt thư viện cần thiết
pip install pycryptodome

# Hoặc nếu dùng Python 3
pip3 install pycryptodome
```

### Chạy Thử Thách

#### Cách 1: Giao diện tương tác (Khuyến nghị)

```bash
python main.py
```

Giao diện menu cung cấp:
- 📖 Xem mô tả thử thách
- 🔑 Xem khóa công khai
- 📜 Xem flag đã mã hóa
- 💡 Xem gợi ý (cẩn thận, có thể lừa đảo!)
- 🧪 Kiểm tra flag của bạn
- 📊 Thống kê thử thách
- 🔬 Chạy solver (SPOILER!)
- ℹ️ Thông tin về thử thách

#### Cách 2: Xem file trực tiếp

```bash
# Xem khóa công khai
cat public_key.txt

# Xem flag đã mã hóa
cat encrypted_flag.txt

# Xem gợi ý
cat hint.txt
```

#### Cách 3: Viết script tấn công của bạn

```python
# Đọc dữ liệu từ file
with open('public_key.txt', 'r') as f:
    lines = f.readlines()
    n = int(lines[0].split('=')[1].strip())
    e = int(lines[1].split('=')[1].strip())

with open('encrypted_flag.txt', 'r') as f:
    c = int(f.read().strip())

# Viết code tấn công của bạn ở đây!
# ...

# Kiểm tra flag
from challenge_data import _verify
if _verify(your_flag):
    print("Chính xác! 🎉")
else:
    print("Sai rồi, thử lại!")
```

---

## 💡 Gợi Ý (Độ Khó Tăng Dần)

<details>
<summary>💡 Gợi Ý 1 - Click để xem</summary>

Tiêu đề không chỉ là trang trí. "Schrödinger" ngụ ý điều gì về trạng thái tồn tại?

Hãy nghĩ về con mèo Schrödinger - nó vừa sống vừa chết cho đến khi được quan sát.

</details>

<details>
<summary>💡 Gợi Ý 2 - Click để xem</summary>

RSA truyền thống yêu cầu `n = p × q` trong đó cả `p` và `q` đều là số nguyên tố.

Nhưng nếu giả định cơ bản này sai thì sao?

</details>

<details>
<summary>💡 Gợi Ý 3 - Click để xem</summary>

Kiểm tra file gợi ý (`hint.txt`) một cách cẩn thận:

```bash
cat hint.txt
```

Liệu `p × q` có thực sự bằng `n` không? Điều này cho bạn biết gì?

</details>

<details>
<summary>💡 Gợi Ý 4 - Click để xem</summary>

Nếu `n` không phải là hợp số (tích `p × q`), thì nó có thể là gì?

**Hãy thử kiểm tra xem `n` có phải là số nguyên tố không!**

Sử dụng thuật toán kiểm tra tính nguyên tố như Miller-Rabin.

</details>

<details>
<summary>💡 Gợi Ý 5 - Spoiler Lớn!</summary>

Nếu `n` là số nguyên tố, thì hàm Euler totient trở thành:

**φ(n) = n - 1** (không phải `(p-1)(q-1)`)

Bạn có thể tính số mũ bí mật:
- `d = e⁻¹ mod (n-1)`

Sau đó giải mã bình thường:
- `m = c^d mod n`
- `flag = long_to_bytes(m).decode()`

</details>

---

## 🔬 Toán Học Đằng Sau Thử Thách

### RSA Chuẩn

```python
# 1. Chọn hai số nguyên tố lớn
p = getPrime(1024)
q = getPrime(1024)

# 2. Tính modulus
n = p * q  # Hợp số

# 3. Tính hàm Euler totient
φ(n) = (p-1)(q-1)

# 4. Chọn số mũ công khai
e = 65537

# 5. Tính số mũ bí mật
d = inverse(e, φ(n))

# 6. Mã hóa
c = pow(message, e, n)

# 7. Giải mã
m = pow(c, d, n)
```

### Schrödinger's RSA (Thử thách này)

```python
# 1. Chọn một số nguyên tố lớn (KHÔNG phải hai số!)
n = getPrime(2048)  # n là NGUYÊN TỐ, không phải hợp số!

# 2. Vì n là nguyên tố:
φ(n) = n - 1  # ĐÂY LÀ ĐIỂM THEN CHỐT!

# 3. Số mũ công khai
e = 65537

# 4. Mã hóa (giống RSA chuẩn)
c = pow(message, e, n)

# 5. Giải mã (nhưng dùng φ(n) = n-1)
d = inverse(e, n-1)  # Khác biệt ở đây!
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
```

### Tại Sao Điều Này Hoạt Động?

Định lý Euler cho biết:
- `m^φ(n) ≡ 1 (mod n)` với gcd(m, n) = 1

Đối với số nguyên tố `p`:
- `φ(p) = p - 1`

Do đó:
- `m^(p-1) ≡ 1 (mod p)` (Định lý Fermat nhỏ)

RSA dựa trên:
- `m^(ed) ≡ m (mod n)` khi `ed ≡ 1 (mod φ(n))`

Nếu `n` là nguyên tố và `d = e⁻¹ mod (n-1)`:
- `ed ≡ 1 (mod n-1)`
- `m^(ed) ≡ m (mod n)` ✓

**Giải mã vẫn hoạt động, nhưng bảo mật đã bị phá vỡ!**

---

## 🎓 Giá Trị Giáo Dục

Thử thách này dạy:

### 1. **Kiến Thức Cơ Bản Về RSA**
- Hiểu rõ vai trò của hàm Euler totient `φ(n)`
- Mối quan hệ giữa `p`, `q`, `n`, `e`, `d`
- Quá trình mã hóa và giải mã RSA

### 2. **Phân Tích Mật Mã**
- Đặt câu hỏi về các giả định cơ bản
- Kiểm tra các trường hợp ngoại lệ và biên
- Tư duy phản biện trong an ninh mạng

### 3. **Tính Chất Toán Học**
- Sự khác biệt giữa `φ(n)` cho số nguyên tố vs hợp số
- Hiểu `φ(p) = p-1` cho số nguyên tố `p`
- Hiểu `φ(pq) = (p-1)(q-1)` cho hợp số

### 4. **Kiểm Tra Tính Nguyên Tố**
- Thuật toán Miller-Rabin
- Kiểm tra tính nguyên tố xác suất vs xác định
- Độ phức tạp thời gian của các thuật toán

### 5. **Bảo Mật Thực Tế**
- Tại sao RSA chuẩn an toàn (phân tích n = pq khó)
- Tại sao Schrödinger's RSA không an toàn (kiểm tra nguyên tố dễ)
- Tầm quan trọng của việc chọn tham số đúng

---

## ⚠️ Lưu Ý Bảo Mật

### ĐÂY LÀ MẬT MÃ HỌC BỊ PHÁ VỠ CỐ Ý CHỈ VỚI MỤC ĐÍCH GIÁO DỤC!

Sử dụng số nguyên tố làm modulus RSA **KHÔNG cung cấp bảo mật** vì:

1. **Kiểm tra tính nguyên tố chạy trong thời gian đa thức**
   - Thuật toán Miller-Rabin rất nhanh
   - Có thể kiểm tra số 2048-bit trong vài giây

2. **Một khi xác nhận `n` là nguyên tố, `φ(n) = n - 1` được biết ngay**
   - Không cần phân tích
   - Không cần tính toán phức tạp

3. **Bất kỳ ai cũng có thể tính khóa bí mật ngay lập tức**
   - `d = inverse(e, n-1)`
   - Giải mã trở nên tầm thường

### RSA An Toàn Thực Sự

```python
# ĐÚNG: RSA an toàn
p = getPrime(2048)  # Số nguyên tố lớn
q = getPrime(2048)  # Số nguyên tố lớn khác
n = p * q           # Hợp số ~4096 bit
φ_n = (p-1)*(q-1)   # Khó tính nếu không biết p, q
d = inverse(e, φ_n)

# SAI: Schrödinger's RSA (thử thách này)
n = getPrime(2048)  # Chỉ một số nguyên tố
φ_n = n - 1         # Dễ tính!
d = inverse(e, φ_n) # Ai cũng có thể tính!
```

### **KHÔNG BAO GIỜ sử dụng trong môi trường thực!**

---

## 🧪 Kiểm Tra Flag

### Sau khi bạn tìm được flag:

```python
from challenge_data import _verify

your_flag = "VNFLAG{...}"

if _verify(your_flag):
    print("🎉 Chính xác! Chúc mừng!")
else:
    print("❌ Sai rồi. Thử lại!")
```

### Hoặc dùng giao diện:

```bash
python main.py
# Chọn: 5. 🧪 Test Your Flag
```

---

## 📊 Thống Kê Thử Thách

- **Độ mạnh bit:** 2048 bits
- **Thời gian giải dự kiến:**
  - Người mới: Vài giờ
  - Trung cấp: 1-2 giờ
  - Chuyên gia: 30-60 phút
  - Tinh hoa: 15-30 phút

- **Kỹ năng cần thiết:**
  - Hiểu biết về RSA
  - Kiến thức về hàm Euler totient
  - Khả năng lập trình Python
  - Tư duy phản biện
  - Kiên nhẫn và sáng tạo

---

## 🛠️ Công Cụ Hữu Ích

### Thư viện Python

```python
from Crypto.Util.number import *

# Đọc/ghi số lớn
bytes_to_long(b"Hello")
long_to_bytes(123456)

# Số học modular
inverse(e, phi_n)  # Tính e^(-1) mod phi_n
pow(m, e, n)       # Tính m^e mod n

# Kiểm tra nguyên tố
getPrime(2048)     # Tạo số nguyên tố
isPrime(n)         # Kiểm tra (nhanh nhưng xác suất)
```

### Thuật Toán Quan Trọng

1. **Miller-Rabin Primality Test** - Kiểm tra tính nguyên tố
2. **Extended Euclidean Algorithm** - Tính modular inverse
3. **Fast Modular Exponentiation** - Tính lũy thừa mod

---

## 📚 Tài Liệu Tham Khảo

### Tiếng Việt
- [RSA - Wikipedia tiếng Việt](https://vi.wikipedia.org/wiki/RSA_(m%C3%A3_h%C3%B3a))
- Sách: "An Toàn Thông Tin Mạng" - Nhiều tác giả
- Khóa học Cryptography trên các nền tảng học online

### Tiếng Anh
- [RSA Cryptosystem - Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Euler's Totient Function](https://en.wikipedia.org/wiki/Euler%27s_totient_function)
- [Miller-Rabin Primality Test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)
- [CryptoHack - Learning Platform](https://cryptohack.org/)
- [The Joy of Cryptography](https://joyofcryptography.com/)

---

## 🤝 Đóng Góp

Tìm thấy lỗi hoặc có đề xuất? Vui lòng:
- Mở issue
- Gửi pull request  
- Chia sẻ writeup của bạn (sau khi giải xong!)

---

## 💬 FAQ (Câu Hỏi Thường Gặp)

<details>
<summary><b>Q: Tôi không thể phân tích n thành p × q, làm sao?</b></summary>

A: Đó chính là điểm then chốt! Nếu bạn không thể phân tích n, có thể n không phải là hợp số. Hãy thử kiểm tra xem n có phải là số nguyên tố không.

</details>

<details>
<summary><b>Q: Gợi ý p và q trong hint.txt không đúng?</b></summary>

A: Hoàn toàn đúng! Đó là gợi ý lừa đảo. Nếu p × q ≠ n, điều đó cho bạn biết gì về giả định của RSA?

</details>

<details>
<summary><b>Q: Làm thế nào để kiểm tra số nguyên tố lớn?</b></summary>

A: Sử dụng thuật toán Miller-Rabin. Trong Python với pycryptodome:

```python
from Crypto.Util.number import isPrime
if isPrime(n):
    print("n là số nguyên tố!")
```

</details>

<details>
<summary><b>Q: Tôi đã tìm ra n là nguyên tố, giờ làm gì?</b></summary>

A: Nếu n là nguyên tố, thì φ(n) = n - 1. Sử dụng điều này để tính:
- d = inverse(e, n-1)
- m = pow(c, d, n)
- flag = long_to_bytes(m).decode()

</details>

<details>
<summary><b>Q: Code của tôi báo lỗi, phải làm sao?</b></summary>

A: Kiểm tra:
1. Đã cài đặt pycryptodome chưa: `pip install pycryptodome`
2. Các file challenge có đầy đủ không
3. Cú pháp Python có đúng không
4. Đọc thông báo lỗi cẩn thận

</details>

---

## 📜 Giấy Phép

Thử thách này được phát hành cho mục đích giáo dục. Vui lòng ghi nguồn khi sử dụng trong các cuộc thi CTF.

---

## 🌟 Lời Kết

**Chúc bạn may mắn, và mong các vị thần lượng tử ở bên bạn!** 🌌

*"Trong mật mã học, như trong cơ học lượng tử, việc quan sát thay đổi mọi thứ."*

---

**Thử thách được tạo với ❤️ cho cộng đồng An ninh mạng Việt Nam**

🇻🇳 **YÊU NƯỚC VIỆT NAM - SỐNG MÃI ĐẤU TU TƯỞNG** 🇻🇳
