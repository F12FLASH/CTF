# 🎓 Hướng Dẫn Chi Tiết - Elliptic Nightmare

## Tổng Quan Quy Trình

Tài liệu này hướng dẫn chi tiết từng bước để giải thử thách Elliptic Nightmare.

---

## Phần 1: Hiểu Vấn Đề

### Thông Tin Được Cung Cấp

Khi bắt đầu thử thách, bạn có file `challenge.txt` chứa:

```
n = 140671763600040119991298781650461307397      # Composite modulus
a = 123456789012345                               # Tham số curve
b = 987654321098765                               # Tham số curve  
G = (x, y)                                        # Base point
order = 140671763600040119967291472450619000460  # Order của nhóm
signature = (r, s)                                # Chữ ký ECDSA
k_leak (2 LSB) = 3                                # 2 bit thấp của nonce k
encrypted_flag = {...}                            # Flag đã mã hóa
```

### Điều Bạn Cần Tìm

**Mục tiêu:** Tìm khóa bí mật `d` để giải mã flag

---

## Phần 2: Bước 1 - Phân Tích Modulus

### Lý Thuyết

ECDSA chuẩn sử dụng số nguyên tố `p` làm modulus. Thử thách này dùng **composite number** `n = p × q`.

### Thực Hành

#### Cách 1: Sử dụng Code Có Sẵn
```python
import sympy
n = 140671763600040119991298781650461307397
factors = sympy.factorint(n)
print(factors)
# Output: {10155422970993613727: 1, 13851886228848693211: 1}
```

#### Cách 2: Sử dụng FactorDB (CTF Thực Tế)

1. Truy cập http://factordb.com/
2. Nhập giá trị n
3. Nếu đã có trong database → lấy kết quả
4. Nếu chưa có → yêu cầu phân tích hoặc dùng công cụ khác

#### Cách 3: Công Cụ YAFU (Local)
```bash
yafu "factor(140671763600040119991298781650461307397)" -threads 4
```

### Kết Quả

```
p = 13851886228848693211
q = 10155422970993613727
```

**✅ Checkpoint 1:** Đã có p và q

---

## Phần 2: Bước 2 - Chinese Remainder Theorem

### Lý Thuyết

Vì `n = p × q`, bài toán ECDSA ban đầu có thể tách thành:

```
Bài toán gốc: Tìm d mod (p-1)(q-1)
     ↓
Bài toán 1: Tìm d_p mod (p-1)
Bài toán 2: Tìm d_q mod (q-1)
     ↓  
Kết hợp: d = CRT(d_p, d_q)
```

### Tại Sao Điều Này Hoạt Động?

Theo định lý CRT, nếu:
- `gcd(p-1, q-1) = 1` (thường đúng)
- Biết `d mod (p-1)` và `d mod (q-1)`

Thì có thể tính chính xác `d mod (p-1)(q-1)`

### Code Minh Họa

```python
from sympy.ntheory.modular import crt

# Giả sử đã tìm được
d_p = 12345  # Private key modulo (p-1)
d_q = 67890  # Private key modulo (q-1)

# Kết hợp
moduli = [p - 1, q - 1]
remainders = [d_p, d_q]
d, _ = crt(moduli, remainders)

print(f"Private key: {d}")
```

**✅ Checkpoint 2:** Hiểu cách tách và kết hợp bài toán

---

## Phần 3: Bước 3 & 4 - Tấn Công Lattice

### 3.1. Xây Dựng Bài Toán Lattice

#### Phương Trình ECDSA Gốc
```
s · k ≡ H(m) + r · d (mod order)
```

Trong đó:
- `s, r`: Chữ ký (đã biết)
- `k`: Nonce (chưa biết, nhưng biết 2 bit LSB)
- `H(m)`: Hash của message (đã biết)
- `d`: Private key (cần tìm)

#### Biến Đổi

Vì biết `k_leak = k & 0b11` (2 bit thấp nhất):

```
k = k_high · 4 + k_leak
```

Thay vào phương trình:
```
s · (k_high · 4 + k_leak) ≡ H(m) + r · d (mod order)
s · k_high · 4 ≡ H(m) - k_leak · s + r · d (mod order)
```

Chia hai vế cho `s`:
```
k_high · 4 ≡ (H(m) - k_leak · s) · s⁻¹ + r · s⁻¹ · d (mod order)
```

Đặt:
- `u = (H(m) - k_leak · s) · s⁻¹ mod order`
- `v = r · s⁻¹ mod order`

Ta có:
```
v · d - k_high · 4 ≡ u (mod order)
```

Đây chính là **Bài toán SVP (Shortest Vector Problem)** trong lattice!

### 3.2. Ma Trận Lattice

Xây dựng ma trận:
```
L = [
    [order,  0,    0   ],
    [v,      K,    0   ],
    [u,      0,    K·4 ]
]
```

Với `K = 2^20` (hằng số scaling)

**Mục tiêu:** Tìm vector `(x, y, z)` trong lattice sao cho:
- `y / K ≈ d` (private key)
- `z / (K·4) ≈ k_high`

### 3.3. Thuật Toán LLL

#### Giả Mã

```
function LLL(basis, delta=0.75):
    B = basis
    k = 1
    
    while k < length(B):
        # Bước 1: Size reduction
        for j from k-1 down to 0:
            if |μ[k][j]| > 0.5:
                B[k] = B[k] - round(μ[k][j]) · B[j]
        
        # Bước 2: Lovász condition
        B* = GramSchmidt(B)
        if ||B*[k]||² >= (δ - μ²) · ||B*[k-1]||²:
            k = k + 1
        else:
            swap(B[k], B[k-1])
            k = max(k-1, 1)
    
    return B
```

#### Code Thực Tế (Đơn Giản Hóa)

```python
import numpy as np

def lll_reduce(L, delta=0.75):
    """Thuật toán LLL reduction đơn giản"""
    
    def gram_schmidt(B):
        """Gram-Schmidt orthogonalization"""
        B_star = []
        mu = []
        
        for i in range(len(B)):
            b_star = B[i].copy()
            mu_row = []
            
            for j in range(i):
                mu_ij = np.dot(B[i], B_star[j]) / np.dot(B_star[j], B_star[j])
                mu_row.append(mu_ij)
                b_star = b_star - mu_ij * B_star[j]
            
            B_star.append(b_star)
            mu.append(mu_row)
        
        return B_star, mu
    
    # Chuyển sang float để tính toán
    B = [np.array(b, dtype=float) for b in L]
    k = 1
    
    while k < len(B):
        B_star, mu = gram_schmidt(B)
        
        # Size reduction
        for j in range(k-1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                B[k] = B[k] - round(mu[k][j]) * B[j]
        
        # Recompute Gram-Schmidt
        B_star, mu = gram_schmidt(B)
        
        # Lovász condition
        norm_k = np.dot(B_star[k], B_star[k])
        norm_k1 = np.dot(B_star[k-1], B_star[k-1])
        
        if norm_k >= (delta - mu[k][k-1]**2) * norm_k1:
            k += 1
        else:
            B[k], B[k-1] = B[k-1].copy(), B[k].copy()
            k = max(k-1, 1)
    
    return [b.astype(int) for b in B]

# Sử dụng
reduced_basis = lll_reduce(L)
```

### 3.4. Trích Xuất Private Key

```python
K = 2**20

for vector in reduced_basis:
    # Trích xuất d và k_high từ vector
    d_candidate = abs(vector[1]) // K
    k_high_candidate = abs(vector[2]) // (K * 4)
    
    # Xác minh
    k_full = k_high_candidate * 4 + k_leak
    
    try:
        test_s = inverse(k_full, order) * (z + r * d_candidate) % order
        
        if test_s == s:
            print(f"✓ Tìm thấy private key: {d_candidate}")
            return d_candidate
    except:
        continue

print("✗ Không tìm thấy private key hợp lệ")
return None
```

**✅ Checkpoint 3:** Đã tìm được `d_p` và `d_q`

---

## Phần 4: Bước 5 - Kết Hợp và Giải Mã

### Kết Hợp CRT

```python
from sympy.ntheory.modular import crt

# d_p: Private key modulo (p-1)
# d_q: Private key modulo (q-1)

moduli = [p - 1, q - 1]
remainders = [d_p, d_q]

private_key, _ = crt(moduli, remainders)
print(f"Private key cuối cùng: {private_key}")
```

### Giải Mã Flag

Hệ thống mã hóa:
```
encrypted_flag = {
    'data': '<base64 encrypted data>',
    'salt': '<base64 salt>',
    'iv': '<base64 IV>',
    'checksum': '<SHA256 checksum>'
}
```

Quá trình giải mã:
```python
from crypto_utils import FlagEncryption

encryptor = FlagEncryption("elliptic_nightmare_ctf_2025")
flag = encryptor.decrypt_flag(encrypted_flag, private_key)

if flag:
    print(f"🎉 FLAG: {flag}")
else:
    print("❌ Giải mã thất bại - private key không đúng")
```

**✅ Checkpoint 4:** Có FLAG!

---

## Phần 5: Tổng Kết

### Các Bước Đã Thực Hiện

1. ✅ **Factorization**: `n = p × q`
2. ✅ **CRT Decomposition**: Tách bài toán
3. ✅ **Lattice Construction**: Xây dựng ma trận
4. ✅ **LLL Reduction**: Tìm vector ngắn
5. ✅ **Key Recovery**: Khôi phục private key
6. ✅ **Decryption**: Giải mã flag

### Công Cụ Đã Dùng

| Công cụ | Mục đích |
|---------|----------|
| SymPy | Factorization, CRT |
| NumPy | Ma trận lattice |
| PyCryptodome | Mã hóa/giải mã |
| LLL Algorithm | Tìm basis rút gọn |

### Bài Học Rút Ra

1. **Không dùng composite modulus cho ECC**
2. **Bảo vệ nonce k tuyệt đối**
3. **Lattice attacks rất mạnh với partial information**
4. **CRT là công cụ hữu ích trong cryptanalysis**

---

## Phần 6: Thử Thách Nâng Cao

Sau khi hiểu cơ bản, thử:

### Level 1: Easy
- Tăng kích thước prime lên 256 bits
- Vẫn có 2 bit leak

### Level 2: Medium  
- 512 bit primes
- Chỉ 1 bit leak
- Cần điều chỉnh lattice dimension

### Level 3: Hard
- 1024 bit primes
- Multiple signatures với shared nonce
- Kết hợp nhiều kỹ thuật

### Level 4: Extreme
- Không cho sẵn factors → phải factor tự động
- No nonce leak → tìm weakness khác
- Side-channel attack simulation

---

## Tài Liệu Tham Khảo

### Papers Nên Đọc

1. **"Lattice-Based Cryptanalysis"** - Dan Boneh, Antoine Joux
2. **"The LLL Algorithm"** - Phong Nguyen, Brigitte Vallée  
3. **"Elliptic Curve Cryptography in Practice"** - Joppe W. Bos et al.

### Code Mẫu

- https://github.com/mimoo/RSA-and-LLL-attacks
- https://github.com/josephsurin/lattice-based-cryptanalysis

---

**Chúc bạn thành công! 🎯**
