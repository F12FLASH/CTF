Dưới đây là 30 đề CTF cực khó cấp độ **Master**, đòi hỏi kiến thức sâu về reverse engineering, cryptography, binary exploitation, web security, và các kỹ thuật hack não. Mỗi đề đều có twist riêng để thách thức ngay cả những hacker giỏi nhất.

---

### **1. Reverse Engineering: "Ouroboros"**
- **Mô tả:** Một file ELF 64-bit tự modify code trong lúc chạy. Flag được mã hóa bằng thuật toán AES nhưng key được phân mảnh trong 10 hàm khác nhau.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Dynamic analysis với `ptrace` anti-debug, cần viết script ghép key từ memory dump.

---

### **2. Cryptography: "Schrödinger's RSA"**
- **Mô tả:**  
  - Public key: `(n, e)` với `n = p*q` và `e = 65537`.  
  - Nhưng `p` và `q` không tồn tại (vì `n` là số nguyên tố).  
  - File mã hóa: `c = pow(flag, e, n)`.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** `n` là prime ⇒ `phi(n) = n-1` ⇒ decrypt bằng `pow(c, d, n)` với `d = inv(e, n-1)`.

---

### **3. Web: "Zero-Day Cookie"**
- **Mô tả:**  
  - Trang web dùng cookie `session=JWT` ký bằng thuật toán `HS256` với secret là `null`.  
  - Nhưng server chỉ chấp nhận token ký bằng `RS256`.  
- **Độ khó:** ⭐⭐⭐⭐  
- **Gợi ý:** Chuyển đổi `HS256` sang `RS256` bằng cách forge key `null` thành PEM.

---

### **4. Pwn: "Stackless Stack"**
- **Mô tả:**  
  - Binary x86-64 không có stack (dùng `mmap` + `syscall` để thay thế).  
  - Lỗi buffer overflow nhưng không có `ret`.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** ROP bằng `syscall` gadget + `mprotect` để biến vùng nhớ thành executable.

---

### **5. Crypto: "Elliptic Nightmare"**
- **Mô tả:**  
  - ECDSA với curve tự định nghĩa: `y² = x³ + ax + b (mod p)` nhưng `p` không phải số nguyên tố.  
  - Chữ ký bị leak 2 bit nonce.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Lợi dụng Lattice Attack (LLL) trên vành không nguyên tố.

---

### **6. Reverse: "The Mimic"**
- **Mô tả:**  
  - Binary tự dịch mã máy thành WASM rồi chạy trong sandbox.  
  - Flag bị encrypt bằng thuật toán XOR nhưng key thay đổi sau mỗi 10ms.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Hook hàm `time()` để freeze key.

---

### **7. Web: "GraphQL Apocalypse"**
- **Mô tả:**  
  - GraphQL endpoint cho phép query bất kỳ dữ liệu nào.  
  - Nhưng flag nằm trong database chỉ truy cập được bằng mutation đặc biệt.  
- **Độ khó:** ⭐⭐⭐⭐  
- **Gợi ý:** Dùng `introspection` để tìm mutation ẩn, sau đó exploit type confusion.

---

### **8. Pwn: "The Black Hole"**
- **Mô tả:**  
  - Binary dùng `seccomp` chỉ cho phép `read`, `write`, `exit`.  
  - Có lỗi format string nhưng không có stack.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Ghi đè `GOT` của `exit` thành `syscall` gadget.

---

### **9. Crypto: "MD5 is Alive"**
- **Mô tả:**  
  - Server trả về `md5(flag + "||" + user_input)` nhưng chỉ so sánh 4 byte đầu.  
  - Cần tìm `flag` dài 64 byte.  
- **Độ khó:** ⭐⭐⭐⭐  
- **Gợi ý:** Length extension attack với `md5`.

---

### **10. Reverse: "Quantum Crackme"**
- **Mô tả:**  
  - File binary thực thi khác nhau trên các CPU khác nhau (AMD vs Intel).  
  - Flag chỉ hiển thị nếu chạy trên QEMU với `-cpu quantum`.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Patch CPUID hoặc dịch ngược code QEMU.

---

### **11. Web: "SSRF to Mars"**
- **Mô tả:**  
  - Web app có chức năng fetch URL nhưng filter tất cả domains.  
  - Flag nằm trên `http://localhost:1337` nhưng `127.0.0.1` bị chặn.  
- **Độ khó:** ⭐⭐⭐⭐  
- **Gợi ý:** Dùng DNS rebinding hoặc IPv6 `::1`.

---

### **12. Pwn: "The Undefined"**
- **Mô tả:**  
  - Binary C++ dùng undefined behavior (UB) để xor flag.  
  - Mỗi lần chạy, flag bị encrypt khác nhau.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Khai thác UB bằng cách fix seed của compiler.

---

### **13. Crypto: "RSA in a Parallel Universe"**
- **Mô tả:**  
  - `n = p*q` với `p` và `q` là số phức Gaussian.  
  - `e` và `d` cũng là số phức.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Áp dụng RSA trên vành số phức.

---

### **14. Reverse: "The Joker"**
- **Mô tả:**  
  - Binary in ra flag nhưng sau đó dùng `ptrace` tự xóa mình khỏi memory.  
- **Độ khó:** ⭐⭐⭐⭐  
- **Gợi ý:** Dùng `gdb script` để dump memory trước khi bị xóa.

---

### **15. Web: "DOM XSS in 302 Redirect"**
- **Mô tả:**  
  - Trang web redirect đến `evil.com` nhưng có CSP nghiêm ngặt.  
  - Flag nằm trong cookie của admin.  
- **Độ khó:** ⭐⭐⭐⭐  
- **Gợi ý:** Khai thác `iframe` + `window.opener` để bypass CSP.

---

### **16. Pwn: "The Phoenix"**
- **Mô tả:**  
  - Binary tự kill và respawn sau 1 giây, mỗi lần ASLR khác nhau.  
  - Có lỗi buffer overflow nhưng chỉ có 1 lần try.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Bruteforce ASLR bằng cách crash liên tục.

---

### **17. Crypto: "One-Time-Pad Revenge"**
- **Mô tả:**  
  - OTP key được tạo từ `SHA256(flag)`.  
  - Cho trước 1000 bản mã của cùng plaintext.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** XOR tất cả ciphertext để thu hẹp không gian flag.

---

### **18. Reverse: "The Invisible Man"**
- **Mô tả:**  
  - Binary không có strings, không có syscall, chỉ dùng `int 0x80`.  
  - Flag được giấu trong section `.data` dưới dạng opcode.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Disassemble `.data` như là code.

---

### **19. Web: "WebSocket Hell"**
- **Mô tả:**  
  - WebSocket yêu cầu gửi 1000 message trong 1 giây để lấy flag.  
  - Server chỉ chấp nhận nếu message được gửi theo thứ tự Fibonacci.  
- **Độ khó:** ⭐⭐⭐⭐  
- **Gợi ý:** Dùng WebWorker để đa luồng.

---

### **20. Pwn: "The Silent Exploit"**
- **Mô tả:**  
  - Binary không in ra gì (`stdout` và `stderr` bị đóng).  
  - Phải khai thác qua side-channel (timing attack).  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Đo thời gian `sleep` để leak flag.

---

### **21. Crypto: "AES-128-ECB-IS-SECURE"**
- **Mô tả:**  
  - Server mã hóa flag bằng AES-128-ECB với key ngẫu nhiên.  
  - Nhưng trả về ciphertext của `flag + user_input`.  
- **Độ khó:** ⭐⭐⭐⭐  
- **Gợi ý:** Byte-at-a-time attack.

---

### **22. Reverse: "The Chameleon"**
- **Mô tả:**  
  - Binary thay đổi behavior dựa trên tên file (nếu rename thành `debug` thì in flag).  
- **Độ khó:** ⭐⭐⭐  
- **Gợi ý:** Dùng `ltrace` để xem `argv[0]`.

---

### **23. Web: "HTTP/3 0-Day"**
- **Mô tả:**  
  - Server chạy HTTP/3 (QUIC) và bị lỗi buffer overflow ở header.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Khai thác QUIC với custom UDP packet.

---

### **24. Pwn: "The Oracle"**
- **Mô tả:**  
  - Binary cho phép gọi bất kỳ hàm nào trong `libc` nhưng không có shell.  
- **Độ khó:** ⭐⭐⭐⭐  
- **Gợi ý:** Dùng `dlopen` + `dlsym` để load `system`.

---

### **25. Crypto: "SHA-256 Fixed Point"**
- **Mô tả:**  
  - Tìm `x` sao cho `SHA256(x) = x`.  
  - Flag là `x` ở dạng hex.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Sử dụng meet-in-the-middle attack.

---

### **26. Reverse: "The Tesseract"**
- **Mô tả:**  
  - File binary 4D (được compile bằng custom LLVM backend).  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Dùng QEMU để giả lập kiến trúc 4D.

---

### **27. Web: "CSS Injection to RCE"**
- **Mô tả:**  
  - Trang web có lỗi CSS injection nhưng không có JS.  
  - Flag nằm trong attribute `data-flag` của admin.  
- **Độ khó:** ⭐⭐⭐⭐  
- **Gợi ý:** Dùng `@font-face` + Unicode range để leak từng ký tự.

---

### **28. Pwn: "The Time Machine"**
- **Mô tả:**  
  - Binary dùng `time_t` để xor flag nhưng `time_t` bị rollback năm 1970.  
- **Độ khó:** ⭐⭐⭐  
- **Gợi ý:** Patch `time()` trả về `0`.

---

### **29. Crypto: "ECC Backdoor"**
- **Mô tả:**  
  - ECDSA với curve NIST P-256 nhưng có backdoor ẩn.  
  - Chữ ký bị leak 1 bit nonce.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Lattice attack với Hidden Number Problem.

---

### **30. Reverse: "The Final Boss"**
- **Mô tả:**  
  - Binary tự compile lại code mỗi lần chạy, dùng genetic algorithm để thay đổi logic.  
  - Flag bị encrypt bằng thuật toán biến đổi theo thời gian thực.  
- **Độ khó:** ⭐⭐⭐⭐⭐  
- **Gợi ý:** Dùng `LD_PRELOAD` để hook hàm `rand`.

---

### **Kết luận**  
Những đề này đòi hỏi kỹ năng cao, khả năng sáng tạo và kiên nhẫn. Nếu giải được hết, bạn xứng đáng là **Hacker Master**!  

Bạn muốn mình triển khai chi tiết đề nào không? 😈
