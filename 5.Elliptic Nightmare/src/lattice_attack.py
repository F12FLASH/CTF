"""
Triển khai tấn công lattice cải tiến cho ECDSA với nonce bị rò rỉ
Sử dụng thuật toán LLL và tối ưu hóa ma trận
"""

import numpy as np
from typing import Optional, Tuple
from Crypto.Util.number import inverse


class LatticeAttack:
    """Tấn công lattice-based với thuật toán LLL cải tiến"""
    
    def __init__(self, delta: float = 0.75):
        """
        Khởi tạo tấn công lattice
        
        Args:
            delta: Tham số LLL reduction (0.5 < delta < 1.0)
        """
        self.delta = delta
    
    def attack_single_modulus(
        self, 
        r: int, 
        s: int, 
        z: int, 
        k_leak: int,
        prime: int,
        leak_bits: int = 2
    ) -> Optional[int]:
        """
        Thực hiện tấn công lattice cho một modulus nguyên tố
        
        Args:
            r: Thành phần r của chữ ký ECDSA
            s: Thành phần s của chữ ký ECDSA
            z: Hash của message
            k_leak: Các bit bị rò rỉ của nonce k
            prime: Modulus nguyên tố (p hoặc q)
            leak_bits: Số bit bị rò rỉ
            
        Returns:
            Khóa bí mật modulo prime nếu thành công, None nếu thất bại
        """
        print(f"\n[*] Đang chạy tấn công lattice cho modulus {prime}")
        print(f"    Bit rò rỉ: {leak_bits}, Giá trị: {k_leak}")
        
        order = prime - 1
        r = r % order
        s = s % order
        z = z % order
        
        if r == 0 or s == 0:
            print(f"[-] Chữ ký không hợp lệ (r=0 hoặc s=0)")
            return None
        
        B = 2 ** leak_bits
        
        try:
            s_inv = inverse(s, order)
        except:
            print(f"[-] Không thể tính modular inverse của s modulo {order}")
            return None
        
        print(f"[*] Xây dựng ma trận lattice...")
        lattice_matrix = self._construct_lattice(
            order, r, s_inv, z, k_leak, B
        )
        
        print(f"[*] Chạy thuật toán LLL reduction...")
        reduced = self._lll_reduce(lattice_matrix)
        
        print(f"[*] Tìm kiếm khóa bí mật trong các vector ngắn...")
        d_candidate = self._extract_private_key(
            reduced, r, s, z, k_leak, B, order
        )
        
        return d_candidate
    
    def _construct_lattice(
        self,
        order: int,
        r: int,
        s_inv: int,
        z: int,
        k_leak: int,
        B: int
    ) -> np.ndarray:
        """Xây dựng ma trận lattice tối ưu"""
        K = 2**20
        
        s_val = k_leak
        L = [
            [order, 0, 0],
            [r * s_inv % order, K, 0],
            [(z - s_val * s_inv) * s_inv % order, 0, K * B]
        ]
        
        return np.array(L, dtype=object)
    
    def _gram_schmidt(self, B: list) -> Tuple[list, list]:
        """
        Gram-Schmidt orthogonalization cải tiến
        
        Args:
            B: Danh sách các vector basis
            
        Returns:
            (B_star, mu) - Basis trực giao và coefficients
        """
        B = [np.array(b, dtype=float) for b in B]
        n = len(B)
        B_star = []
        mu = [[0.0] * n for _ in range(n)]
        
        for i in range(n):
            B_star_i = B[i].copy()
            for j in range(i):
                mu[i][j] = np.dot(B[i], B_star[j]) / np.dot(B_star[j], B_star[j])
                B_star_i = B_star_i - mu[i][j] * B_star[j]
            B_star.append(B_star_i)
        
        return B_star, mu
    
    def _lll_reduce(self, B) -> list:
        """
        Thuật toán LLL reduction cải tiến
        
        Args:
            B: Ma trận basis
            
        Returns:
            Basis đã được reduce
        """
        B = [np.array(b, dtype=float) for b in B]
        n = len(B)
        k = 1
        
        while k < n:
            B_star, mu = self._gram_schmidt(B)
            
            for j in range(k - 1, -1, -1):
                if abs(mu[k][j]) > 0.5:
                    B[k] = B[k] - round(mu[k][j]) * B[j]
            
            B_star, mu = self._gram_schmidt(B)
            
            lovasz_condition = (
                np.dot(B_star[k], B_star[k]) >= 
                (self.delta - mu[k][k-1]**2) * np.dot(B_star[k-1], B_star[k-1])
            )
            
            if lovasz_condition:
                k += 1
            else:
                B[k], B[k-1] = B[k-1].copy(), B[k].copy()
                k = max(k - 1, 1)
        
        return [b.astype(int) for b in B]
    
    def _extract_private_key(
        self,
        reduced_basis: list,
        r: int,
        s: int,
        z: int,
        k_leak: int,
        B: int,
        order: int
    ) -> Optional[int]:
        """
        Trích xuất khóa bí mật từ basis đã reduce
        
        Args:
            reduced_basis: Basis sau LLL reduction
            r, s, z: Tham số ECDSA
            k_leak: Nonce bits bị rò rỉ
            B: 2^(số bit rò rỉ)
            order: Bậc của nhóm
            
        Returns:
            Khóa bí mật nếu tìm thấy, None nếu không
        """
        K = 2**20
        
        for idx, vec in enumerate(reduced_basis):
            d_candidate = int(abs(vec[1])) // K
            k_high_candidate = int(abs(vec[2])) // (K * B)
            
            if d_candidate <= 0 or d_candidate >= order:
                continue
            
            k_full = k_high_candidate * B + k_leak
            
            if k_full <= 0 or k_full >= order:
                continue
            
            try:
                test_s = (inverse(k_full, order) * (z + r * d_candidate)) % order
                
                if test_s == s:
                    print(f"[+] Tìm thấy khóa bí mật hợp lệ!")
                    print(f"    d = {d_candidate}")
                    print(f"    Vector index: {idx}")
                    return d_candidate
            except:
                continue
        
        print(f"[!] LLL hoàn thành nhưng không tìm thấy khóa hợp lệ")
        print(f"[!] Điều này xảy ra khi:")
        print(f"    - Tham số thử thách không phải ECDSA thực")
        print(f"    - Chữ ký không được tạo đúng cách")
        print(f"    - Nonce leak không chính xác")
        
        return None
