"""
Solver cải tiến cho thử thách Elliptic Nightmare
Với bảo mật tốt hơn, xử lý lỗi tốt hơn và code sạch hơn
"""

from Crypto.Hash import SHA256
import sympy
from sympy.ntheory.modular import crt
import sys
import json
from typing import Optional, Dict, Any

from crypto_utils import FlagEncryption, validate_challenge_parameters
from lattice_attack import LatticeAttack


class EllipticNightmareSolver:
    """Solver chính thức cho thử thách Elliptic Nightmare"""
    
    MASTER_PASSWORD = "elliptic_nightmare_ctf_2025"
    
    def __init__(self):
        """Khởi tạo solver"""
        self.encryptor = FlagEncryption(self.MASTER_PASSWORD)
        self.lattice_attacker = LatticeAttack(delta=0.75)
        self.params = {}
        
    def load_challenge(self, filepath: str = 'challenges/challenge.txt') -> bool:
        """
        Tải dữ liệu thử thách từ file
        
        Args:
            filepath: Đường dẫn đến file thử thách
            
        Returns:
            True nếu tải thành công, False nếu thất bại
        """
        try:
            print(f"[*] Đang tải thử thách từ {filepath}...")
            
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    
                    if not line or line.startswith('#'):
                        continue
                    
                    if '=' not in line:
                        continue
                    
                    key, value = line.split('=', 1)
                    key = key.strip().split('(')[0].strip()
                    value = value.strip()
                    
                    if key == 'message':
                        self.params[key] = value.strip("'\"")
                    elif key in ['G', 'public_key', 'signature']:
                        import ast
                        self.params[key] = ast.literal_eval(value)
                    elif key == 'encrypted_flag':
                        self.params[key] = json.loads(value)
                    else:
                        try:
                            self.params[key] = int(value)
                        except:
                            pass
            
            is_valid, error_msg = validate_challenge_parameters(self.params)
            if not is_valid:
                print(f"[-] Thử thách không hợp lệ: {error_msg}")
                return False
            
            print(f"[+] Đã tải thành công thử thách!")
            print(f"    Modulus: {self.params['n'].bit_length()} bits")
            print(f"    Order: {self.params['order'].bit_length()} bits")
            return True
            
        except FileNotFoundError:
            print(f"[-] Không tìm thấy file: {filepath}")
            print(f"[!] Hãy chạy generate_challenge.py trước để tạo thử thách")
            return False
        except Exception as e:
            print(f"[-] Lỗi khi tải thử thách: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def factor_modulus(self, p_hint: Optional[int] = None, q_hint: Optional[int] = None) -> tuple:
        """
        Phân tích modulus thành thừa số nguyên tố
        
        Args:
            p_hint: Giá trị p được cung cấp trước (để test)
            q_hint: Giá trị q được cung cấp trước (để test)
            
        Returns:
            (p, q) nếu thành công, (None, None) nếu thất bại
        """
        n = self.params['n']
        
        if p_hint and q_hint:
            print(f"[*] Sử dụng các thừa số được cung cấp")
            if p_hint * q_hint == n:
                print(f"    p = {p_hint}")
                print(f"    q = {q_hint}")
                return p_hint, q_hint
            else:
                print(f"[-] Các thừa số không khớp với n!")
        
        print(f"[*] Đang phân tích n = {n}")
        print(f"    Kích thước: {n.bit_length()} bits")
        
        if n.bit_length() > 200:
            print(f"[!] Modulus quá lớn để phân tích nhanh")
            print(f"[!] Trong CTF thực tế, bạn sẽ:")
            print(f"    1. Thử factordb.com")
            print(f"    2. Sử dụng YAFU hoặc công cụ tương tự")
            print(f"    3. Thêm 'p = <giá trị>' và 'q = <giá trị>' vào file thử thách")
            return None, None
        
        try:
            print(f"[*] Đang chạy thuật toán phân tích...")
            factors = sympy.factorint(n)
            
            if len(factors) == 2:
                primes = list(factors.keys())
                p, q = primes[0], primes[1]
                print(f"[+] Phân tích thành công!")
                print(f"    p = {p}")
                print(f"    q = {q}")
                return p, q
            else:
                print(f"[-] Không phân tích được thành hai số nguyên tố")
                return None, None
                
        except Exception as e:
            print(f"[-] Lỗi phân tích: {e}")
            return None, None
    
    def hash_message(self, message: str) -> int:
        """Tính hash SHA256 của message"""
        h = SHA256.new(message.encode()).digest()
        return int.from_bytes(h, 'big')
    
    def solve(self) -> Optional[int]:
        """
        Giải thử thách và khôi phục khóa bí mật
        
        Returns:
            Khóa bí mật nếu thành công, None nếu thất bại
        """
        print("\n" + "="*70)
        print("ELLIPTIC NIGHTMARE - Tấn Công ECDSA Trên Composite Modulus")
        print("="*70)
        
        p_hint = self.params.get('p')
        q_hint = self.params.get('q')
        
        p, q = self.factor_modulus(p_hint, q_hint)
        
        if p is None or q is None:
            print("\n[-] Không thể tiếp tục - cần phân tích modulus")
            return None
        
        print(f"\n[*] Áp dụng Định Lý Thặng Dư Trung Hoa (CRT)...")
        print(f"[*] Tách bài toán thành hai thành phần trên F_p và F_q")
        
        r, s = self.params['signature']
        z = self.hash_message(self.params['message'])
        k_leak = self.params['k_leak']
        
        print(f"\n[PHASE 1] Tấn công lattice trên F_p")
        d_p = self.lattice_attacker.attack_single_modulus(
            r, s, z, k_leak, p, leak_bits=2
        )
        
        if d_p is None:
            print(f"\n[-] Tấn công thất bại cho modulus p")
            return None
        
        print(f"\n[PHASE 2] Tấn công lattice trên F_q")
        d_q = self.lattice_attacker.attack_single_modulus(
            r, s, z, k_leak, q, leak_bits=2
        )
        
        if d_q is None:
            print(f"\n[-] Tấn công thất bại cho modulus q")
            return None
        
        print(f"\n[*] Kết hợp kết quả bằng CRT...")
        moduli = [p - 1, q - 1]
        remainders = [d_p, d_q]
        
        try:
            result = crt(moduli, remainders)
            if result is None or result[0] is None:
                print(f"[-] CRT thất bại")
                return None
            
            private_key = result[0]
            print(f"[+] Khôi phục thành công khóa bí mật!")
            print(f"    d = {private_key}")
            print(f"    Kích thước: {private_key.bit_length()} bits")
            
            return private_key
            
        except Exception as e:
            print(f"[-] Lỗi CRT: {e}")
            return None
    
    def decrypt_flag(self, private_key: int) -> Optional[str]:
        """
        Giải mã flag sau khi khôi phục khóa bí mật
        
        Args:
            private_key: Khóa bí mật đã khôi phục
            
        Returns:
            Flag nếu thành công, None nếu thất bại
        """
        if 'encrypted_flag' not in self.params:
            print("[-] Không tìm thấy encrypted flag trong thử thách")
            return None
        
        print(f"\n[*] Đang giải mã flag...")
        
        try:
            flag = self.encryptor.decrypt_flag(
                self.params['encrypted_flag'],
                private_key
            )
            return flag
        except Exception as e:
            print(f"[-] Giải mã thất bại: {e}")
            print(f"[!] Khóa bí mật có thể không chính xác")
            return None
    
    def run(self, challenge_file: str = 'challenges/challenge.txt'):
        """
        Chạy toàn bộ quy trình giải thử thách
        
        Args:
            challenge_file: Đường dẫn file thử thách
        """
        if not self.load_challenge(challenge_file):
            sys.exit(1)
        
        private_key = self.solve()
        
        if private_key is None:
            print("\n" + "="*70)
            print("THẤT BẠI")
            print("="*70)
            print("\n[-] Không thể khôi phục khóa bí mật")
            print("[!] Kiểm tra lại tham số thử thách")
            sys.exit(1)
        
        flag = self.decrypt_flag(private_key)
        
        if flag:
            print("\n" + "="*70)
            print("🎉 THÀNH CÔNG! 🎉")
            print("="*70)
            print(f"\n✓ Khóa bí mật: {private_key}")
            print(f"✓ FLAG: {flag}")
            print("\nChúc mừng bạn đã giải thành công thử thách Elliptic Nightmare!")
        else:
            print("\n" + "="*70)
            print("HOÀN THÀNH PHẦN PHÂN TÍCH")
            print("="*70)
            print("\n[*] Đã khôi phục khóa bí mật nhưng không giải mã được flag")
            print(f"[*] Khóa: {private_key}")
            print("[!] Thử thách cần tham số ECDSA hợp lệ để giải mã flag")


def main():
    """Entry point chính"""
    solver = EllipticNightmareSolver()
    solver.run()


if __name__ == "__main__":
    main()
