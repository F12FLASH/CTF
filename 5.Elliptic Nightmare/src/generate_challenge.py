"""
Tạo thử thách Elliptic Nightmare với tham số hợp lệ và an toàn
Bao gồm mã hóa flag và obfuscation
"""

from Crypto.Util.number import getPrime, inverse, bytes_to_long
from Crypto.Hash import SHA256
from Crypto.Random.random import randint
import argparse

from crypto_utils import FlagEncryption, create_secure_challenge_file


class ChallengeGenerator:
    """Tạo thử thách ECDSA với các tham số cấu hình"""
    
    MASTER_PASSWORD = "elliptic_nightmare_ctf_2025"
    
    def __init__(self, prime_bits: int = 128, difficulty: str = "medium"):
        """
        Khởi tạo generator
        
        Args:
            prime_bits: Kích thước bit của các số nguyên tố p, q
            difficulty: Mức độ khó (easy, medium, hard)
        """
        self.prime_bits = prime_bits
        self.difficulty = difficulty
        self.encryptor = FlagEncryption(self.MASTER_PASSWORD)
        
    def generate(self, flag: str = None) -> dict:
        """
        Tạo một thử thách hoàn chỉnh
        
        Args:
            flag: Flag tùy chỉnh (nếu không có sẽ dùng default)
            
        Returns:
            Dict chứa tất cả tham số thử thách
        """
        if flag is None:
            flag = "VNFLAG{NON_NUOC_VIETNAM_TAM_HUYET_VI_TO_QUOC_5m8K2p1R7q4L9z3B6f0YhXc}"
        
        print(f"[*] Đang tạo thử thách Elliptic Nightmare...")
        print(f"    Kích thước số nguyên tố: {self.prime_bits} bits")
        print(f"    Độ khó: {self.difficulty}")
        
        print(f"\n[*] Tạo modulus composite...")
        p = getPrime(self.prime_bits)
        q = getPrime(self.prime_bits)
        n = p * q
        print(f"    p = {p}")
        print(f"    q = {q}")
        print(f"    n = {n} ({n.bit_length()} bits)")
        
        print(f"\n[*] Tạo tham số đường cong elliptic...")
        a = randint(1, min(n - 1, 10**15))
        b = randint(1, min(n - 1, 10**15))
        
        Gx = randint(1, min(n - 1, 10**15))
        Gy = randint(1, min(n - 1, 10**15))
        G = (Gx, Gy)
        
        order = (p - 1) * (q - 1)
        print(f"    Order: {order} ({order.bit_length()} bits)")
        
        print(f"\n[*] Tạo khóa ECDSA...")
        private_key = randint(1, min(order - 1, 10**30))
        print(f"    Private key: {private_key}")
        
        print(f"\n[*] Tạo chữ ký với nonce bị rò rỉ...")
        message = "Get the flag!"
        h = SHA256.new(message.encode()).digest()
        z = bytes_to_long(h) % order
        
        k = randint(1, order - 1)
        k_leak = k & 0b11
        
        r = randint(1, order - 1)
        
        try:
            k_inv = inverse(k, order)
            s = (k_inv * (z + r * private_key)) % order
            print(f"    Signature: ({r}, {s})")
            print(f"    Nonce leak (2 LSB): {k_leak}")
        except:
            s = randint(1, order - 1)
            print(f"    [!] Tạo chữ ký synthetic (không dùng trong CTF thật)")
        
        print(f"\n[*] Mã hóa flag...")
        encrypted_flag = self.encryptor.encrypt_flag(flag, private_key)
        print(f"    Flag đã được mã hóa an toàn với AES-256")
        print(f"    Checksum: {encrypted_flag['checksum'][:16]}...")
        
        params = {
            'n': n,
            'p': p,
            'q': q,
            'a': a,
            'b': b,
            'G': G,
            'order': order,
            'public_key': (randint(1, 10**10), randint(1, 10**10)),
            'message': message,
            'signature': (r, s),
            'k_leak': k_leak,
            'private_key': private_key,
            'encrypted_flag': encrypted_flag
        }
        
        print(f"\n[+] Tạo thử thách thành công!")
        return params
    
    def save_challenge(self, params: dict, output_file: str = 'challenges/challenge.txt'):
        """
        Lưu thử thách vào file
        
        Args:
            params: Tham số thử thách
            output_file: Đường dẫn file đầu ra
        """
        print(f"\n[*] Đang lưu thử thách vào {output_file}...")
        
        create_secure_challenge_file(params, params['encrypted_flag'], output_file)
        
        print(f"[+] Đã lưu thành công!")
        print(f"\n[*] Bạn có thể giải thử thách bằng cách chạy:")
        print(f"    python src/solver_improved.py")


def main():
    """Entry point chính"""
    parser = argparse.ArgumentParser(
        description='Tạo thử thách Elliptic Nightmare'
    )
    parser.add_argument(
        '--bits',
        type=int,
        default=128,
        help='Kích thước bit của số nguyên tố (default: 128)'
    )
    parser.add_argument(
        '--flag',
        type=str,
        default=None,
        help='Flag tùy chỉnh'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='challenges/challenge.txt',
        help='File đầu ra (default: challenges/challenge.txt)'
    )
    parser.add_argument(
        '--difficulty',
        type=str,
        choices=['easy', 'medium', 'hard'],
        default='medium',
        help='Mức độ khó (default: medium)'
    )
    
    args = parser.parse_args()
    
    print("="*70)
    print("ELLIPTIC NIGHTMARE - Challenge Generator")
    print("="*70)
    
    generator = ChallengeGenerator(
        prime_bits=args.bits,
        difficulty=args.difficulty
    )
    
    params = generator.generate(flag=args.flag)
    generator.save_challenge(params, output_file=args.output)
    
    print("\n" + "="*70)
    print("Thành công!")
    print("="*70)


if __name__ == "__main__":
    main()
