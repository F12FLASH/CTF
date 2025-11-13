"""
Tiện ích mã hóa và bảo mật cho Elliptic Nightmare
Cung cấp các hàm mã hóa flag và xác thực dữ liệu
"""

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json


class FlagEncryption:
    """Hệ thống mã hóa flag an toàn với nhiều lớp bảo vệ"""
    
    def __init__(self, master_password: str):
        """
        Khởi tạo hệ thống mã hóa
        
        Args:
            master_password: Mật khẩu chính để mã hóa flag
        """
        self.master_password = master_password
    
    def encrypt_flag(self, flag: str, private_key: int) -> dict:
        """
        Mã hóa flag với nhiều lớp bảo mật
        
        Args:
            flag: Cờ cần mã hóa
            private_key: Khóa bí mật ECDSA để làm seed
            
        Returns:
            Dict chứa dữ liệu mã hóa và metadata
        """
        salt = get_random_bytes(32)
        iv = get_random_bytes(16)
        
        key_seed = f"{self.master_password}:{private_key}"
        key = PBKDF2(key_seed, salt, dkLen=32, count=100000)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        flag_bytes = flag.encode('utf-8')
        encrypted = cipher.encrypt(pad(flag_bytes, AES.block_size))
        
        obfuscated = self._obfuscate_data(encrypted)
        
        return {
            'data': base64.b64encode(obfuscated).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'checksum': SHA256.new(flag_bytes).hexdigest()
        }
    
    def decrypt_flag(self, encrypted_data: dict, private_key: int) -> str:
        """
        Giải mã flag sau khi giải thành công thử thách
        
        Args:
            encrypted_data: Dữ liệu mã hóa từ encrypt_flag
            private_key: Khóa bí mật đã khôi phục
            
        Returns:
            Flag gốc nếu khóa đúng
            
        Raises:
            ValueError: Nếu khóa không đúng hoặc dữ liệu bị hỏng
        """
        try:
            salt = base64.b64decode(encrypted_data['salt'])
            iv = base64.b64decode(encrypted_data['iv'])
            obfuscated = base64.b64decode(encrypted_data['data'])
            
            encrypted = self._deobfuscate_data(obfuscated)
            
            key_seed = f"{self.master_password}:{private_key}"
            key = PBKDF2(key_seed, salt, dkLen=32, count=100000)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            
            flag = decrypted.decode('utf-8')
            
            checksum = SHA256.new(decrypted).hexdigest()
            if checksum != encrypted_data['checksum']:
                raise ValueError("Checksum không khớp - dữ liệu bị hỏng")
            
            return flag
            
        except Exception as e:
            raise ValueError(f"Giải mã thất bại: {str(e)}")
    
    def _obfuscate_data(self, data: bytes) -> bytes:
        """Làm rối dữ liệu để khó reverse engineer"""
        obfuscated = bytearray(data)
        for i in range(len(obfuscated)):
            obfuscated[i] ^= ((i * 13 + 37) % 256)
        return bytes(obfuscated)
    
    def _deobfuscate_data(self, data: bytes) -> bytes:
        """Khôi phục dữ liệu đã làm rối"""
        return self._obfuscate_data(data)


def validate_challenge_parameters(params: dict) -> tuple[bool, str]:
    """
    Xác thực tính hợp lệ của tham số thử thách
    
    Args:
        params: Dict chứa các tham số thử thách
        
    Returns:
        (is_valid, error_message)
    """
    required_fields = ['n', 'a', 'b', 'G', 'order', 'signature', 'k_leak']
    
    for field in required_fields:
        if field not in params:
            return False, f"Thiếu tham số bắt buộc: {field}"
    
    if params['n'] <= 0:
        return False, "Modulus n phải là số dương"
    
    if params['order'] <= 0:
        return False, "Order phải là số dương"
    
    if not isinstance(params['G'], tuple) or len(params['G']) != 2:
        return False, "G phải là tuple (x, y)"
    
    if not isinstance(params['signature'], tuple) or len(params['signature']) != 2:
        return False, "Signature phải là tuple (r, s)"
    
    r, s = params['signature']
    if r <= 0 or s <= 0:
        return False, "Signature (r, s) phải là số dương"
    
    if params['k_leak'] < 0 or params['k_leak'] >= 4:
        return False, "k_leak phải nằm trong khoảng [0, 3]"
    
    return True, ""


def create_secure_challenge_file(params: dict, encrypted_flag: dict, output_file: str):
    """
    Tạo file thử thách với flag đã được mã hóa an toàn
    
    Args:
        params: Tham số thử thách
        encrypted_flag: Flag đã mã hóa
        output_file: Đường dẫn file đầu ra
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"n = {params['n']}\n")
        f.write(f"a = {params['a']}\n")
        f.write(f"b = {params['b']}\n")
        f.write(f"G = {params['G']}\n")
        f.write(f"order = {params['order']}\n")
        f.write(f"public_key = {params.get('public_key', (0, 0))}\n")
        f.write(f"message = '{params.get('message', 'Get the flag!')}'\n")
        f.write(f"signature = {params['signature']}\n")
        f.write(f"k_leak (2 LSB) = {params['k_leak']}\n")
        f.write(f"\n# Encrypted Flag (Only decryptable with correct private key)\n")
        f.write(f"encrypted_flag = {json.dumps(encrypted_flag)}\n")
        
        if 'p' in params and 'q' in params:
            f.write(f"\n# Debug Info (for testing)\n")
            f.write(f"# p = {params['p']}\n")
            f.write(f"# q = {params['q']}\n")
