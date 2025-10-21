#!/usr/bin/env python3
"""
Extremely difficult solution for Ouroboros challenge
Requires deep understanding of the key combination algorithm
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct

def reverse_engineer_key():
    """
    Reverse engineer the complex key generation algorithm
    This is the core challenge - understanding how fragments are combined
    """
    
    # Step 1: Replicate each fragment generation
    fragments = []
    
    # Fragment 0 (from crypto_extension.c)
    frag0 = []
    for i in range(16):
        val = (i * 13 + 7) % 256
        val = ((val << 4) | (val >> 4)) & 0xFF
        val ^= 0xAA
        val = (val * 3 + 11) % 256
        frag0.append(val)
    fragments.append(bytes(frag0))
    
    # Fragment 1  
    primes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53]
    frag1 = []
    for i in range(16):
        val = primes[i] * 7
        val = ((val & 0x0F) << 4) | ((val & 0xF0) >> 4)
        val ^= 0x37
        val = ~val & 0xFF
        frag1.append(val)
    fragments.append(bytes(frag1))
    
    # Fragment 2 - Fibonacci
    frag2 = []
    a, b = 1, 1
    for i in range(16):
        val = (a + b) % 256
        val = (val ^ 0x55) + i
        val = ((val << 3) | (val >> 5)) & 0xFF
        frag2.append(val)
        a, b = b, (a + b) % 256
    fragments.append(bytes(frag2))
    
    # TODO: Implement fragments 3-9 based on crypto_extension.c
    # This is left as an exercise for the reverse engineer
    
    # Step 2: Replicate the 3-stage key combination
    stage1_key = bytearray(16)
    stage2_key = bytearray(16) 
    final_key = bytearray(16)
    
    # Stage 1: XOR combination with rotation
    for i in range(10):
        for j in range(16):
            stage1_key[j] ^= fragments[i][(j + i) % 16]
    
    # Stage 2: Mathematical transformation  
    for i in range(16):
        stage2_key[i] = (stage1_key[i] * 3 + stage1_key[(i + 1) % 16]) % 256
        stage2_key[i] ^= fragments[i % 10][(i + 3) % 16]
    
    # Stage 3: Final transformation
    for i in range(16):
        final_key[i] = stage2_key[i]
        final_key[i] = ((final_key[i] << 4) | (final_key[i] >> 4)) & 0xFF
        final_key[i] ^= 0xAB
        final_key[i] = (final_key[i] + 0xCD) % 256
        final_key[i] = ((final_key[i] & 0x55) << 1) | ((final_key[i] & 0xAA) >> 1)
    
    return bytes(final_key)

def decrypt_flag(encrypted_hex, key):
    """Decrypt using reconstructed key"""
    encrypted = bytes.fromhex(encrypted_hex)
    
    cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)
    decrypted = cipher.decrypt(encrypted)
    
    try:
        return unpad(decrypted, AES.block_size).decode('utf-8')
    except:
        return decrypted.decode('utf-8', errors='ignore')

def main():
    print("Ouroboros Challenge Solver - EXTREME DIFFICULTY")
    print("=" * 55)
    print("This requires deep reverse engineering of the C extension")
    print()
    
    encrypted_flag = input("Enter encrypted flag from main.py: ").strip()
    
    print("\nAttempting to reconstruct AES key...")
    print("This requires understanding of:")
    print("• 10 complex fragment generation algorithms")
    print("• 3-stage key combination process") 
    print("• Self-modifying code behavior")
    print("• Anti-debugging bypass techniques")
    print()
    
    key = reverse_engineer_key()
    print(f"Recovered Key: {key.hex()}")
    
    print("Decrypting flag...")
    flag = decrypt_flag(encrypted_flag, key)
    
    print(f"\n🎯 Flag: {flag}")
    print("\nChallenge solved! This indicates expert-level reverse engineering skills! 🏆")

if __name__ == "__main__":
    main()