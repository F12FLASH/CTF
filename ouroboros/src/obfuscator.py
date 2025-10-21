#!/usr/bin/env python3

import random
import struct
import hashlib

class Obfuscator:
    def __init__(self):
        self.magic_constants = [
            0xDEADBEEF, 0xCAFEBABE, 0x0D15EA5E, 0xBAADF00D,
            0x12345678, 0x87654321, 0xABCDEF01, 0xFEDCBA98
        ]
    
    def generate_obfuscated_flag(self):
        flag = "VNFLAG{TOQUOC_VIETNAM_UNG_HO_NHAN_DAT_#TQVN_9a3F6b2Kx4P1R8L0zQ7Y5s}"
        
        # Multiple layers of obfuscation
        obfuscated = self._layer1_xor(flag)
        obfuscated = self._layer2_shift(obfuscated)
        obfuscated = self._layer3_hash(obfuscated)
        
        return obfuscated
    
    def _layer1_xor(self, data):
        result = bytearray()
        key = self.magic_constants[0] & 0xFF
        for char in data.encode():
            result.append(char ^ key)
            key = (key * 3 + 7) % 256
        return bytes(result)
    
    def _layer2_shift(self, data):
        result = bytearray()
        for i, byte in enumerate(data):
            shift = (i % 7) + 1
            result.append(((byte << shift) | (byte >> (8 - shift))) & 0xFF)
        return bytes(result)
    
    def _layer3_hash(self, data):
        # Use hash as seed for further obfuscation
        hash_obj = hashlib.sha256(data)
        return hash_obj.digest()

def generate_flag():
    obf = Obfuscator()
    return obf.generate_obfuscated_flag()

if __name__ == "__main__":
    flag = generate_flag()
    print(f"Obfuscated flag: {flag.hex()}")