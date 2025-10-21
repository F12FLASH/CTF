#!/usr/bin/env python3

import crypto_extension
import time
import random
import sys

def obfuscated_print(text, delay=0.03):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(random.uniform(delay/2, delay*2))
    print()

def fake_operations():
    operations = [
        "Initializing cryptographic core...",
        "Loading fragmented key modules...", 
        "Activating self-modification routines...",
        "Setting up anti-analysis protections...",
        "Generating entropy sources...",
        "Validating execution environment...",
        "Preparing encryption pipeline...",
        "Configuring memory protection...",
        "Initializing obfuscation layers...",
        "Starting main sequence..."
    ]
    
    for op in operations:
        obfuscated_print(f"[+] {op}", 0.05)
        time.sleep(0.2)

def main():
    print("=" * 60)
    obfuscated_print("    🐍 O U R O B O R O S  -  Advanced RE Challenge")
    print("=" * 60)
    obfuscated_print("    Self-Modifying Code • Fragmented AES • Anti-Debug")
    obfuscated_print("    Difficulty: ⭐⭐⭐⭐⭐ (Extreme)")
    print()
    
    fake_operations()
    print()
    
    # The actual flag
    flag = "VNFLAG{TOQUOC_VIETNAM_UNG_HO_NHAN_DAT_#TQVN_9a3F6b2Kx4P1R8L0zQ7Y5s}"
    
    obfuscated_print("[*] Beginning flag encryption process...")
    time.sleep(1)
    
    try:
        # This will trigger anti-debug and self-modification
        encrypted_flag = crypto_extension.encrypt_flag(flag)
        
        obfuscated_print(f"[*] Encrypted Flag: {encrypted_flag}")
        print()
        
        obfuscated_print("[!] Security Features Active:")
        obfuscated_print("    • 10-Way Key Fragmentation")
        obfuscated_print("    • Runtime Self-Modification") 
        obfuscated_print("    • Advanced Anti-Debugging")
        obfuscated_print("    • Code Integrity Verification")
        obfuscated_print("    • Timing Attack Protection")
        print()
        
        obfuscated_print("[*] Challenge initialized successfully!")
        obfuscated_print("[*] Use dynamic analysis to extract key fragments from memory")
        obfuscated_print("[*] Flag format: VNFLAG{...}")
        
    except Exception as e:
        obfuscated_print(f"[!] Security violation detected: {e}")
        obfuscated_print("[!] Debugger or analysis tool detected!")
    
    print("=" * 60)

if __name__ == "__main__":
    main()