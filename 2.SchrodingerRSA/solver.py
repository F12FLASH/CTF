#!/usr/bin/env python3
"""
Schrödinger's RSA Solver
Demonstrates the solution to the challenge
"""

from Crypto.Util.number import long_to_bytes, inverse

def is_prime(n, k=20):
    """
    Miller-Rabin primality test
    Uses k=20 rounds for cryptographic security
    Error probability: (1/4)^20 ≈ 10^-12
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    import random
    for i in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
        
        if (i + 1) % 5 == 0:
            print(f"  Testing round {i + 1}/{k}...", end='\r')
    
    print(" " * 40, end='\r')
    return True

def solve_challenge():
    """Solve the Schrödinger's RSA challenge"""
    
    print("=" * 70)
    print("Schrödinger's RSA Solver")
    print("=" * 70)
    print()
    
    try:
        with open('public_key.txt', 'r') as f:
            lines = f.readlines()
            n = int(lines[0].split('=')[1].strip())
            e = int(lines[1].split('=')[1].strip())
    except FileNotFoundError:
        print("❌ Error: public_key.txt not found!")
        print("Please ensure all challenge files are present.")
        return None
    except (IndexError, ValueError) as e:
        print(f"❌ Error: Invalid public key format - {e}")
        return None
    
    try:
        with open('encrypted_flag.txt', 'r') as f:
            c = int(f.read().strip())
    except FileNotFoundError:
        print("❌ Error: encrypted_flag.txt not found!")
        return None
    except ValueError as e:
        print(f"❌ Error: Invalid ciphertext format - {e}")
        return None
    
    print("[Step 1] Reading challenge parameters...")
    print(f"  n = {str(n)[:60]}... ({len(str(n))} digits)")
    print(f"  e = {e}")
    print(f"  c = {str(c)[:60]}... ({len(str(c))} digits)")
    print()
    
    print("[Step 2] Checking if the hint p and q are valid...")
    try:
        with open('hint.txt', 'r') as f:
            content = f.read()
            if 'False' in content:
                print("  ⚠ The hints show p * q ≠ n")
                print("  ⚠ Something is wrong with the standard RSA assumption!")
    except FileNotFoundError:
        print("  ℹ hint.txt not found, skipping hint validation...")
    print()
    
    print("[Step 3] Testing if n is prime (this is unusual for RSA)...")
    print("  Running primality test...")
    
    if is_prime(n):
        print("  🎯 BREAKTHROUGH: n is PRIME!")
        print("  🎯 This is not standard RSA where n = p * q (composite)")
        print()
        print("[Step 4] Exploiting the quantum paradox...")
        print("  In standard RSA: φ(n) = (p-1)(q-1)")
        print("  But if n is prime: φ(n) = n - 1")
        print()
        
        phi_n = n - 1
        print(f"  φ(n) = {str(phi_n)[:60]}...")
        print()
        
        print("[Step 5] Computing private exponent d...")
        d = inverse(e, phi_n)
        print(f"  d = e⁻¹ mod φ(n)")
        print(f"  d = {str(d)[:60]}...")
        print()
        
        print("[Step 6] Decrypting the flag...")
        m = pow(c, d, n)
        flag = long_to_bytes(m).decode()
        
        print("  " + "=" * 66)
        print(f"  🚩 FLAG RECOVERED: {flag}")
        print("  " + "=" * 66)
        print()
        
        print("[Step 7] Verifying with challenge data...")
        try:
            from challenge_data import _verify
            if _verify(flag):
                print("  ✓ Flag verified successfully!")
            else:
                print("  ✗ Flag verification failed")
        except:
            print("  ⚠ Verification module not available")
        
        return flag
    else:
        print("  ✗ n is not prime")
        print("  ✗ Standard RSA factorization approach needed")
        print("  ✗ This challenge requires a different insight...")
        return None

if __name__ == "__main__":
    try:
        flag = solve_challenge()
        if flag:
            print()
            print("Challenge solved successfully! 🎉")
    except FileNotFoundError as e:
        print(f"Error: Missing challenge file - {e}")
        print("Please run 'python challenge_generator.py' first to generate the challenge.")
    except Exception as e:
        print(f"Error during solving: {e}")
        import traceback
        traceback.print_exc()
