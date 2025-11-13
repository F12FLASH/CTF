#!/usr/bin/env python3
"""
Schrödinger's RSA - Interactive Challenge Interface
Master Level Cryptography CTF Challenge
"""

import os
import sys

def print_banner():
    """Display challenge banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║              🔐  SCHRÖDINGER'S RSA  🔐                       ║
    ║                                                               ║
    ║            Master Level Cryptography Challenge                ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    Welcome to Schrödinger's RSA!
    
    In this challenge, the RSA modulus exists in a quantum superposition.
    The primes p and q both exist and don't exist simultaneously.
    Can you unlock the mystery and decrypt the flag?
    
    """
    print(banner)

def display_menu():
    """Display main menu options"""
    menu = """
    ═══════════════════════════════════════════════════════════════
    CHALLENGE MENU
    ═══════════════════════════════════════════════════════════════
    
    1. 📖 View Challenge Description
    2. 🔑 View Public Key
    3. 📜 View Encrypted Flag
    4. 💡 View Hints (Suspicious!)
    5. 🧪 Test Your Flag
    6. 📊 Challenge Statistics
    7. 🔬 Run Solver (SPOILER WARNING!)
    8. ℹ️  About This Challenge
    9. 🚪 Exit
    
    ═══════════════════════════════════════════════════════════════
    """
    print(menu)

def view_description():
    """Display challenge description"""
    print("\n" + "="*70)
    print("CHALLENGE DESCRIPTION")
    print("="*70)
    print("""
You've intercepted an encrypted message using RSA encryption.

Given:
  • Public Key: (n, e) where n is allegedly p*q
  • Public Exponent: e = 65537
  • Encrypted Flag: c = pow(flag, e, n)

Your Task:
  Decrypt the encrypted flag and reveal the secret message.

The Twist:
  Just like Schrödinger's cat, the state of n is paradoxical.
  The primes p and q both exist and don't exist.
  Until you observe the true nature of n, you cannot decrypt.

Difficulty: 🔴 Master Hacker
Category: Cryptography
Points: 500
    """)
    input("\nPress Enter to continue...")

def view_public_key():
    """Display public key"""
    print("\n" + "="*70)
    print("PUBLIC KEY")
    print("="*70)
    if os.path.exists('public_key.txt'):
        with open('public_key.txt', 'r') as f:
            print(f.read())
    else:
        print("❌ Error: public_key.txt not found!")
        print("Please run: python challenge_generator.py")
    input("\nPress Enter to continue...")

def view_encrypted_flag():
    """Display encrypted flag"""
    print("\n" + "="*70)
    print("ENCRYPTED FLAG")
    print("="*70)
    if os.path.exists('encrypted_flag.txt'):
        with open('encrypted_flag.txt', 'r') as f:
            ciphertext = f.read().strip()
            print(f"\nCiphertext (c):\n{ciphertext}\n")
            print(f"Length: {len(ciphertext)} digits")
    else:
        print("❌ Error: encrypted_flag.txt not found!")
    input("\nPress Enter to continue...")

def view_hints():
    """Display hints file"""
    print("\n" + "="*70)
    print("HINTS (Be Careful - They Might Deceive You!)")
    print("="*70)
    if os.path.exists('hint.txt'):
        with open('hint.txt', 'r') as f:
            print(f.read())
    else:
        print("❌ Error: hint.txt not found!")
    input("\nPress Enter to continue...")

def run_solver():
    """Run the solver script"""
    print("\n" + "="*70)
    print("⚠️  SPOILER WARNING!")
    print("="*70)
    print("This will run the solver and reveal the solution.")
    choice = input("Are you sure you want to continue? (yes/no): ")
    
    if choice.lower() in ['yes', 'y']:
        print("\n")
        os.system('python solver.py')
    else:
        print("Solver cancelled. Keep trying on your own!")
    
    input("\nPress Enter to continue...")

def test_flag():
    """Allow user to test their flag solution"""
    print("\n" + "="*70)
    print("FLAG VERIFICATION")
    print("="*70)
    print()
    print("Enter your flag to verify if it's correct.")
    print("Format: VNFLAG{...}")
    print()
    
    flag_input = input("Your flag: ").strip()
    
    if not flag_input:
        print("\n❌ No flag entered!")
        input("\nPress Enter to continue...")
        return
    
    try:
        from challenge_data import _verify
        print("\nVerifying...")
        if _verify(flag_input):
            print("\n" + "="*70)
            print("🎉 CORRECT! CONGRATULATIONS! 🎉")
            print("="*70)
            print("\nYou have successfully solved Schrödinger's RSA!")
            print("You've proven that n is prime and exploited φ(n) = n - 1")
            print("\n✓ Challenge completed successfully!")
        else:
            print("\n❌ Incorrect flag. Keep trying!")
            print("\nHints:")
            print("  • Have you checked if n is actually prime?")
            print("  • If n is prime, what is φ(n)?")
            print("  • Remember: φ(prime) = prime - 1")
    except Exception as e:
        print(f"\n❌ Verification error: {e}")
    
    input("\nPress Enter to continue...")

def show_statistics():
    """Display challenge statistics"""
    print("\n" + "="*70)
    print("CHALLENGE STATISTICS")
    print("="*70)
    
    try:
        from challenge_data import _n, _e, _c
        import math
        
        n_bits = _n.bit_length()
        n_digits = len(str(_n))
        c_digits = len(str(_c))
        
        print(f"""
RSA Parameters:
  • Modulus (n): {n_bits} bits ({n_digits} decimal digits)
  • Public exponent (e): {_e}
  • Ciphertext (c): {c_digits} decimal digits
  
Security Level:
  • Bit strength: {n_bits} bits
  • Difficulty: 🔴 Master Hacker
  • Points: 500
  
Mathematical Properties:
  • n should be composite (p × q) in standard RSA
  • e is the standard RSA public exponent
  • This challenge has a twist... 🤔
  
Expected Solve Time:
  • Beginner: Several hours
  • Intermediate: 1-2 hours  
  • Expert: 30-60 minutes
  • Elite: 15-30 minutes
        """)
        
    except Exception as e:
        print(f"\n❌ Error loading statistics: {e}")
    
    input("\nPress Enter to continue...")

def about():
    """Display information about the challenge"""
    print("\n" + "="*70)
    print("ABOUT SCHRÖDINGER'S RSA")
    print("="*70)
    print("""
This challenge explores a quantum paradox in classical cryptography.

Mathematical Concept:
  Standard RSA assumes n = p × q (composite)
  But what if this fundamental assumption is wrong?
  
Educational Value:
  ✓ RSA fundamentals and Euler's totient function
  ✓ Cryptanalysis and testing assumptions
  ✓ Primality testing algorithms (Miller-Rabin)
  ✓ Mathematical properties of prime vs composite numbers
  ✓ Understanding φ(n) for different number types

Security Note:
  This is INTENTIONALLY BROKEN cryptography for education only!
  Never use a prime modulus in production RSA!

Why "Schrödinger"?
  Like Schrödinger's cat that is both alive and dead,
  the primes p and q both exist and don't exist.
  You must observe n's true nature to solve the puzzle!

References:
  • RSA Cryptosystem
  • Euler's Totient Function  
  • Miller-Rabin Primality Test

For full documentation, see README.md
    """)
    input("\nPress Enter to continue...")

def main():
    """Main program loop"""
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print_banner()
        display_menu()
        
        try:
            choice = input("Enter your choice (1-9): ").strip()
            
            if choice == '1':
                view_description()
            elif choice == '2':
                view_public_key()
            elif choice == '3':
                view_encrypted_flag()
            elif choice == '4':
                view_hints()
            elif choice == '5':
                test_flag()
            elif choice == '6':
                show_statistics()
            elif choice == '7':
                run_solver()
            elif choice == '8':
                about()
            elif choice == '9':
                print("\n👋 Thanks for playing! Good luck with the challenge!\n")
                sys.exit(0)
            else:
                print("\n❌ Invalid choice. Please enter 1-9.")
                input("Press Enter to continue...")
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!\n")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Error: {e}")
            input("Press Enter to continue...")

if __name__ == "__main__":
    if not os.path.exists('public_key.txt'):
        print("⚠️  Challenge files not found!")
        print("\nThis appears to be a fresh installation.")
        print("Challenge files should be pre-generated by CTF organizers.")
        print("\nIf you are a CTF organizer, run:")
        print("  cd admin_only && python challenge_generator.py")
        print("\nIf you are a participant, please download the complete challenge package.")
        sys.exit(1)
    
    main()
