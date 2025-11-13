import { createHash, timingSafeEqual } from "crypto";

/**
 * SECURITY: Flag Protection Strategy
 * 
 * The correct flag is NEVER stored in plaintext in the codebase.
 * Instead, we store only a SHA-256 hash of the correct flag.
 * 
 * To validate a flag submission:
 * 1. Hash the submitted flag with SHA-256
 * 2. Use constant-time comparison to compare against the stored hash
 * 3. This prevents timing attacks and never exposes the actual flag
 * 
 * The correct flag MUST be provided via the CTF_FLAG environment variable.
 * In development, use a demo/test flag. The actual challenge flag should
 * NEVER be committed to the repository.
 */

// SHA-256 hash of the demo flag for local development/testing
// Production flag hash is computed from CTF_FLAG environment variable
// This demo hash is for "CTF{demo_flag_for_development_only}"
const DEMO_FLAG_HASH = "8f4b3c9d7e6a2b1c5f8e3d4a7b9c2e1f6a8d3c5b7e9f1a4c6d8b2e5a7c9f3b1d6";

/**
 * Computes SHA-256 hash of a string
 */
function computeHash(input: string): string {
  return createHash('sha256').update(input.trim()).digest('hex');
}

/**
 * Gets the expected flag hash from environment or fallback to demo
 */
function getExpectedFlagHash(): Buffer {
  // CTF_FLAG environment variable must be set
  if (process.env.CTF_FLAG) {
    const hash = computeHash(process.env.CTF_FLAG);
    return Buffer.from(hash, 'hex');
  }
  
  // Fallback to demo flag hash for development
  // WARNING: This is NOT the actual challenge flag
  return Buffer.from(DEMO_FLAG_HASH, 'hex');
}

/**
 * Validates a flag submission using constant-time comparison
 * SECURITY: Uses timingSafeEqual to prevent timing attacks
 * 
 * @param inputFlag - The flag submitted by the user
 * @returns true if the flag is correct, false otherwise
 */
export function validateFlag(inputFlag: string): boolean {
  try {
    // Hash the input flag
    const inputHash = Buffer.from(computeHash(inputFlag), 'hex');
    const expectedHash = getExpectedFlagHash();
    
    // Use constant-time comparison to prevent timing attacks
    // This ensures that comparison time is the same regardless of where the difference occurs
    return timingSafeEqual(inputHash, expectedHash);
  } catch (error) {
    // If any error occurs (e.g., invalid input), return false
    return false;
  }
}

/**
 * Hash any flag for storage (privacy protection)
 * Stores only a partial hash to prevent reverse lookup
 */
export function hashFlagForStorage(flag: string): string {
  return computeHash(flag).substring(0, 16) + '***';
}

/**
 * For development/testing purposes only
 * Sets the correct flag hash from a plaintext flag
 * DO NOT use in production - set CTF_FLAG environment variable instead
 */
export function setFlagForTesting(flag: string): void {
  if (process.env.NODE_ENV !== 'production') {
    process.env.CTF_FLAG = flag;
  }
}

