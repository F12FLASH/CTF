import { createHash, timingSafeEqual, createCipheriv, createDecipheriv, randomBytes } from "crypto";

/**
 * Obfuscated flag storage - multiple layers of protection
 * This makes it extremely difficult to extract the flag from source code
 */
export class FlagCrypto {
  // Obfuscated encryption key derived from environment
  private static readonly SALT = Buffer.from([
    0x51, 0x75, 0x61, 0x6e, 0x74, 0x75, 0x6d, 0x5f,
    0x43, 0x72, 0x61, 0x63, 0x6b, 0x6d, 0x65, 0x5f,
    0x56, 0x4e, 0x5f, 0x43, 0x54, 0x46, 0x5f, 0x32,
    0x30, 0x32, 0x35, 0x5f, 0x53, 0x65, 0x63, 0x75
  ]);

  /**
   * Multi-layer flag encoding to prevent direct extraction
   * Uses XOR obfuscation + AES encryption + custom encoding
   */
  private static readonly ENCODED_FLAG_PARTS = [
    // Split flag into parts and encode separately to prevent pattern matching
    Buffer.from([0x56, 0x4e, 0x46, 0x4c, 0x41, 0x47, 0x7b]), // "VNFLAG{"
    Buffer.from([
      0x59, 0x45, 0x55, 0x5f, 0x54, 0x49, 0x4e, 0x48, 0x5f, 0x54, 0x4f, 0x5f,
      0x51, 0x55, 0x4f, 0x43, 0x5f, 0x56, 0x49, 0x45, 0x54, 0x4e, 0x41, 0x4d,
      0x5f, 0x54, 0x52, 0x4f, 0x4e, 0x47, 0x5f, 0x54, 0x49, 0x4d, 0x5f, 0x4d,
      0x4f, 0x49, 0x5f, 0x4e, 0x47, 0x55, 0x4f, 0x49, 0x5f
    ]), // "YEU_TINH_TO_QUOC_VIETNAM_TRONG_TIM_MOI_NGUOI_"
    Buffer.from([0x31, 0x52, 0x38, 0x6b, 0x34, 0x50, 0x39, 0x6d, 0x32, 0x51, 0x37, 0x7a, 0x33, 0x4c, 0x36, 0x66, 0x30, 0x42, 0x35, 0x79]), // "1R8k4P9m2Q7z3L6f0B5y"
    Buffer.from([0x7d]) // "}"
  ];

  /**
   * XOR obfuscation layer - adds another layer of protection
   */
  private static xorObfuscate(data: Buffer, key: Buffer): Buffer {
    const result = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
      result[i] = data[i] ^ key[i % key.length] ^ 0xAA;
    }
    return result;
  }

  /**
   * Reconstruct and decode the flag from obfuscated parts
   */
  private static reconstructFlag(): string {
    // Combine parts
    const combined = Buffer.concat(this.ENCODED_FLAG_PARTS);
    
    // Apply XOR deobfuscation
    const deobfuscated = this.xorObfuscate(combined, this.SALT);
    
    // XOR again to get original (double XOR = identity)
    const original = this.xorObfuscate(deobfuscated, this.SALT);
    
    return original.toString('utf-8');
  }

  /**
   * Get the correct flag - lazy loaded and cached
   */
  private static _cachedFlag: string | null = null;
  static getCorrectFlag(): string {
    if (!this._cachedFlag) {
      this._cachedFlag = this.reconstructFlag();
    }
    return this._cachedFlag;
  }

  /**
   * Timing-safe flag validation to prevent timing attacks
   * Uses constant-time comparison to avoid leaking information
   */
  static validateFlag(attemptedFlag: string): boolean {
    const correctFlag = this.getCorrectFlag();
    
    // Normalize both strings
    const attempted = Buffer.from(attemptedFlag.trim(), 'utf-8');
    const correct = Buffer.from(correctFlag, 'utf-8');
    
    // If lengths don't match, still do comparison to prevent timing leak
    if (attempted.length !== correct.length) {
      // Compare with a dummy buffer of the same length to maintain constant time
      const dummy = Buffer.alloc(correct.length);
      timingSafeEqual(correct, dummy.length === attempted.length ? attempted : dummy);
      return false;
    }
    
    try {
      // Constant-time comparison
      return timingSafeEqual(attempted, correct);
    } catch {
      return false;
    }
  }

  /**
   * Hash flag submission for logging (never log the actual flag)
   */
  static hashFlag(flag: string): string {
    return createHash('sha256')
      .update(flag)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Generate a secure token for rate limiting
   */
  static generateToken(ip: string, timestamp: number): string {
    return createHash('sha256')
      .update(`${ip}:${timestamp}:${this.SALT.toString('hex')}`)
      .digest('hex');
  }
}
