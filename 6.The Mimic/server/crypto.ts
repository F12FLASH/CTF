import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const SALT_LENGTH = 64;

export class SecureFlagManager {
  private masterKey: Buffer;
  
  constructor() {
    const envKey = process.env.FLAG_ENCRYPTION_KEY;
    
    if (!envKey) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error(
          'FLAG_ENCRYPTION_KEY environment variable is required in production. ' +
          'Set it to a strong random key (e.g., 64+ character random string).'
        );
      }
      console.warn(
        '⚠️  WARNING: Using development-only random key. ' +
        'Set FLAG_ENCRYPTION_KEY environment variable for production.'
      );
      this.masterKey = randomBytes(32);
    } else {
      this.masterKey = this.deriveKey(envKey);
    }
  }
  
  private deriveKey(password: string): Buffer {
    return createHash('sha256')
      .update(password)
      .digest();
  }
  
  encryptFlag(flag: string): string {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.masterKey, iv);
    
    let encrypted = cipher.update(flag, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return JSON.stringify({
      iv: iv.toString('hex'),
      encrypted,
      tag: tag.toString('hex')
    });
  }
  
  decryptFlag(encryptedData: string): string {
    const { iv, encrypted, tag } = JSON.parse(encryptedData);
    
    const decipher = createDecipheriv(
      ALGORITHM,
      this.masterKey,
      Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
  
  hashFlag(flag: string): string {
    return createHash('sha256')
      .update(flag.trim())
      .digest('hex');
  }
  
  verifyFlag(submittedFlag: string, correctFlagHash: string): boolean {
    const submittedHash = this.hashFlag(submittedFlag);
    return submittedHash === correctFlagHash;
  }
}

export function xorEncrypt(text: string, key: string): string {
  let result = "";
  for (let i = 0; i < text.length; i++) {
    const charCode = text.charCodeAt(i) ^ key.charCodeAt(i % key.length);
    result += String.fromCharCode(charCode);
  }
  return Buffer.from(result).toString("base64");
}

export function xorDecrypt(encrypted: string, key: string): string {
  const decoded = Buffer.from(encrypted, "base64").toString();
  let result = "";
  for (let i = 0; i < decoded.length; i++) {
    const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length);
    result += String.fromCharCode(charCode);
  }
  return result;
}

export function generateKey(length: number = 32): string {
  return randomBytes(length).toString('hex').substring(0, length);
}

export function sanitizeInput(input: string, maxLength: number = 1000): string {
  return input.trim().substring(0, maxLength);
}
