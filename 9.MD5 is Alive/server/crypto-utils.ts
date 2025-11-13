import { createCipheriv, createDecipheriv, randomBytes, scrypt } from "crypto";
import { promisify } from "util";

const scryptAsync = promisify(scrypt);

const ALGORITHM = "aes-256-gcm";
const SALT_LENGTH = 16;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

/**
 * Derives a cryptographic key from a password using scrypt
 */
async function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return (await scryptAsync(password, salt, KEY_LENGTH)) as Buffer;
}

/**
 * Encrypts data using AES-256-GCM
 * Returns: salt:iv:authTag:encryptedData (all base64 encoded)
 */
export async function encrypt(plaintext: string, password: string): Promise<string> {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = await deriveKey(password, salt);
  
  const cipher = createCipheriv(ALGORITHM, key, iv);
  
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");
  
  const authTag = cipher.getAuthTag();
  
  return [
    salt.toString("base64"),
    iv.toString("base64"),
    authTag.toString("base64"),
    encrypted,
  ].join(":");
}

/**
 * Decrypts data encrypted with encrypt()
 */
export async function decrypt(encryptedData: string, password: string): Promise<string> {
  const parts = encryptedData.split(":");
  
  if (parts.length !== 4) {
    throw new Error("Invalid encrypted data format");
  }
  
  const [saltB64, ivB64, authTagB64, encryptedB64] = parts;
  
  const salt = Buffer.from(saltB64, "base64");
  const iv = Buffer.from(ivB64, "base64");
  const authTag = Buffer.from(authTagB64, "base64");
  const key = await deriveKey(password, salt);
  
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encryptedB64, "base64", "utf8");
  decrypted += decipher.final("utf8");
  
  return decrypted;
}

/**
 * Obfuscates a string by XOR with a repeating key pattern
 * This is for additional obfuscation, not cryptographic security
 */
export function obfuscate(data: string, key: string): string {
  const obfuscated = Buffer.from(data, "utf8").map((byte, i) => {
    return byte ^ key.charCodeAt(i % key.length);
  });
  return obfuscated.toString("base64");
}

/**
 * Deobfuscates data obfuscated with obfuscate()
 * Validates the output before returning
 */
export function deobfuscate(obfuscatedData: string, key: string): string {
  try {
    const buffer = Buffer.from(obfuscatedData, "base64");
    const deobfuscated = buffer.map((byte, i) => {
      return byte ^ key.charCodeAt(i % key.length);
    });
    
    const result = deobfuscated.toString("utf8");
    
    if (!result || result.length === 0) {
      throw new Error("Deobfuscation produced empty result");
    }
    
    return result;
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Deobfuscation failed: ${error.message}`);
    }
    throw new Error("Deobfuscation failed with unknown error");
  }
}

/**
 * Generates a random encryption key
 */
export function generateEncryptionKey(): string {
  const bytes = randomBytes(32);
  return bytes.toString("hex");
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}
