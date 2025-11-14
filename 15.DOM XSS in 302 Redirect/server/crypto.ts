import { createCipheriv, createDecipheriv, randomBytes, createHash } from "crypto";

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

function getEncryptionKey(): Buffer {
  const secret = process.env.FLAG_ENCRYPTION_KEY || "default-dev-key-change-in-production-32chars";
  
  if (process.env.NODE_ENV === 'production' && !process.env.FLAG_ENCRYPTION_KEY) {
    console.warn("WARNING: Using default encryption key in production. Set FLAG_ENCRYPTION_KEY environment variable!");
  }
  
  return createHash("sha256").update(secret).digest();
}

export function encryptFlag(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = randomBytes(IV_LENGTH);
  
  const cipher = createCipheriv(ALGORITHM, key, iv);
  
  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");
  
  const authTag = cipher.getAuthTag();
  
  const combined = iv.toString("hex") + encrypted + authTag.toString("hex");
  
  return combined;
}

export function decryptFlag(ciphertext: string): string {
  try {
    const key = getEncryptionKey();
    
    const iv = Buffer.from(ciphertext.substring(0, IV_LENGTH * 2), "hex");
    
    const authTag = Buffer.from(
      ciphertext.substring(ciphertext.length - AUTH_TAG_LENGTH * 2),
      "hex"
    );
    
    const encrypted = ciphertext.substring(
      IV_LENGTH * 2,
      ciphertext.length - AUTH_TAG_LENGTH * 2
    );
    
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    
    return decrypted;
  } catch (error) {
    throw new Error("Failed to decrypt flag");
  }
}

export function hashCookie(cookie: string): string {
  return createHash("sha256").update(cookie).digest("hex");
}
