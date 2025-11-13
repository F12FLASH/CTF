import crypto from "crypto";
import bcrypt from "bcrypt";

const ENCRYPTION_KEY = process.env.FLAG_ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex");
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_ROUNDS = 12;

if (!process.env.FLAG_ENCRYPTION_KEY) {
  console.warn(
    "FLAG_ENCRYPTION_KEY not set. Using random key. Flags will be lost on restart. " +
    "Set FLAG_ENCRYPTION_KEY environment variable for production."
  );
}

export async function hashFlag(flag: string): Promise<string> {
  return await bcrypt.hash(flag, SALT_ROUNDS);
}

export async function verifyFlag(submittedFlag: string, flagHash: string): Promise<boolean> {
  return await bcrypt.compare(submittedFlag, flagHash);
}

export function encryptFlag(flag: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), "hex");
  
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  
  let encrypted = cipher.update(flag, "utf8", "hex");
  encrypted += cipher.final("hex");
  
  const authTag = cipher.getAuthTag();
  
  return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
}

export function decryptFlag(encryptedData: string): string {
  try {
    const parts = encryptedData.split(":");
    if (parts.length !== 3) {
      throw new Error("Invalid encrypted data format");
    }
    
    const [ivHex, authTagHex, encrypted] = parts;
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");
    const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), "hex");
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    
    return decrypted;
  } catch (error) {
    throw new Error("Failed to decrypt flag");
  }
}

export function generateRevealToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  
  return crypto.timingSafeEqual(bufA, bufB);
}
