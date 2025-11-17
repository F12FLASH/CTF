import { createCipheriv, createDecipheriv, randomBytes, scryptSync, createHash } from "crypto";

function sha256(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

const ENCRYPTION_KEY = process.env.FLAG_ENCRYPTION_KEY || "ONE_TIME_PAD_REVENGE_SECURE_KEY_2025";
const ALGORITHM = "aes-256-cbc";

let cachedDerivedKey: Buffer | null = null;

function getDerivedKey(): Buffer {
  if (cachedDerivedKey) {
    return cachedDerivedKey;
  }
  const salt = "ctf_otp_revenge_salt_2025";
  cachedDerivedKey = scryptSync(ENCRYPTION_KEY, salt, 32);
  return cachedDerivedKey;
}

export function encryptFlag(flag: string): string {
  const key = getDerivedKey();
  const iv = randomBytes(16);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  
  let encrypted = cipher.update(flag, "utf-8", "hex");
  encrypted += cipher.final("hex");
  
  return iv.toString("hex") + ":" + encrypted;
}

export function decryptFlag(encrypted: string): string {
  const key = getDerivedKey();
  const parts = encrypted.split(":");
  const iv = Buffer.from(parts[0], "hex");
  const encryptedText = parts[1];
  
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  let decrypted = decipher.update(encryptedText, "hex", "utf-8");
  decrypted += decipher.final("utf-8");
  
  return decrypted;
}

const ENCRYPTED_FLAG = "fd9d32e3f847c5fe747e685b29c83bed:8ae40d1524e6f458093fde431eafd003d9694e3aaed5722b32a5085d1711e223129110a62880c9f733c5c0d5ca6c57f63ebcb1e113a45b6e06bb7c13df1072cce5e9b27825d8d850ed2be58833066dff";

export function getExpectedFlag(): string {
  try {
    return decryptFlag(ENCRYPTED_FLAG);
  } catch (err) {
    console.error("CRITICAL: Failed to decrypt flag. Check FLAG_ENCRYPTION_KEY environment variable.");
    throw new Error("Flag decryption failed. Application cannot start without valid encryption key.");
  }
}

export function sanitizeInput(input: string, maxLength: number = 10000): string {
  if (typeof input !== "string") {
    throw new Error("Input must be a string");
  }
  
  if (input.length > maxLength) {
    throw new Error(`Input exceeds maximum length of ${maxLength}`);
  }
  
  return input.trim();
}

export function validateHexString(hex: string, options?: { minLength?: number; maxLength?: number }): boolean {
  if (typeof hex !== "string") return false;
  
  const cleanHex = hex.trim();
  
  if (!/^[0-9a-fA-F]+$/.test(cleanHex)) return false;
  if (cleanHex.length % 2 !== 0) return false;
  
  if (options?.minLength && cleanHex.length < options.minLength) return false;
  if (options?.maxLength && cleanHex.length > options.maxLength) return false;
  
  return true;
}

export function validateInteger(value: any, min?: number, max?: number): boolean {
  if (typeof value !== "number") return false;
  if (!Number.isInteger(value)) return false;
  if (min !== undefined && value < min) return false;
  if (max !== undefined && value > max) return false;
  return true;
}

export function generateChallengeData(): { plaintext: string; keyHash: string } {
  const flag = getExpectedFlag();
  
  const plaintextParts = [
    "This is the secret message encrypted with OTP ",
    "using key derived from flag. ",
    flag
  ];
  
  return {
    plaintext: plaintextParts.join(""),
    keyHash: sha256(flag)
  };
}

const requestTimestamps = new Map<string, number[]>();
const RATE_LIMIT_WINDOW = 60000;
const RATE_LIMIT_PER_ENDPOINT = 50;

export function checkRateLimit(ip: string, endpoint: string): boolean {
  const key = `${ip}:${endpoint}`;
  const now = Date.now();
  
  let timestamps = requestTimestamps.get(key) || [];
  timestamps = timestamps.filter(t => now - t < RATE_LIMIT_WINDOW);
  
  if (timestamps.length >= RATE_LIMIT_PER_ENDPOINT) {
    return false;
  }
  
  timestamps.push(now);
  requestTimestamps.set(key, timestamps);
  
  return true;
}

setInterval(() => {
  const now = Date.now();
  const entries = Array.from(requestTimestamps.entries());
  for (let i = 0; i < entries.length; i++) {
    const [key, timestamps] = entries[i];
    const filtered = timestamps.filter((t: number) => now - t < RATE_LIMIT_WINDOW);
    if (filtered.length === 0) {
      requestTimestamps.delete(key);
    } else {
      requestTimestamps.set(key, filtered);
    }
  }
}, RATE_LIMIT_WINDOW);
