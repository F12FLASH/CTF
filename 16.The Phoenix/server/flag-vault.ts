import crypto from "crypto";

const ACTUAL_FLAG = "VNFLAG{CHIEN_CONG_VA_DOAN_KET_VI_TUONG_LAI_VIET_6P2r9K1m4Q8z3L7f0B5yXcG}";

const OBFUSCATION_LAYERS = [
  (s: string) => Buffer.from(s).toString("base64"),
  (s: string) => s.split("").reverse().join(""),
  (s: string) => Buffer.from(s, "utf8").toString("hex"),
  (s: string) => s.split("").map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ (i % 256))).join(""),
];

export function encryptFlag(flag: string): string {
  let encrypted = flag;
  for (const layer of OBFUSCATION_LAYERS) {
    encrypted = layer(encrypted);
  }
  return encrypted;
}

export function decryptFlag(encrypted: string): string {
  let decrypted = encrypted;
  
  decrypted = decrypted.split("").map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ (i % 256))).join("");
  
  decrypted = Buffer.from(decrypted, "hex").toString("utf8");
  
  decrypted = decrypted.split("").reverse().join("");
  
  decrypted = Buffer.from(decrypted, "base64").toString("utf8");
  
  return decrypted;
}

export function getEncryptedFlag(): string {
  return encryptFlag(ACTUAL_FLAG);
}

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

export function validateFlag(submittedFlag: string): boolean {
  let normalizedSubmitted = submittedFlag;
  
  normalizedSubmitted = normalizedSubmitted.replace(/[\u200B-\u200D\uFEFF]/g, '');
  
  normalizedSubmitted = normalizedSubmitted.replace(/^`+|`+$/g, '');
  
  normalizedSubmitted = normalizedSubmitted.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  
  normalizedSubmitted = normalizedSubmitted.trim().toUpperCase();
  
  const normalizedActual = ACTUAL_FLAG.trim().toUpperCase();
  
  return constantTimeCompare(normalizedSubmitted, normalizedActual);
}

export function getActualFlag(): string {
  return ACTUAL_FLAG;
}

export function generateFlagHash(flag: string): string {
  return crypto.createHash("sha256").update(flag).digest("hex");
}
