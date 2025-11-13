import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || createHash('sha256')
  .update('stackless-stack-encryption-key-dev-secret')
  .digest();

export function encryptFlag(flag: string): { encrypted: string; iv: string; authTag: string } {
  const iv = randomBytes(16);
  const cipher = createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  
  let encrypted = cipher.update(flag, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
}

export function decryptFlag(encrypted: string, iv: string, authTag: string): string {
  const decipher = createDecipheriv(
    ALGORITHM,
    ENCRYPTION_KEY,
    Buffer.from(iv, 'hex')
  );
  
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

export function obfuscateFlag(flag: string): string {
  const parts = flag.split('');
  let obfuscated = '';
  
  for (let i = 0; i < parts.length; i++) {
    if (i % 3 === 0 && i > 0 && i < parts.length - 1) {
      obfuscated += '*';
    } else {
      obfuscated += parts[i];
    }
  }
  
  return obfuscated;
}
