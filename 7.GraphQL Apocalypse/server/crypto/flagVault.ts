import crypto from 'crypto';
import { config } from '../config';

interface FlagVaultConfig {
  ciphertext: string;
  key: string;
  salt: string;
}

class FlagVault {
  private static instance: FlagVault;
  private cachedFlag: string | null = null;
  private readonly config: FlagVaultConfig;

  private constructor() {
    this.config = {
      ciphertext: config.flagCiphertext,
      key: config.flagKey,
      salt: config.flagSalt,
    };
  }

  public static getInstance(): FlagVault {
    if (!FlagVault.instance) {
      FlagVault.instance = new FlagVault();
    }
    return FlagVault.instance;
  }

  private deriveKey(salt: string): Buffer {
    return crypto.pbkdf2Sync(
      this.config.key,
      salt,
      100000,
      32,
      'sha512'
    );
  }


  private decrypt(): string {
    try {
      const derivedKey = this.deriveKey(this.config.salt);
      const iv = crypto.createHash('sha256').update(this.config.salt).digest().slice(0, 16);
      
      const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);
      const encrypted = Buffer.from(this.config.ciphertext, 'base64');
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ]);
      
      return decrypted.toString('utf-8');
    } catch (error) {
      console.error('Flag vault decryption failed:', error);
      return '[VAULT_ERROR]';
    }
  }


  public getFlag(): string {
    if (this.cachedFlag) {
      return this.cachedFlag;
    }

    this.cachedFlag = this.decrypt();
    return this.cachedFlag;
  }

  public static encryptFlag(flag: string, key: string, salt: string): string {
    const derivedKey = crypto.pbkdf2Sync(key, salt, 100000, 32, 'sha512');
    const iv = crypto.createHash('sha256').update(salt).digest().slice(0, 16);
    
    const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(flag)),
      cipher.final()
    ]);
    
    return encrypted.toString('base64');
  }
}

export const flagVault = FlagVault.getInstance();
export { FlagVault };
