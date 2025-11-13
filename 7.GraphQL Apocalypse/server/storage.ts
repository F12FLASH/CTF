import bcrypt from 'bcrypt';
import { flagVault } from './crypto/flagVault';

export interface IStorage {
  getFlag(): Promise<string>;
  getUsers(): Promise<Array<{ id: string; username: string }>>;
  unlockSecretData(accessCode: string): Promise<{ flag: string } | null>;
  validateAccessCode(inputCode: string): Promise<boolean>;
}

const _0x4a2b = (s: string) => Buffer.from(s, 'base64').toString('utf-8');

export class MemStorage implements IStorage {
  private readonly _vault = flagVault;
  private readonly SECRET_ACCESS_CODE_HASH: string;
  private users: Array<{ id: string; username: string }>;
  private lastAttemptTime: number = 0;
  private attemptCount: number = 0;
  private readonly RATE_LIMIT_WINDOW = 60000;
  private readonly MAX_ATTEMPTS = 10;

  constructor() {
    const _ac = _0x4a2b('VFlQRV9DT05GVVNJT05fRVhQTE9JVA==');
    this.SECRET_ACCESS_CODE_HASH = bcrypt.hashSync(_ac, 10);
    
    this.users = [
      { id: "1", username: "admin" },
      { id: "2", username: "user" },
      { id: "3", username: "guest" },
    ];
  }

  async getFlag(): Promise<string> {
    return "[REDACTED - Access Denied]";
  }

  async getUsers(): Promise<Array<{ id: string; username: string }>> {
    return this.users;
  }

  async validateAccessCode(inputCode: string): Promise<boolean> {
    try {
      const now = Date.now();
      
      if (now - this.lastAttemptTime > this.RATE_LIMIT_WINDOW) {
        this.attemptCount = 0;
      }
      
      this.attemptCount++;
      this.lastAttemptTime = now;
      
      if (this.attemptCount > this.MAX_ATTEMPTS) {
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
      
      const isValid = await bcrypt.compare(inputCode, this.SECRET_ACCESS_CODE_HASH);
      
      if (isValid) {
        this.attemptCount = 0;
      }
      
      return isValid;
    } catch (error) {
      return false;
    }
  }

  async unlockSecretData(accessCode: string): Promise<{ flag: string } | null> {
    const isValid = await this.validateAccessCode(accessCode);
    
    if (isValid) {
      const decryptedFlag = this._vault.getFlag();
      return { flag: decryptedFlag };
    }
    
    return null;
  }
}

export const storage = new MemStorage();
