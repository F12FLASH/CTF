import type { HashResult, ChallengeStats } from "@shared/schema";

export interface IStorage {
  addHashQuery(input: string, fullHash: string, first4Bytes: string): Promise<HashResult>;
  getStats(): Promise<ChallengeStats>;
  incrementAttempts(): Promise<void>;
  markAsSolved(): Promise<void>;
}

export class MemStorage implements IStorage {
  private hashQueries: HashResult[] = [];
  private attemptCount: number = 0;
  private solved: boolean = false;

  async addHashQuery(input: string, fullHash: string, first4Bytes: string): Promise<HashResult> {
    const result: HashResult = {
      input,
      fullHash,
      first4Bytes,
      timestamp: Date.now(),
    };
    this.hashQueries.push(result);
    return result;
  }

  async getStats(): Promise<ChallengeStats> {
    return {
      totalQueries: this.hashQueries.length,
      totalAttempts: this.attemptCount,
      solved: this.solved,
    };
  }

  async incrementAttempts(): Promise<void> {
    this.attemptCount++;
  }

  async markAsSolved(): Promise<void> {
    this.solved = true;
  }
}

export const storage = new MemStorage();
