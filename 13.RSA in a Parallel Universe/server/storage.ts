import { 
  type ChallengeAttempt, 
  type InsertChallengeAttempt,
  type HintProgress,
  type InsertHintProgress,
} from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  createChallengeAttempt(attempt: InsertChallengeAttempt): Promise<ChallengeAttempt>;
  getChallengeAttempts(): Promise<ChallengeAttempt[]>;
  
  getHintProgress(sessionId: string): Promise<HintProgress | undefined>;
  updateHintProgress(progress: InsertHintProgress): Promise<HintProgress>;
}

export class MemStorage implements IStorage {
  private challengeAttempts: Map<string, ChallengeAttempt>;
  private hintProgressMap: Map<string, HintProgress>;

  constructor() {
    this.challengeAttempts = new Map();
    this.hintProgressMap = new Map();
  }

  async createChallengeAttempt(insertAttempt: InsertChallengeAttempt): Promise<ChallengeAttempt> {
    const id = randomUUID();
    const attempt: ChallengeAttempt = {
      ...insertAttempt,
      id,
      timestamp: new Date(),
      isCorrect: insertAttempt.isCorrect ?? false,
      ipAddress: insertAttempt.ipAddress ?? null,
    };
    this.challengeAttempts.set(id, attempt);
    return attempt;
  }

  async getChallengeAttempts(): Promise<ChallengeAttempt[]> {
    return Array.from(this.challengeAttempts.values()).sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
    );
  }

  async getHintProgress(sessionId: string): Promise<HintProgress | undefined> {
    return this.hintProgressMap.get(sessionId);
  }

  async updateHintProgress(insertProgress: InsertHintProgress): Promise<HintProgress> {
    const existing = this.hintProgressMap.get(insertProgress.sessionId);
    
    if (existing) {
      const updated: HintProgress = {
        ...existing,
        ...insertProgress,
        timestamp: new Date(),
        unlockedHintIds: insertProgress.unlockedHintIds ?? [],
      };
      this.hintProgressMap.set(insertProgress.sessionId, updated);
      return updated;
    }

    const id = randomUUID();
    const progress: HintProgress = {
      ...insertProgress,
      id,
      timestamp: new Date(),
      unlockedHintIds: insertProgress.unlockedHintIds ?? [],
    };
    this.hintProgressMap.set(insertProgress.sessionId, progress);
    return progress;
  }
}

export const storage = new MemStorage();
