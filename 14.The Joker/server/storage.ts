import { 
  type Progress, 
  type InsertProgress,
  type Submission,
  type InsertSubmission,
} from "@shared/schema";
import { randomUUID } from "crypto";
import { validateFlag, hashFlagForStorage } from "./flag-encryption";

export interface IStorage {
  getProgress(): Promise<Progress[]>;
  markSection(data: InsertProgress): Promise<Progress>;
  submitFlag(flag: string): Promise<{ correct: boolean; submission: Submission }>;
  getSubmissions(): Promise<Submission[]>;
}

export class MemStorage implements IStorage {
  private progress: Map<string, Progress>;
  private submissions: Submission[];

  constructor() {
    this.progress = new Map();
    this.submissions = [];
  }

  async getProgress(): Promise<Progress[]> {
    return Array.from(this.progress.values());
  }

  async markSection(data: InsertProgress): Promise<Progress> {
    const existing = Array.from(this.progress.values()).find(
      p => p.sectionId === data.sectionId
    );

    if (existing) {
      existing.completed = data.completed ?? false;
      existing.completedAt = data.completed ? new Date() : null;
      this.progress.set(existing.id, existing);
      return existing;
    }

    const id = randomUUID();
    const progress: Progress = {
      id,
      sectionId: data.sectionId,
      completed: data.completed ?? false,
      completedAt: data.completed ? new Date() : null,
    };
    this.progress.set(id, progress);
    return progress;
  }

  async submitFlag(flag: string): Promise<{ correct: boolean; submission: Submission }> {
    // Security: Use constant-time comparison from flag-encryption module
    const isCorrect = validateFlag(flag);
    
    const submission: Submission = {
      id: randomUUID(),
      flag: hashFlagForStorage(flag), // Store hashed flag for privacy
      isCorrect,
      submittedAt: new Date(),
    };

    this.submissions.push(submission);
    return { correct: isCorrect, submission };
  }

  async getSubmissions(): Promise<Submission[]> {
    return this.submissions;
  }
}

export const storage = new MemStorage();
