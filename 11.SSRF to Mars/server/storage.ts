import type { SSRFAttempt, FlagSubmissionRecord } from "@shared/schema";

export interface IStorage {
  addAttempt(attempt: SSRFAttempt): Promise<void>;
  getAttempts(): Promise<SSRFAttempt[]>;
  addFlagSubmission(submission: FlagSubmissionRecord): Promise<void>;
  getFlagSubmissions(): Promise<FlagSubmissionRecord[]>;
  getSuccessCount(): Promise<number>;
}

export class MemStorage implements IStorage {
  private attempts: SSRFAttempt[];
  private flagSubmissions: FlagSubmissionRecord[];

  constructor() {
    this.attempts = [];
    this.flagSubmissions = [];
  }

  async addAttempt(attempt: SSRFAttempt): Promise<void> {
    this.attempts.push(attempt);
    if (this.attempts.length > 100) {
      this.attempts = this.attempts.slice(-100);
    }
  }

  async getAttempts(): Promise<SSRFAttempt[]> {
    return [...this.attempts];
  }

  async addFlagSubmission(submission: FlagSubmissionRecord): Promise<void> {
    this.flagSubmissions.push(submission);
    if (this.flagSubmissions.length > 100) {
      this.flagSubmissions = this.flagSubmissions.slice(-100);
    }
  }

  async getFlagSubmissions(): Promise<FlagSubmissionRecord[]> {
    return [...this.flagSubmissions];
  }

  async getSuccessCount(): Promise<number> {
    return this.flagSubmissions.filter(s => s.result === 'success').length;
  }
}

export const storage = new MemStorage();
