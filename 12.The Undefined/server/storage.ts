import type { Progress, Hint, FlagResponse } from "@shared/schema";
import { CORRECT_FLAG, INITIAL_PROGRESS, HINTS } from "@shared/schema";

export interface IStorage {
  getProgress(sessionId: string): Promise<Progress>;
  updateProgress(sessionId: string, progress: Progress): Promise<Progress>;
  getAttempts(sessionId: string): Promise<number>;
  incrementAttempts(sessionId: string): Promise<number>;
  validateFlag(sessionId: string, flag: string): Promise<FlagResponse>;
  getHints(sessionId: string): Promise<Hint[]>;
  updateHints(sessionId: string, hints: Hint[]): Promise<Hint[]>;
}

interface SessionData {
  progress: Progress;
  attempts: number;
  hints: Hint[];
  solved: boolean;
}

export class MemStorage implements IStorage {
  private sessions: Map<string, SessionData>;

  constructor() {
    this.sessions = new Map();
  }

  private getOrCreateSession(sessionId: string): SessionData {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, {
        progress: { ...INITIAL_PROGRESS },
        attempts: 0,
        hints: HINTS.map(h => ({ ...h })),
        solved: false,
      });
    }
    return this.sessions.get(sessionId)!;
  }

  async getProgress(sessionId: string): Promise<Progress> {
    const session = this.getOrCreateSession(sessionId);
    return { ...session.progress };
  }

  async updateProgress(sessionId: string, progress: Progress): Promise<Progress> {
    const session = this.getOrCreateSession(sessionId);
    session.progress = { ...progress };
    return { ...session.progress };
  }

  async getAttempts(sessionId: string): Promise<number> {
    const session = this.getOrCreateSession(sessionId);
    return session.attempts;
  }

  async incrementAttempts(sessionId: string): Promise<number> {
    const session = this.getOrCreateSession(sessionId);
    session.attempts += 1;
    return session.attempts;
  }

  async validateFlag(sessionId: string, flag: string): Promise<FlagResponse> {
    const session = this.getOrCreateSession(sessionId);
    const newAttempts = await this.incrementAttempts(sessionId);

    const isCorrect = flag === CORRECT_FLAG;

    if (isCorrect) {
      session.solved = true;
      const allStepsCompleted = session.progress.steps.map(step => ({
        ...step,
        completed: true,
      }));
      session.progress = {
        ...session.progress,
        currentStep: 4,
        steps: allStepsCompleted,
      };
    }

    const unlockedHints = session.hints.filter(h => newAttempts >= h.unlockAttempts).length;

    session.hints = session.hints.map(hint => ({
      ...hint,
      unlocked: hint.unlocked || newAttempts >= hint.unlockAttempts,
    }));

    return {
      success: isCorrect,
      message: isCorrect
        ? 'Chúc mừng! Bạn đã giải được thử thách The Undefined. Flag chính xác!'
        : `Flag không đúng. Hãy thử lại! (Attempt ${newAttempts})`,
      attempts: newAttempts,
      hintsUnlocked: unlockedHints,
    };
  }

  async getHints(sessionId: string): Promise<Hint[]> {
    const session = this.getOrCreateSession(sessionId);
    return session.hints.map(h => ({ ...h }));
  }

  async updateHints(sessionId: string, hints: Hint[]): Promise<Hint[]> {
    const session = this.getOrCreateSession(sessionId);
    session.hints = hints.map(h => ({ ...h }));
    return session.hints;
  }
}

export const storage = new MemStorage();
