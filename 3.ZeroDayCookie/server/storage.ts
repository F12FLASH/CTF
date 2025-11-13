import { 
  type Challenge, type InsertChallenge, 
  type Attempt, type InsertAttempt,
  type LeaderboardEntry, type InsertLeaderboardEntry,
  challenges, attempts, leaderboardEntries 
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and } from "drizzle-orm";

export interface IStorage {
  getChallenge(id: number): Promise<Challenge | undefined>;
  getAllChallenges(): Promise<Challenge[]>;
  createChallenge(challenge: InsertChallenge): Promise<Challenge>;
  updateChallenge(id: number, challenge: Partial<InsertChallenge>): Promise<Challenge | undefined>;
  deleteChallenge(id: number): Promise<boolean>;
  
  getAttempt(id: number): Promise<Attempt | undefined>;
  createAttempt(attempt: InsertAttempt): Promise<Attempt>;
  updateAttempt(id: number, attempt: Partial<InsertAttempt>): Promise<Attempt | undefined>;
  deleteAttempt(id: number): Promise<boolean>;
  getUserAttempts(username: string): Promise<Attempt[]>;
  getChallengeAttempts(challengeId: number): Promise<Attempt[]>;
  getUserChallengeAttempts(username: string, challengeId: number): Promise<Attempt[]>;
  
  createLeaderboardEntry(entry: InsertLeaderboardEntry): Promise<LeaderboardEntry>;
  getLeaderboard(limit?: number): Promise<LeaderboardEntry[]>;
  getChallengeLeaderboard(challengeId: number, limit?: number): Promise<LeaderboardEntry[]>;
  updateLeaderboardRankings(challengeId?: number): Promise<void>;
}

export class DbStorage implements IStorage {
  private ensureDb() {
    if (!db) {
      throw new Error('Database not initialized. Set DATABASE_URL to use database features.');
    }
    return db;
  }

  async getChallenge(id: number): Promise<Challenge | undefined> {
    const database = this.ensureDb();
    const result = await database.select().from(challenges).where(eq(challenges.id, id));
    return result[0];
  }

  async getAllChallenges(): Promise<Challenge[]> {
    const database = this.ensureDb();
    return await database.select().from(challenges);
  }

  async createChallenge(challenge: InsertChallenge): Promise<Challenge> {
    const database = this.ensureDb();
    const result = await database.insert(challenges).values(challenge).returning();
    return result[0];
  }

  async updateChallenge(id: number, challenge: Partial<InsertChallenge>): Promise<Challenge | undefined> {
    const database = this.ensureDb();
    const result = await database.update(challenges).set(challenge).where(eq(challenges.id, id)).returning();
    return result[0];
  }

  async deleteChallenge(id: number): Promise<boolean> {
    const database = this.ensureDb();
    const result = await database.delete(challenges).where(eq(challenges.id, id)).returning();
    return result.length > 0;
  }

  async getAttempt(id: number): Promise<Attempt | undefined> {
    const database = this.ensureDb();
    const result = await database.select().from(attempts).where(eq(attempts.id, id));
    return result[0];
  }

  async createAttempt(attempt: InsertAttempt): Promise<Attempt> {
    const database = this.ensureDb();
    const result = await database.insert(attempts).values(attempt).returning();
    return result[0];
  }

  async updateAttempt(id: number, attempt: Partial<InsertAttempt>): Promise<Attempt | undefined> {
    const database = this.ensureDb();
    const result = await database.update(attempts).set(attempt).where(eq(attempts.id, id)).returning();
    return result[0];
  }

  async deleteAttempt(id: number): Promise<boolean> {
    const database = this.ensureDb();
    const result = await database.delete(attempts).where(eq(attempts.id, id)).returning();
    return result.length > 0;
  }

  async getUserAttempts(username: string): Promise<Attempt[]> {
    const database = this.ensureDb();
    return await database.select().from(attempts).where(eq(attempts.username, username)).orderBy(desc(attempts.timestamp));
  }

  async getChallengeAttempts(challengeId: number): Promise<Attempt[]> {
    const database = this.ensureDb();
    return await database.select().from(attempts).where(eq(attempts.challengeId, challengeId)).orderBy(desc(attempts.timestamp));
  }

  async getUserChallengeAttempts(username: string, challengeId: number): Promise<Attempt[]> {
    const database = this.ensureDb();
    return await database.select().from(attempts).where(
      and(eq(attempts.username, username), eq(attempts.challengeId, challengeId))
    ).orderBy(desc(attempts.timestamp));
  }

  async createLeaderboardEntry(entry: InsertLeaderboardEntry): Promise<LeaderboardEntry> {
    const database = this.ensureDb();
    const result = await database.insert(leaderboardEntries).values(entry).returning();
    return result[0];
  }

  async getLeaderboard(limit: number = 10): Promise<LeaderboardEntry[]> {
    const database = this.ensureDb();
    return await database.select().from(leaderboardEntries).orderBy(desc(leaderboardEntries.score), leaderboardEntries.rank).limit(limit);
  }

  async getChallengeLeaderboard(challengeId: number, limit: number = 10): Promise<LeaderboardEntry[]> {
    const database = this.ensureDb();
    return await database.select().from(leaderboardEntries).where(eq(leaderboardEntries.challengeId, challengeId)).orderBy(leaderboardEntries.rank).limit(limit);
  }

  async updateLeaderboardRankings(challengeId?: number): Promise<void> {
    const database = this.ensureDb();
    if (challengeId) {
      await database.delete(leaderboardEntries).where(eq(leaderboardEntries.challengeId, challengeId));
      
      const topAttempts = await database.select().from(attempts).where(
        and(eq(attempts.completed, true), eq(attempts.challengeId, challengeId))
      ).orderBy(desc(attempts.score)).limit(100);
      
      const entries = topAttempts.map((attempt, index) => ({
        challengeId: attempt.challengeId!,
        username: attempt.username,
        score: attempt.score!,
        timeTaken: attempt.timeTaken!,
        rank: index + 1,
      }));
      
      if (entries.length > 0) {
        await database.insert(leaderboardEntries).values(entries);
      }
    } else {
      await database.delete(leaderboardEntries);
      
      const topAttempts = await database.select().from(attempts).where(eq(attempts.completed, true)).orderBy(desc(attempts.score)).limit(100);
      
      const entries = topAttempts.map((attempt, index) => ({
        challengeId: attempt.challengeId!,
        username: attempt.username,
        score: attempt.score!,
        timeTaken: attempt.timeTaken!,
        rank: index + 1,
      }));
      
      if (entries.length > 0) {
        await database.insert(leaderboardEntries).values(entries);
      }
    }
  }
}

// Only create storage instance if database is available
export const storage = db ? new DbStorage() : null;
