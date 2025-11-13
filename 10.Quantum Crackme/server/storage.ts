import { type Submission, type InsertSubmission } from "@shared/schema";
import { db, submissions } from "./db";
import { FlagCrypto } from "./crypto";
import { desc, count, eq, and, gte, sql } from "drizzle-orm";

/**
 * Storage interface for CTF submissions
 * Uses PostgreSQL for persistence and security
 */
export interface IStorage {
  createSubmission(submission: InsertSubmission, ipAddress?: string): Promise<Submission>;
  getSubmissions(limit?: number): Promise<Submission[]>;
  getSubmissionStats(): Promise<{ total: number; correct: number }>;
  getRecentSubmissionsByIP(ipAddress: string, minutes: number): Promise<number>;
}

/**
 * PostgreSQL-backed storage implementation
 * Provides secure, persistent storage for CTF submissions
 */
export class DbStorage implements IStorage {
  /**
   * Create a new submission with encrypted flag validation
   * Never stores the actual flag, only validation result
   */
  async createSubmission(
    insertSubmission: InsertSubmission,
    ipAddress?: string
  ): Promise<Submission> {
    // Validate flag using timing-safe comparison
    const isCorrect = FlagCrypto.validateFlag(insertSubmission.attemptedFlag);
    
    // Insert submission into database
    const [submission] = await db
      .insert(submissions)
      .values({
        attemptedFlag: FlagCrypto.hashFlag(insertSubmission.attemptedFlag), // Never store actual flag
        isCorrect,
        ipAddress: ipAddress || null,
      })
      .returning();

    return submission;
  }

  /**
   * Get recent submissions (limited for security)
   */
  async getSubmissions(limit: number = 50): Promise<Submission[]> {
    return await db
      .select()
      .from(submissions)
      .orderBy(desc(submissions.submittedAt))
      .limit(limit);
  }

  /**
   * Get submission statistics
   */
  async getSubmissionStats(): Promise<{ total: number; correct: number }> {
    const allSubmissions = await db.select().from(submissions);
    
    return {
      total: allSubmissions.length,
      correct: allSubmissions.filter(s => s.isCorrect).length,
    };
  }

  /**
   * Count recent submissions from an IP address (for rate limiting)
   * Only counts submissions within the specified time window
   */
  async getRecentSubmissionsByIP(ipAddress: string, minutes: number): Promise<number> {
    const cutoffTime = new Date(Date.now() - minutes * 60 * 1000);
    
    const result = await db
      .select({ count: count() })
      .from(submissions)
      .where(
        and(
          eq(submissions.ipAddress, ipAddress),
          gte(submissions.submittedAt, cutoffTime)
        )
      );

    return Number(result[0]?.count) || 0;
  }
}

export const storage = new DbStorage();
