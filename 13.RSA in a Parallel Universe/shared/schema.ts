import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const challengeAttempts = pgTable("challenge_attempts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  submittedFlag: text("submitted_flag").notNull(),
  isCorrect: boolean("is_correct").notNull().default(false),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  ipAddress: text("ip_address"),
});

export const hintProgress = pgTable("hint_progress", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  sessionId: text("session_id").notNull(),
  unlockedHintIds: integer("unlocked_hint_ids").array().notNull().default(sql`ARRAY[]::integer[]`),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
});

export const insertChallengeAttemptSchema = createInsertSchema(challengeAttempts).omit({
  id: true,
  timestamp: true,
});

export const insertHintProgressSchema = createInsertSchema(hintProgress).omit({
  id: true,
  timestamp: true,
});

export type InsertChallengeAttempt = z.infer<typeof insertChallengeAttemptSchema>;
export type ChallengeAttempt = typeof challengeAttempts.$inferSelect;
export type InsertHintProgress = z.infer<typeof insertHintProgressSchema>;
export type HintProgress = typeof hintProgress.$inferSelect;

export interface GaussianInteger {
  real: number;
  imaginary: number;
}

export interface GaussianCalculationResult {
  operation: string;
  result: GaussianInteger;
  norm?: number;
}

export interface SolverStep {
  id: number;
  title: string;
  description: string;
  formula?: string;
  completed: boolean;
}
