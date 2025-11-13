import { pgTable, text, serial, integer, timestamp, boolean, json } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const challenges = pgTable("challenges", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  difficulty: text("difficulty").notNull(),
  vulnerabilityType: text("vulnerability_type").notNull(),
  description: text("description").notNull(),
  hints: json("hints").$type<string[]>().notNull(),
  flag: text("flag").notNull(),
  solutionWriteup: text("solution_writeup").notNull(),
  basePoints: integer("base_points").notNull().default(1000),
});

export const attempts = pgTable("attempts", {
  id: serial("id").primaryKey(),
  challengeId: integer("challenge_id").notNull().references(() => challenges.id),
  username: text("username").notNull(),
  completed: boolean("completed").notNull().default(false),
  timeTaken: integer("time_taken"),
  score: integer("score"),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
});

export const leaderboardEntries = pgTable("leaderboard_entries", {
  id: serial("id").primaryKey(),
  challengeId: integer("challenge_id").notNull().references(() => challenges.id),
  username: text("username").notNull(),
  score: integer("score").notNull(),
  timeTaken: integer("time_taken").notNull(),
  rank: integer("rank").notNull(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
});

export const insertChallengeSchema = createInsertSchema(challenges).omit({ id: true });
export const insertAttemptSchema = createInsertSchema(attempts).omit({ id: true, timestamp: true });
export const insertLeaderboardEntrySchema = createInsertSchema(leaderboardEntries).omit({ id: true, timestamp: true });

export type Challenge = typeof challenges.$inferSelect;
export type InsertChallenge = z.infer<typeof insertChallengeSchema>;
export type Attempt = typeof attempts.$inferSelect;
export type InsertAttempt = z.infer<typeof insertAttemptSchema>;
export type LeaderboardEntry = typeof leaderboardEntries.$inferSelect;
export type InsertLeaderboardEntry = z.infer<typeof insertLeaderboardEntrySchema>;

export const jwtSubmissionSchema = z.object({
  token: z.string().min(1, "Token is required"),
});

export type JwtSubmission = z.infer<typeof jwtSubmissionSchema>;

export interface JwtValidationResponse {
  success: boolean;
  message: string;
  flag?: string;
  details?: {
    algorithm?: string;
    payload?: any;
    score?: number;
    timeTaken?: number;
    vulnerability?: string;
    hint?: string;
  };
}

export interface ChallengeInfo {
  currentToken: string;
  publicKey?: string;
  description: string;
  difficulty: string;
  hints: string[];
}
