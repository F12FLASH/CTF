import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const submissions = pgTable("submissions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  challengeId: varchar("challenge_id").notNull(),
  isCorrect: boolean("is_correct").notNull().default(false),
  submittedAt: timestamp("submitted_at").notNull().defaultNow(),
});

export const challenges = pgTable("challenges", {
  id: varchar("id").primaryKey(),
  name: text("name").notNull(),
  nameVi: text("name_vi").notNull(),
  category: text("category").notNull(),
  difficulty: text("difficulty").notNull(),
  description: text("description").notNull(),
  descriptionVi: text("description_vi").notNull(),
  flagHash: text("flag_hash").notNull(),
  encryptedFlag: text("encrypted_flag").notNull(),
  seccompRules: text("seccomp_rules").array().notNull(),
  vulnerabilities: text("vulnerabilities").array().notNull(),
  protections: text("protections").array().notNull(),
  environment: text("environment").array().notNull(),
  skills: text("skills").array().notNull(),
  solvers: varchar("solvers").notNull().default('0'),
  successRate: varchar("success_rate").notNull().default('0'),
});

export const revealTokens = pgTable("reveal_tokens", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  token: text("token").notNull().unique(),
  challengeId: varchar("challenge_id").notNull(),
  used: boolean("used").notNull().default(false),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export const insertSubmissionSchema = createInsertSchema(submissions).omit({
  id: true,
  submittedAt: true,
});

export const insertChallengeSchema = createInsertSchema(challenges);

export const insertRevealTokenSchema = createInsertSchema(revealTokens).omit({
  id: true,
  createdAt: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertSubmission = z.infer<typeof insertSubmissionSchema>;
export type Submission = typeof submissions.$inferSelect;
export type Challenge = typeof challenges.$inferSelect;
export type InsertChallenge = z.infer<typeof insertChallengeSchema>;
export type RevealToken = typeof revealTokens.$inferSelect;
export type InsertRevealToken = z.infer<typeof insertRevealTokenSchema>;

export interface ChallengeData {
  id: string;
  name: string;
  nameVi: string;
  category: string;
  difficulty: string;
  description: string;
  descriptionVi: string;
  flag: string;
  seccompRules: string[];
  vulnerabilities: string[];
  protections: string[];
  environment: string[];
  skills: string[];
  exploitSteps: ExploitStep[];
  solvers: number;
  successRate: number;
}

export interface ExploitStep {
  id: number;
  title: string;
  titleVi: string;
  description: string;
  descriptionVi: string;
  code?: string;
  codeLanguage?: string;
}

export interface CodeExample {
  language: string;
  code: string;
  description: string;
  descriptionVi: string;
}
