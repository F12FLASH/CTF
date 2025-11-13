import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, boolean, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Challenge execution state
export const challengeStates = pgTable("challenge_states", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  encryptedFlag: text("encrypted_flag").notNull(),
  currentKey: text("current_key").notNull(),
  keyRotationCount: integer("key_rotation_count").notNull().default(0),
  isTimeHooked: boolean("is_time_hooked").notNull().default(false),
  wasmExecutionStatus: text("wasm_execution_status").notNull().default("idle"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

// Flag submission attempts
export const flagSubmissions = pgTable("flag_submissions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  submittedFlag: text("submitted_flag").notNull(),
  isCorrect: boolean("is_correct").notNull(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
});

// Hints system
export const hints = pgTable("hints", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  order: integer("order").notNull(),
  title: text("title").notNull(),
  content: text("content").notNull(),
  isRevealed: boolean("is_revealed").notNull().default(false),
});

// Schemas
export const insertChallengeStateSchema = createInsertSchema(challengeStates).omit({
  id: true,
  createdAt: true,
});

export const insertFlagSubmissionSchema = createInsertSchema(flagSubmissions).omit({
  id: true,
  timestamp: true,
});

// Client-side flag submission schema (only needs submittedFlag, server calculates isCorrect)
export const clientFlagSubmissionSchema = z.object({
  submittedFlag: z.string().min(1, "Flag cannot be empty"),
});

export const insertHintSchema = createInsertSchema(hints).omit({
  id: true,
});

// Types
export type ChallengeState = typeof challengeStates.$inferSelect;
export type InsertChallengeState = z.infer<typeof insertChallengeStateSchema>;
export type FlagSubmission = typeof flagSubmissions.$inferSelect;
export type InsertFlagSubmission = z.infer<typeof insertFlagSubmissionSchema>;
export type Hint = typeof hints.$inferSelect;
export type InsertHint = z.infer<typeof insertHintSchema>;

// Frontend-only types for real-time state
export interface EncryptionState {
  encryptedFlag: string;
  currentKey: string;
  keyRotationCount: number;
  lastRotation: number;
}

export interface WasmExecutionState {
  status: "idle" | "compiling" | "running" | "paused" | "complete" | "error";
  progress: number;
  logs: string[];
  bytecode: string;
}

export interface TimeHookState {
  isHooked: boolean;
  frozenTimestamp: number | null;
  hookAttempts: number;
}

export interface ChallengeProgress {
  hasStarted: boolean;
  hasHookedTime: boolean;
  hasSubmittedFlag: boolean;
  isCompleted: boolean;
  hintsRevealed: number;
}
