import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Challenge progress tracking
export const progress = pgTable("progress", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  sectionId: text("section_id").notNull(),
  completed: boolean("completed").notNull().default(false),
  completedAt: timestamp("completed_at"),
});

// Flag submissions
export const submissions = pgTable("submissions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  flag: text("flag").notNull(),
  isCorrect: boolean("is_correct").notNull(),
  submittedAt: timestamp("submitted_at").notNull().default(sql`now()`),
});

// Progress schemas
export const insertProgressSchema = createInsertSchema(progress).omit({
  id: true,
  completedAt: true,
});

export type InsertProgress = z.infer<typeof insertProgressSchema>;
export type Progress = typeof progress.$inferSelect;

// Submission schemas
export const insertSubmissionSchema = createInsertSchema(submissions).omit({
  id: true,
  isCorrect: true,
  submittedAt: true,
});

export type InsertSubmission = z.infer<typeof insertSubmissionSchema>;
export type Submission = typeof submissions.$inferSelect;

// Flag validation schema
export const flagSubmissionSchema = z.object({
  flag: z.string().min(1, "Flag không được để trống").regex(/^VNFLAG\{[^}]+\}$/, "Flag phải có định dạng VNFLAG{...}"),
});

export type FlagSubmission = z.infer<typeof flagSubmissionSchema>;

// Challenge section type
export interface ChallengeSection {
  id: string;
  title: string;
  icon?: string;
  subsections?: { id: string; title: string }[];
}

// Note: The correct flag is stored securely on the server side only
// See server/flag-encryption.ts for the actual flag validation logic
