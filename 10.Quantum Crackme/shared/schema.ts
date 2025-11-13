import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const submissions = pgTable("submissions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  attemptedFlag: text("attempted_flag").notNull(),
  isCorrect: boolean("is_correct").notNull().default(false),
  submittedAt: timestamp("submitted_at").notNull().defaultNow(),
  ipAddress: text("ip_address"),
});

export const insertSubmissionSchema = createInsertSchema(submissions).pick({
  attemptedFlag: true,
});

export type InsertSubmission = z.infer<typeof insertSubmissionSchema>;
export type Submission = typeof submissions.$inferSelect;

// Challenge data structure (static, no DB needed)
export interface ChallengeInfo {
  name: string;
  category: string;
  difficulty: number;
  technologies: string[];
  flag: string;
}

export interface SolutionMethod {
  id: string;
  title: string;
  difficulty: number;
  steps: string[];
  techniques?: string[];
  codeExample?: {
    language: string;
    code: string;
  };
  files?: string[];
}

export interface Tool {
  category: string;
  name: string;
  description: string;
}
