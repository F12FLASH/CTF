import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, boolean, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const challenges = pgTable("challenges", {
  id: varchar("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  category: text("category").notNull(),
  difficulty: text("difficulty").notNull(),
  points: integer("points").notNull(),
  flag: text("flag").notNull(),
  author: text("author").notNull(),
  solves: integer("solves").notNull().default(0),
});

export const hints = pgTable("hints", {
  id: varchar("id").primaryKey(),
  challengeId: varchar("challenge_id").notNull(),
  order: integer("order").notNull(),
  content: text("content").notNull(),
  pointsCost: integer("points_cost").notNull(),
});

export const submissions = pgTable("submissions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  challengeId: varchar("challenge_id").notNull(),
  flag: text("flag").notNull(),
  correct: boolean("correct").notNull(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
});

export const writeupSections = pgTable("writeup_sections", {
  id: varchar("id").primaryKey(),
  challengeId: varchar("challenge_id").notNull(),
  order: integer("order").notNull(),
  title: text("title").notNull(),
  content: text("content").notNull(),
  codeBlock: text("code_block"),
  language: text("language"),
});

export const insertChallengeSchema = createInsertSchema(challenges).omit({ id: true });
export const insertHintSchema = createInsertSchema(hints).omit({ id: true });
export const insertSubmissionSchema = createInsertSchema(submissions).omit({ id: true, timestamp: true });
export const insertWriteupSectionSchema = createInsertSchema(writeupSections).omit({ id: true });

export const flagSubmissionSchema = z.object({
  challengeId: z.string(),
  flag: z.string().min(1, "Flag cannot be empty"),
});

export type Challenge = typeof challenges.$inferSelect;
export type InsertChallenge = z.infer<typeof insertChallengeSchema>;
export type Hint = typeof hints.$inferSelect;
export type InsertHint = z.infer<typeof insertHintSchema>;
export type Submission = typeof submissions.$inferSelect;
export type InsertSubmission = z.infer<typeof insertSubmissionSchema>;
export type FlagSubmission = z.infer<typeof flagSubmissionSchema>;
export type WriteupSection = typeof writeupSections.$inferSelect;
export type InsertWriteupSection = z.infer<typeof insertWriteupSectionSchema>;
