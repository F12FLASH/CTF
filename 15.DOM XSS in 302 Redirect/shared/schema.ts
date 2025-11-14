import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, integer, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const exploitAttempts = pgTable("exploit_attempts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  payload: text("payload").notNull(),
  timestamp: timestamp("timestamp").notNull().default(sql`now()`),
  success: boolean("success").notNull().default(false),
});

export const capturedCookies = pgTable("captured_cookies", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  cookie: text("cookie").notNull(),
  timestamp: timestamp("timestamp").notNull().default(sql`now()`),
  sourceUrl: text("source_url"),
});

export const hints = pgTable("hints", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  level: integer("level").notNull(),
  title: text("title").notNull(),
  content: text("content").notNull(),
  revealed: boolean("revealed").notNull().default(false),
});

export const insertExploitAttemptSchema = createInsertSchema(exploitAttempts).omit({
  id: true,
  timestamp: true,
});

export const insertCapturedCookieSchema = createInsertSchema(capturedCookies).omit({
  id: true,
  timestamp: true,
});

export const insertHintSchema = createInsertSchema(hints).omit({
  id: true,
});

export type InsertExploitAttempt = z.infer<typeof insertExploitAttemptSchema>;
export type ExploitAttempt = typeof exploitAttempts.$inferSelect;

export type InsertCapturedCookie = z.infer<typeof insertCapturedCookieSchema>;
export type CapturedCookie = typeof capturedCookies.$inferSelect;

export type InsertHint = z.infer<typeof insertHintSchema>;
export type Hint = typeof hints.$inferSelect;
