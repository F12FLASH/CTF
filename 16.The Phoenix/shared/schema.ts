import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const exploitAttempts = pgTable("exploit_attempts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  payload: text("payload").notNull(),
  payloadPreview: text("payload_preview").notNull(),
  result: varchar("result", { length: 50 }).notNull(),
  duration: integer("duration").notNull(),
  status: varchar("status", { length: 20 }).notNull(),
});

export const payloads = pgTable("payloads", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  type: varchar("type", { length: 50 }).notNull(),
  offset: integer("offset").notNull(),
  address: text("address"),
  shellcode: text("shellcode"),
  description: text("description"),
  code: text("code").notNull(),
});

export const templates = pgTable("templates", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  description: text("description").notNull(),
  descriptionVi: text("description_vi"),
  difficulty: integer("difficulty").notNull(),
  category: varchar("category", { length: 50 }).notNull(),
  code: text("code").notNull(),
  documentation: text("documentation"),
  documentationVi: text("documentation_vi"),
});

export const oneGadgets = pgTable("one_gadgets", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  address: text("address").notNull(),
  constraints: text("constraints").notNull(),
  libcVersion: text("libc_version").notNull(),
  architecture: varchar("architecture", { length: 20 }).notNull().default("x86_64"),
});

export const challengeHintsSchema = z.record(z.string());

export const challenges = pgTable("challenges", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  nameVi: text("name_vi"),
  description: text("description").notNull(),
  descriptionVi: text("description_vi"),
  difficulty: integer("difficulty").notNull(),
  category: varchar("category", { length: 50 }).notNull(),
  encryptedFlag: text("encrypted_flag").notNull(),
  hints: jsonb("hints").$type<Record<string, string>>(),
  isSolved: integer("is_solved").notNull().default(0),
  solvedAt: timestamp("solved_at"),
  totalAttempts: integer("total_attempts").notNull().default(0),
});

export const flagSubmissions = pgTable("flag_submissions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  submittedFlag: text("submitted_flag").notNull(),
  isCorrect: integer("is_correct").notNull(),
  ipAddress: varchar("ip_address", { length: 45 }),
  userAgent: text("user_agent"),
});

export const instructions = pgTable("instructions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  title: text("title").notNull(),
  titleVi: text("title_vi"),
  content: text("content").notNull(),
  contentVi: text("content_vi"),
  orderIndex: integer("order_index").notNull(),
  category: varchar("category", { length: 50 }).notNull(),
  codeExample: text("code_example"),
});

export const insertExploitAttemptSchema = createInsertSchema(exploitAttempts).omit({
  id: true,
  timestamp: true,
});

export const insertPayloadSchema = createInsertSchema(payloads).omit({
  id: true,
});

export const insertTemplateSchema = createInsertSchema(templates).omit({
  id: true,
});

export const insertOneGadgetSchema = createInsertSchema(oneGadgets).omit({
  id: true,
});

export const insertChallengeSchema = createInsertSchema(challenges).omit({
  id: true,
  solvedAt: true,
  totalAttempts: true,
});

export const insertFlagSubmissionSchema = createInsertSchema(flagSubmissions).omit({
  id: true,
  timestamp: true,
});

export const insertInstructionSchema = createInsertSchema(instructions).omit({
  id: true,
});

export type InsertExploitAttempt = z.infer<typeof insertExploitAttemptSchema>;
export type ExploitAttempt = typeof exploitAttempts.$inferSelect;

export type InsertPayload = z.infer<typeof insertPayloadSchema>;
export type Payload = typeof payloads.$inferSelect;

export type InsertTemplate = z.infer<typeof insertTemplateSchema>;
export type Template = typeof templates.$inferSelect;

export type InsertOneGadget = z.infer<typeof insertOneGadgetSchema>;
export type OneGadget = typeof oneGadgets.$inferSelect;

export type InsertChallenge = z.infer<typeof insertChallengeSchema>;
export type Challenge = typeof challenges.$inferSelect;

export type InsertFlagSubmission = z.infer<typeof insertFlagSubmissionSchema>;
export type FlagSubmission = typeof flagSubmissions.$inferSelect;

export type InsertInstruction = z.infer<typeof insertInstructionSchema>;
export type Instruction = typeof instructions.$inferSelect;
