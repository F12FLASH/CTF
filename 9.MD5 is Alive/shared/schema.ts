import { z } from "zod";

// Hash Query schema - represents a query to the MD5 oracle
export const hashQuerySchema = z.object({
  input: z.string().min(1, "Input cannot be empty"),
});

export type HashQuery = z.infer<typeof hashQuerySchema>;

// Hash Result - returned from the oracle
export const hashResultSchema = z.object({
  input: z.string(),
  fullHash: z.string(),
  first4Bytes: z.string(),
  timestamp: z.number(),
});

export type HashResult = z.infer<typeof hashResultSchema>;

// Flag Submission schema - for validating flag attempts
export const flagSubmissionSchema = z.object({
  flag: z.string().min(1, "Flag cannot be empty"),
});

export type FlagSubmission = z.infer<typeof flagSubmissionSchema>;

// Flag Validation Result
export const flagValidationResultSchema = z.object({
  correct: z.boolean(),
  message: z.string(),
});

export type FlagValidationResult = z.infer<typeof flagValidationResultSchema>;

// Hint schema
export const hintSchema = z.object({
  id: z.string(),
  title: z.string(),
  content: z.string(),
  difficulty: z.number().min(1).max(5),
  unlocked: z.boolean().default(false),
});

export type Hint = z.infer<typeof hintSchema>;

// Challenge statistics
export const challengeStatsSchema = z.object({
  totalQueries: z.number(),
  totalAttempts: z.number(),
  solved: z.boolean(),
});

export type ChallengeStats = z.infer<typeof challengeStatsSchema>;
