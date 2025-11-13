import { z } from "zod";

// SSRF Attempt tracking
export const ssrfAttemptSchema = z.object({
  id: z.string(),
  url: z.string(),
  timestamp: z.number(),
  status: z.enum(['blocked', 'allowed', 'error', 'success']),
  response: z.string().optional(),
  technique: z.string().optional(),
  statusCode: z.number().optional(),
  ip: z.string().optional(),
});

export type SSRFAttempt = z.infer<typeof ssrfAttemptSchema>;

// Fetch request schema
export const fetchRequestSchema = z.object({
  url: z.string().min(1, "URL is required").max(2048, "URL too long"),
});

export type FetchRequest = z.infer<typeof fetchRequestSchema>;

// Fetch response schema
export const fetchResponseSchema = z.object({
  success: z.boolean(),
  status: z.enum(['blocked', 'allowed', 'error', 'success']),
  message: z.string(),
  response: z.string().optional(),
  statusCode: z.number().optional(),
  headers: z.record(z.string()).optional(),
  timing: z.number().optional(),
  blockedReason: z.string().optional(),
});

export type FetchResponse = z.infer<typeof fetchResponseSchema>;

// Flag submission schema
export const flagSubmissionSchema = z.object({
  flag: z.string().min(1, "Flag is required").max(200, "Flag too long"),
  userAlias: z.string().min(1, "Alias is required").max(50, "Alias too long").optional(),
});

export type FlagSubmission = z.infer<typeof flagSubmissionSchema>;

// Flag submission response
export const flagSubmissionResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
  points: z.number().optional(),
  timestamp: z.number().optional(),
});

export type FlagSubmissionResponse = z.infer<typeof flagSubmissionResponseSchema>;

// Flag submission record (does NOT store the actual flag for security)
export const flagSubmissionRecordSchema = z.object({
  id: z.string(),
  userAlias: z.string().optional(),
  timestamp: z.number(),
  result: z.enum(['success', 'failure']),
  ip: z.string().optional(),
});

export type FlagSubmissionRecord = z.infer<typeof flagSubmissionRecordSchema>;

// Payload examples
export interface PayloadExample {
  id: string;
  name: string;
  technique: string;
  url: string;
  description: string;
  difficulty: number;
  status?: 'attempted' | 'blocked' | 'successful';
}

// Challenge info
export interface ChallengeInfo {
  name: string;
  difficulty: number;
  category: string;
  points: number;
  flag: string;
  description: string;
}
