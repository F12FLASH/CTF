import { z } from "zod";

export const queryResultSchema = z.object({
  data: z.any().optional(),
  errors: z.array(z.object({
    message: z.string(),
    locations: z.array(z.object({
      line: z.number(),
      column: z.number(),
    })).optional(),
    path: z.array(z.union([z.string(), z.number()])).optional(),
  })).optional(),
});

export type QueryResult = z.infer<typeof queryResultSchema>;

export const flagSubmissionSchema = z.object({
  flag: z.string().min(1, "Flag cannot be empty"),
});

export type FlagSubmission = z.infer<typeof flagSubmissionSchema>;

export const flagResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
});

export type FlagResponse = z.infer<typeof flagResponseSchema>;
