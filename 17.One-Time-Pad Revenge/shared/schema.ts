import { z } from "zod";

export const ciphertextSchema = z.object({
  id: z.string(),
  data: z.string(),
  size: z.number(),
  uploadedAt: z.date(),
});

export const encryptRequestSchema = z.object({
  plaintext: z.string().min(1, "Plaintext cannot be empty"),
  key: z.string().optional(),
});

export const encryptResponseSchema = z.object({
  ciphertext: z.string(),
  key: z.string(),
  keyHash: z.string(),
});

export const statisticalAnalysisSchema = z.object({
  totalCiphertexts: z.number(),
  keyLength: z.number(),
  entropy: z.number(),
  byteFrequency: z.array(z.record(z.string(), z.number())),
  averageByteValue: z.number(),
});

export const xorAnalysisSchema = z.object({
  pairIndex1: z.number(),
  pairIndex2: z.number(),
  xorResult: z.string(),
  patterns: z.array(z.object({
    position: z.number(),
    value: z.string(),
    frequency: z.number(),
  })),
});

export const knownPlaintextAttackSchema = z.object({
  knownPrefix: z.string().min(1, "Known prefix cannot be empty"),
  ciphertextIds: z.array(z.string()).optional(),
});

export const keystreamRecoverySchema = z.object({
  recoveredKeystream: z.string(),
  confidence: z.number(),
  matchedCiphertexts: z.number(),
  recoveredPlaintext: z.string().optional(),
});

export const flagVerificationSchema = z.object({
  flag: z.string().min(1, "Flag cannot be empty"),
});

export const challengeGenerateSchema = z.object({
  count: z.number().int().min(1).max(1000).optional().default(1000),
});

export const flagVerificationResponseSchema = z.object({
  valid: z.boolean(),
  providedHash: z.string(),
  expectedHash: z.string().optional(),
  message: z.string(),
});

export type Ciphertext = z.infer<typeof ciphertextSchema>;
export type EncryptRequest = z.infer<typeof encryptRequestSchema>;
export type EncryptResponse = z.infer<typeof encryptResponseSchema>;
export type StatisticalAnalysis = z.infer<typeof statisticalAnalysisSchema>;
export type XorAnalysis = z.infer<typeof xorAnalysisSchema>;
export type KnownPlaintextAttack = z.infer<typeof knownPlaintextAttackSchema>;
export type KeystreamRecovery = z.infer<typeof keystreamRecoverySchema>;
export type FlagVerification = z.infer<typeof flagVerificationSchema>;
export type FlagVerificationResponse = z.infer<typeof flagVerificationResponseSchema>;
