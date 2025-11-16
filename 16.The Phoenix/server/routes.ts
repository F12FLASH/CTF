import type { Express } from "express";
import { createServer, type Server } from "http";
import rateLimit from "express-rate-limit";
import { storage } from "./storage";
import {
  insertExploitAttemptSchema,
  insertPayloadSchema,
  insertTemplateSchema,
  insertOneGadgetSchema,
  insertFlagSubmissionSchema,
  insertInstructionSchema,
} from "@shared/schema";
import { validateFlag, decryptFlag } from "./flag-vault";
import { z } from "zod";

const generalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests from this IP, please try again later."
});

const sensitiveApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, please slow down."
});

export async function registerRoutes(app: Express): Promise<Server> {
  // Exploit Attempts
  app.post("/api/attempts", generalApiLimiter, async (req, res) => {
    try {
      const data = insertExploitAttemptSchema.parse(req.body);
      const attempt = await storage.createExploitAttempt(data);
      res.json(attempt);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.get("/api/attempts", async (_req, res) => {
    try {
      const attempts = await storage.getExploitAttempts();
      res.json(attempts);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/attempts/:id", async (req, res) => {
    try {
      const attempt = await storage.getExploitAttemptById(req.params.id);
      if (!attempt) {
        return res.status(404).json({ error: "Attempt not found" });
      }
      res.json(attempt);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Payloads
  app.post("/api/payloads", generalApiLimiter, async (req, res) => {
    try {
      const data = insertPayloadSchema.parse(req.body);
      const payload = await storage.createPayload(data);
      res.json(payload);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.get("/api/payloads", async (_req, res) => {
    try {
      const payloads = await storage.getPayloads();
      res.json(payloads);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/payloads/:id", async (req, res) => {
    try {
      const payload = await storage.getPayloadById(req.params.id);
      if (!payload) {
        return res.status(404).json({ error: "Payload not found" });
      }
      res.json(payload);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Payload Generation Utilities
  const cyclicSchema = z.object({
    length: z.number().int().min(1).max(10000),
  });

  app.post("/api/payloads/generate/cyclic", async (req, res) => {
    try {
      const data = cyclicSchema.parse(req.body);

      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      let pattern = "";
      for (let i = 0; i < data.length; i++) {
        pattern += chars[i % chars.length];
      }

      res.json({ pattern });
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid input", details: error.errors });
      }
      res.status(500).json({ error: error.message });
    }
  });

  const overwriteSchema = z.object({
    offset: z.number().int().min(0).max(10000),
    address: z.string().regex(/^0x[0-9a-fA-F]+$/),
    type: z.enum(["partial", "full"]).optional(),
  });

  app.post("/api/payloads/generate/overwrite", async (req, res) => {
    try {
      const data = overwriteSchema.parse(req.body);

      let payload: string;
      
      if (data.type === "partial") {
        const lower12bits = parseInt(data.address.slice(-3), 16);
        payload = `b"A" * ${data.offset} + p16(0x${lower12bits.toString(16).padStart(3, '0')})`;
      } else {
        payload = `b"A" * ${data.offset} + p64(${data.address})`;
      }

      res.json({ payload });
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid input", details: error.errors });
      }
      res.status(500).json({ error: error.message });
    }
  });

  // Templates
  app.post("/api/templates", sensitiveApiLimiter, async (req, res) => {
    try {
      const data = insertTemplateSchema.parse(req.body);
      const template = await storage.createTemplate(data);
      res.json(template);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.get("/api/templates", async (_req, res) => {
    try {
      const templates = await storage.getTemplates();
      res.json(templates);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/templates/:id", async (req, res) => {
    try {
      const template = await storage.getTemplateById(req.params.id);
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }
      res.json(template);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // One-Gadgets
  app.post("/api/gadgets", sensitiveApiLimiter, async (req, res) => {
    try {
      const data = insertOneGadgetSchema.parse(req.body);
      const gadget = await storage.createOneGadget(data);
      res.json(gadget);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.get("/api/gadgets", async (req, res) => {
    try {
      const libcVersion = req.query.libcVersion as string | undefined;
      const gadgets = await storage.getOneGadgets(libcVersion);
      res.json(gadgets);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/gadgets/:id", async (req, res) => {
    try {
      const gadget = await storage.getOneGadgetById(req.params.id);
      if (!gadget) {
        return res.status(404).json({ error: "Gadget not found" });
      }
      res.json(gadget);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Challenge
  app.get("/api/challenge", async (_req, res) => {
    try {
      const challenge = await storage.getChallenge();
      if (!challenge) {
        return res.status(404).json({ error: "Challenge not found" });
      }
      
      const { encryptedFlag, ...safeChallenge } = challenge;
      res.json(safeChallenge);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Flag Submission
  const flagSubmissionRateLimiter = new Map<string, number[]>();
  
  app.post("/api/flags/submit", sensitiveApiLimiter, async (req, res) => {
    try {
      const submittedFlag = z.string().min(1).max(500).parse(req.body.flag);
      const ipAddress = (req.headers['x-forwarded-for'] as string) || 
                        (req.socket.remoteAddress || 'unknown');
      const userAgent = req.headers['user-agent'] || null;

      const now = Date.now();
      const rateLimitKey = ipAddress;
      const attempts = flagSubmissionRateLimiter.get(rateLimitKey) || [];
      const recentAttempts = attempts.filter(time => now - time < 60000);
      
      if (recentAttempts.length >= 10) {
        return res.status(429).json({ 
          error: "Too many attempts. Please wait before trying again.",
          errorVi: "Quá nhiều lần thử. Vui lòng đợi trước khi thử lại."
        });
      }
      
      recentAttempts.push(now);
      flagSubmissionRateLimiter.set(rateLimitKey, recentAttempts);
      
      for (const [key, times] of Array.from(flagSubmissionRateLimiter.entries())) {
        const validTimes = times.filter((time: number) => now - time < 60000);
        if (validTimes.length === 0) {
          flagSubmissionRateLimiter.delete(key);
        } else {
          flagSubmissionRateLimiter.set(key, validTimes);
        }
      }

      const isCorrect = validateFlag(submittedFlag);
      
      await storage.incrementChallengeAttempts();
      
      const submission = await storage.createFlagSubmission({
        submittedFlag: submittedFlag.substring(0, 50),
        isCorrect: isCorrect ? 1 : 0,
        ipAddress: ipAddress.substring(0, 45),
        userAgent: userAgent ? userAgent.substring(0, 200) : null,
      });

      if (isCorrect) {
        const challenge = await storage.markChallengeSolved();
        const actualFlag = decryptFlag(challenge.encryptedFlag);
        
        return res.json({
          correct: true,
          flag: actualFlag,
          message: "Congratulations! You've solved the challenge!",
          messageVi: "Chúc mừng! Bạn đã giải được thử thách!",
          solvedAt: challenge.solvedAt,
        });
      } else {
        return res.json({
          correct: false,
          message: "Incorrect flag. Keep trying!",
          messageVi: "Flag không đúng. Hãy thử lại!",
        });
      }
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ 
          error: "Invalid flag format",
          errorVi: "Định dạng flag không hợp lệ"
        });
      }
      res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/flags/submissions", async (_req, res) => {
    try {
      const submissions = await storage.getFlagSubmissions();
      const sanitized = submissions.map(({ submittedFlag, ...rest }) => ({
        ...rest,
        submittedFlag: submittedFlag.substring(0, 20) + "...",
      }));
      res.json(sanitized);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Instructions
  app.post("/api/instructions", sensitiveApiLimiter, async (req, res) => {
    try {
      const data = insertInstructionSchema.parse(req.body);
      const instruction = await storage.createInstruction(data);
      res.json(instruction);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.get("/api/instructions", async (req, res) => {
    try {
      const category = req.query.category as string | undefined;
      const instructions = category 
        ? await storage.getInstructionsByCategory(category)
        : await storage.getInstructions();
      res.json(instructions);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}
