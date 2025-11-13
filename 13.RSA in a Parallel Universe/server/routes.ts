import type { Express } from "express";
import { createServer, type Server } from "http";
import { rateLimit } from "express-rate-limit";
import { storage } from "./storage";
import { insertChallengeAttemptSchema, insertHintProgressSchema } from "@shared/schema";
import { z } from "zod";

// Load flag from environment variable for security
const CORRECT_FLAG = process.env.CTF_FLAG || "VNFLAG{TU_HAO_DAN_TOC_VIETNAM_TRUYEN_THONG_BAT_TU_5R9k2P1m7Q4z3L6f0B8yXc}";

if (!process.env.CTF_FLAG && process.env.NODE_ENV === 'production') {
  console.warn('⚠️  WARNING: CTF_FLAG not set in environment variables! Using default flag.');
}

// Flag submission rate limiting - more strict
const flagSubmitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.FLAG_SUBMIT_RATE_LIMIT || '10', 10),
  message: 'Too many flag submission attempts. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful submissions
});

const gaussianIntegerSchema = z.object({
  real: z.number(),
  imaginary: z.number(),
});

export async function registerRoutes(app: Express): Promise<Server> {
  
  app.post("/api/flag/submit", flagSubmitLimiter, async (req, res) => {
    try {
      const { submittedFlag } = req.body;
      
      if (!submittedFlag || typeof submittedFlag !== "string") {
        return res.status(400).json({ error: "Flag is required" });
      }

      const isCorrect = submittedFlag.trim() === CORRECT_FLAG;
      
      const attempt = await storage.createChallengeAttempt({
        submittedFlag: submittedFlag.trim(),
        isCorrect,
        ipAddress: req.ip || "unknown",
      });

      return res.json({
        success: isCorrect,
        message: isCorrect 
          ? "Chúc mừng! Flag chính xác. Bạn đã hoàn thành thử thách!" 
          : "Flag không chính xác. Hãy thử lại!",
        attemptId: attempt.id,
      });
    } catch (error) {
      console.error("Error submitting flag:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/attempts", async (req, res) => {
    try {
      const attempts = await storage.getChallengeAttempts();
      return res.json(attempts);
    } catch (error) {
      console.error("Error fetching attempts:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/hints/progress", async (req, res) => {
    try {
      const validated = insertHintProgressSchema.parse(req.body);
      
      const normalizedIds = Array.from(new Set(validated.unlockedHintIds || []))
        .filter(id => Number.isInteger(id) && id > 0)
        .sort((a, b) => a - b);
      
      const progress = await storage.updateHintProgress({
        ...validated,
        unlockedHintIds: normalizedIds,
      });
      return res.json(progress);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid request data", details: error.errors });
      }
      console.error("Error updating hint progress:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/hints/progress/:sessionId", async (req, res) => {
    try {
      const { sessionId } = req.params;
      const progress = await storage.getHintProgress(sessionId);
      
      if (!progress) {
        return res.json({ unlockedHintIds: [] });
      }
      
      return res.json(progress);
    } catch (error) {
      console.error("Error fetching hint progress:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/gaussian/add", async (req, res) => {
    try {
      const { a, b } = req.body;
      const validatedA = gaussianIntegerSchema.parse(a);
      const validatedB = gaussianIntegerSchema.parse(b);

      const result = {
        real: validatedA.real + validatedB.real,
        imaginary: validatedA.imaginary + validatedB.imaginary,
      };

      return res.json({ operation: "add", result });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid Gaussian integers", details: error.errors });
      }
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/gaussian/multiply", async (req, res) => {
    try {
      const { a, b } = req.body;
      const validatedA = gaussianIntegerSchema.parse(a);
      const validatedB = gaussianIntegerSchema.parse(b);

      const result = {
        real: validatedA.real * validatedB.real - validatedA.imaginary * validatedB.imaginary,
        imaginary: validatedA.real * validatedB.imaginary + validatedA.imaginary * validatedB.real,
      };

      return res.json({ operation: "multiply", result });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid Gaussian integers", details: error.errors });
      }
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/gaussian/norm", async (req, res) => {
    try {
      const { z } = req.body;
      const validated = gaussianIntegerSchema.parse(z);

      const norm = validated.real * validated.real + validated.imaginary * validated.imaginary;

      return res.json({ 
        operation: "norm",
        gaussian: validated, 
        norm 
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid Gaussian integer", details: error.errors });
      }
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/gaussian/gcd", async (req, res) => {
    try {
      const { a, b } = req.body;
      const validatedA = gaussianIntegerSchema.parse(a);
      const validatedB = gaussianIntegerSchema.parse(b);

      let x = { ...validatedA };
      let y = { ...validatedB };

      while (y.real !== 0 || y.imaginary !== 0) {
        const normY = y.real * y.real + y.imaginary * y.imaginary;
        if (normY === 0) break;

        const quotientReal = Math.round((x.real * y.real + x.imaginary * y.imaginary) / normY);
        const quotientImag = Math.round((x.imaginary * y.real - x.real * y.imaginary) / normY);

        const temp = { ...x };
        x = { ...y };
        y = {
          real: temp.real - quotientReal * y.real + quotientImag * y.imaginary,
          imaginary: temp.imaginary - quotientReal * y.imaginary - quotientImag * y.real,
        };
      }

      return res.json({ 
        operation: "gcd",
        result: x 
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid Gaussian integers", details: error.errors });
      }
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
