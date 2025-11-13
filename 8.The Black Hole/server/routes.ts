import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { z } from "zod";
import rateLimit from "express-rate-limit";

const submissionLimiter = rateLimit({
  windowMs: parseInt(process.env.SUBMISSION_RATE_LIMIT_WINDOW_MS || '60000', 10),
  max: parseInt(process.env.SUBMISSION_RATE_LIMIT_MAX_REQUESTS || '10', 10),
  message: 'Too many submission attempts. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

export async function registerRoutes(app: Express): Promise<Server> {
  
  app.get("/api/challenge/:id", async (req, res) => {
    try {
      const { id } = req.params;
      
      if (!id || typeof id !== 'string' || id.length > 100) {
        return res.status(400).json({ message: "Invalid challenge ID" });
      }
      
      const challenge = await storage.getChallenge(id);
      
      if (!challenge) {
        return res.status(404).json({ message: "Challenge not found" });
      }
      
      res.json(challenge);
    } catch (error) {
      console.error("Error fetching challenge:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  const submissionRequestSchema = z.object({
    challengeId: z.string().min(1, "Challenge ID is required").max(100, "Challenge ID is too long"),
    flag: z.string().min(1, "Flag is required").max(200, "Flag is too long"),
  });

  app.post("/api/submissions", submissionLimiter, async (req, res) => {
    try {
      const validatedRequest = submissionRequestSchema.parse({
        challengeId: typeof req.body.challengeId === 'string' ? req.body.challengeId.trim() : "the-black-hole",
        flag: typeof req.body.flag === 'string' ? req.body.flag.trim() : req.body.flag,
      });
      
      const challenge = await storage.getChallenge(validatedRequest.challengeId);
      if (!challenge) {
        return res.status(404).json({ message: "Challenge not found" });
      }
      
      const isCorrect = await storage.verifyFlagSubmission(validatedRequest.challengeId, validatedRequest.flag);
      
      const submission = await storage.createSubmission({
        challengeId: validatedRequest.challengeId,
        isCorrect,
      });
      
      if (isCorrect) {
        const { token, expiresAt } = await storage.createRevealToken(validatedRequest.challengeId);
        
        return res.status(201).json({
          id: submission.id,
          isCorrect: true,
          submittedAt: submission.submittedAt,
          revealToken: token,
          revealTokenExpiresAt: expiresAt,
        });
      }
      
      res.status(201).json({
        id: submission.id,
        isCorrect: false,
        submittedAt: submission.submittedAt,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ 
          message: "Invalid submission data", 
          errors: error.errors 
        });
      }
      console.error("Error creating submission");
      res.status(500).json({ message: "Internal server error" });
    }
  });

  const flagRevealSchema = z.object({
    token: z.string().min(1, "Token is required").max(100, "Token is too long"),
  });

  app.post("/api/reveal-flag", async (req, res) => {
    try {
      const validatedRequest = flagRevealSchema.parse({
        token: typeof req.body.token === 'string' ? req.body.token.trim() : req.body.token,
      });
      
      const flag = await storage.consumeRevealToken(validatedRequest.token);
      
      if (!flag) {
        return res.status(404).json({ message: "Invalid or expired reveal token" });
      }
      
      res.json({ flag });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ 
          message: "Invalid request data", 
          errors: error.errors 
        });
      }
      console.error("Error revealing flag");
      res.status(500).json({ message: "Internal server error" });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}
