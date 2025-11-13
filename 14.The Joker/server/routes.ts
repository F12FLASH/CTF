import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertProgressSchema, flagSubmissionSchema } from "@shared/schema";
import { z } from "zod";
import { fromZodError } from "zod-validation-error";
import { flagSubmissionRateLimit } from "./security-middleware";

export async function registerRoutes(app: Express): Promise<Server> {
  app.get("/api/progress", async (_req, res) => {
    try {
      const progress = await storage.getProgress();
      res.json(progress);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch progress" });
    }
  });

  app.post("/api/mark-section", async (req, res) => {
    try {
      const data = insertProgressSchema.parse(req.body);
      const progress = await storage.markSection(data);
      res.json(progress);
    } catch (error) {
      if (error instanceof z.ZodError) {
        const validationError = fromZodError(error);
        res.status(400).json({ error: validationError.message });
      } else {
        res.status(500).json({ error: "Failed to mark section" });
      }
    }
  });

  app.post("/api/submit-flag", flagSubmissionRateLimit, async (req, res) => {
    try {
      const { flag } = flagSubmissionSchema.parse(req.body);
      const result = await storage.submitFlag(flag);
      
      res.json({
        correct: result.correct,
        message: result.correct 
          ? "Chính xác! Bạn đã giải quyết thử thách The Joker thành công!" 
          : "Flag không chính xác. Hãy thử lại với các phương pháp khác.",
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        const validationError = fromZodError(error);
        res.status(400).json({ 
          correct: false,
          message: validationError.message 
        });
      } else {
        res.status(500).json({ 
          correct: false,
          message: "Lỗi server khi kiểm tra flag" 
        });
      }
    }
  });

  app.get("/api/download-binary", async (_req, res) => {
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="the_joker"');
    
    const mockBinary = Buffer.from(
      'ELF Binary Placeholder - In a real scenario, this would be the actual binary file',
      'utf-8'
    );
    
    res.send(mockBinary);
  });

  app.get("/api/submissions", async (_req, res) => {
    try {
      const submissions = await storage.getSubmissions();
      res.json(submissions);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch submissions" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
