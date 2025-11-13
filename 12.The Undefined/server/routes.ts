import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { flagSubmissionSchema } from "@shared/schema";

const SESSION_ID_REGEX = /^session-\d{13}-[a-z0-9]{8,}$/;

function validateSessionId(sessionId: string): boolean {
  if (!sessionId || typeof sessionId !== 'string') {
    return false;
  }
  if (sessionId.length > 100) {
    return false;
  }
  return SESSION_ID_REGEX.test(sessionId);
}

const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 60000;
const MAX_ATTEMPTS_PER_MINUTE = 20;

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const rateData = rateLimitMap.get(ip);
  
  if (!rateData || now > rateData.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }
  
  if (rateData.count >= MAX_ATTEMPTS_PER_MINUTE) {
    return false;
  }
  
  rateData.count++;
  return true;
}

setInterval(() => {
  const now = Date.now();
  const entries = Array.from(rateLimitMap.entries());
  for (const [ip, data] of entries) {
    if (now > data.resetTime) {
      rateLimitMap.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW);

export async function registerRoutes(app: Express): Promise<Server> {
  app.get("/api/progress/:sessionId", async (req, res) => {
    try {
      const { sessionId } = req.params;
      
      if (!validateSessionId(sessionId)) {
        return res.status(400).json({ error: "Invalid session ID format" });
      }
      
      const progress = await storage.getProgress(sessionId);
      res.json(progress);
    } catch (error) {
      console.error('Error getting progress:', error);
      res.status(500).json({ error: "Failed to get progress" });
    }
  });

  app.post("/api/progress/:sessionId", async (req, res) => {
    try {
      const { sessionId } = req.params;
      
      if (!validateSessionId(sessionId)) {
        return res.status(400).json({ error: "Invalid session ID format" });
      }
      
      const progress = req.body;
      const updatedProgress = await storage.updateProgress(sessionId, progress);
      res.json(updatedProgress);
    } catch (error) {
      console.error('Error updating progress:', error);
      res.status(500).json({ error: "Failed to update progress" });
    }
  });

  app.get("/api/attempts/:sessionId", async (req, res) => {
    try {
      const { sessionId } = req.params;
      
      if (!validateSessionId(sessionId)) {
        return res.status(400).json({ error: "Invalid session ID format" });
      }
      
      const attempts = await storage.getAttempts(sessionId);
      res.json({ attempts });
    } catch (error) {
      console.error('Error getting attempts:', error);
      res.status(500).json({ error: "Failed to get attempts" });
    }
  });

  app.post("/api/submit-flag/:sessionId", async (req, res) => {
    try {
      const { sessionId } = req.params;
      
      if (!validateSessionId(sessionId)) {
        return res.status(400).json({ 
          success: false,
          message: "Invalid session ID format",
          attempts: 0,
          hintsUnlocked: 0,
        });
      }
      
      const clientIp = (req.socket.remoteAddress || 'unknown').toString();
      
      if (!checkRateLimit(clientIp)) {
        return res.status(429).json({ 
          success: false,
          message: "Too many attempts. Please wait before trying again.",
          attempts: 0,
          hintsUnlocked: 0,
        });
      }
      
      const parsed = flagSubmissionSchema.safeParse(req.body);
      
      if (!parsed.success) {
        return res.status(400).json({ 
          success: false,
          message: "Invalid flag format",
          attempts: 0,
          hintsUnlocked: 0,
        });
      }

      const result = await storage.validateFlag(sessionId, parsed.data.flag);
      res.json(result);
    } catch (error) {
      console.error('Error validating flag:', error);
      res.status(500).json({ 
        success: false,
        message: "Server error",
        attempts: 0,
        hintsUnlocked: 0,
      });
    }
  });

  app.get("/api/hints/:sessionId", async (req, res) => {
    try {
      const { sessionId } = req.params;
      
      if (!validateSessionId(sessionId)) {
        return res.status(400).json({ error: "Invalid session ID format" });
      }
      
      const hints = await storage.getHints(sessionId);
      res.json(hints);
    } catch (error) {
      console.error('Error getting hints:', error);
      res.status(500).json({ error: "Failed to get hints" });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}
