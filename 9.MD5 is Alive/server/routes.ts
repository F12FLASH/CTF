import type { Express } from "express";
import { createServer, type Server } from "http";
import { createHash } from "crypto";
import { storage } from "./storage";
import { hashQuerySchema, flagSubmissionSchema } from "@shared/schema";
import { flagManager } from "./flag-manager";

export async function registerRoutes(app: Express): Promise<Server> {
  await flagManager.initialize();

  app.post("/api/hash", async (req, res) => {
    try {
      const { input } = hashQuerySchema.parse(req.body);
      
      const flag = flagManager.getFlag();
      const message = `${flag}||${input}`;
      
      const md5Hash = createHash("md5");
      md5Hash.update(message);
      const fullHash = md5Hash.digest("hex");
      
      const first4Bytes = fullHash.substring(0, 8);
      
      const result = await storage.addHashQuery(input, fullHash, first4Bytes);
      
      res.json(result);
    } catch (error) {
      console.error("Hash computation error:", error);
      res.status(400).json({ 
        error: error instanceof Error ? error.message : "Invalid request" 
      });
    }
  });

  app.get("/api/stats", async (_req, res) => {
    try {
      const stats = await storage.getStats();
      res.json(stats);
    } catch (error) {
      console.error("Stats retrieval error:", error);
      res.status(500).json({ 
        error: "Failed to retrieve statistics" 
      });
    }
  });

  app.post("/api/validate-flag", async (req, res) => {
    try {
      const { flag } = flagSubmissionSchema.parse(req.body);
      
      await storage.incrementAttempts();
      
      const correct = flagManager.validateFlag(flag);
      
      if (correct) {
        await storage.markAsSolved();
      }
      
      res.json({
        correct,
        message: correct 
          ? "Congratulations! You've successfully exploited the MD5 vulnerability!" 
          : "Incorrect flag. Keep analyzing the hash patterns!",
      });
    } catch (error) {
      console.error("Flag validation error:", error);
      res.status(400).json({ 
        error: error instanceof Error ? error.message : "Invalid request" 
      });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}
