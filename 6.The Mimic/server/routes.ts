import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { z } from "zod";
import { clientFlagSubmissionSchema } from "@shared/schema";
import { SecureFlagManager, xorEncrypt, xorDecrypt, generateKey, sanitizeInput } from "./crypto";
import { createRateLimiter, validateContentType, securityHeaders } from "./middleware";

const flagManager = new SecureFlagManager();

const CORRECT_FLAG = "VNFLAG{SONG_MAIVIETNAM_TU_HAO_VANG_DOANH_2P9r7K4m1Q8z6B3s0L5yFhXcG}";

const CORRECT_FLAG_HASH = flagManager.hashFlag(CORRECT_FLAG);

interface ChallengeState {
  currentKey: string;
  keyRotationCount: number;
  isTimeHooked: boolean;
  keyRotationInterval: NodeJS.Timeout | null;
}

const challengeStates = new Map<string, ChallengeState>();

function getOrCreateSessionState(sessionId: string = 'default'): ChallengeState {
  if (!challengeStates.has(sessionId)) {
    challengeStates.set(sessionId, {
      currentKey: generateKey(),
      keyRotationCount: 0,
      isTimeHooked: false,
      keyRotationInterval: null,
    });
  }
  return challengeStates.get(sessionId)!;
}

export async function registerRoutes(app: Express): Promise<Server> {
  app.use(securityHeaders);
  app.use(validateContentType);

  const submitRateLimit = createRateLimiter(10, 60000);
  const generalRateLimit = createRateLimiter(100, 60000);

  app.post("/api/start-challenge", generalRateLimit, async (req, res) => {
    try {
      const sessionId = req.ip || 'default';
      const state = getOrCreateSessionState(sessionId);

      state.currentKey = generateKey();
      state.keyRotationCount = 0;
      state.isTimeHooked = false;

      if (state.keyRotationInterval) {
        clearInterval(state.keyRotationInterval);
      }

      state.keyRotationInterval = setInterval(() => {
        if (!state.isTimeHooked) {
          state.currentKey = generateKey();
          state.keyRotationCount++;
        }
      }, 10);

      const encryptedFlag = xorEncrypt(CORRECT_FLAG, state.currentKey);

      await storage.createChallengeState({
        encryptedFlag,
        currentKey: state.currentKey,
        keyRotationCount: state.keyRotationCount,
        isTimeHooked: false,
        wasmExecutionStatus: "running",
      });

      res.json({
        success: true,
        message: "Challenge started successfully"
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to start challenge" });
    }
  });

  app.get("/api/challenge-data", generalRateLimit, async (req, res) => {
    try {
      const sessionId = req.ip || 'default';
      const state = getOrCreateSessionState(sessionId);

      const encryptedFlag = xorEncrypt(CORRECT_FLAG, state.currentKey);

      res.json({
        encryptedFlag,
        keyRotationCount: state.keyRotationCount,
        isTimeHooked: state.isTimeHooked,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch challenge data" });
    }
  });

  app.get("/api/get-frozen-key", generalRateLimit, async (req, res) => {
    try {
      const sessionId = req.ip || 'default';
      const state = getOrCreateSessionState(sessionId);

      if (!state.isTimeHooked) {
        return res.status(403).json({ 
          error: "Time must be hooked to access the frozen key",
          hint: "Use the Hook time() button first"
        });
      }

      res.json({
        frozenKey: state.currentKey,
        message: "Key captured successfully. Use this to decrypt the flag."
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to retrieve frozen key" });
    }
  });

  app.post("/api/hook-time", generalRateLimit, async (req, res) => {
    try {
      const { hook } = z.object({
        hook: z.boolean(),
      }).parse(req.body);

      const sessionId = req.ip || 'default';
      const state = getOrCreateSessionState(sessionId);

      state.isTimeHooked = hook;

      if (hook && state.keyRotationInterval) {
        clearInterval(state.keyRotationInterval);
        state.keyRotationInterval = null;
      } else if (!hook && !state.keyRotationInterval) {
        state.keyRotationInterval = setInterval(() => {
          if (!state.isTimeHooked) {
            state.currentKey = generateKey();
            state.keyRotationCount++;
          }
        }, 10);
      }

      const currentState = await storage.getCurrentChallengeState();
      if (currentState) {
        await storage.updateChallengeState(currentState.id, {
          isTimeHooked: hook,
          currentKey: state.currentKey,
        });
      }

      res.json({
        success: true,
        isHooked: state.isTimeHooked,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid request format" });
      }
      res.status(500).json({ error: "Failed to hook time" });
    }
  });

  app.get("/api/hints", generalRateLimit, async (_req, res) => {
    try {
      const hints = await storage.getAllHints();
      res.json(hints);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch hints" });
    }
  });

  app.post("/api/hints/:id/reveal", generalRateLimit, async (req, res) => {
    try {
      const { id } = req.params;
      
      if (!id || !/^[0-9a-f-]+$/i.test(id)) {
        return res.status(400).json({ error: "Invalid hint ID" });
      }

      const hint = await storage.revealHint(id);
      
      if (!hint) {
        return res.status(404).json({ error: "Hint not found" });
      }

      res.json(hint);
    } catch (error) {
      res.status(500).json({ error: "Failed to reveal hint" });
    }
  });

  app.post("/api/submit-flag", submitRateLimit, async (req, res) => {
    try {
      const { submittedFlag: rawFlag } = clientFlagSubmissionSchema.parse(req.body);
      
      const submittedFlag = sanitizeInput(rawFlag, 200);
      
      const isCorrect = flagManager.verifyFlag(submittedFlag, CORRECT_FLAG_HASH);
      
      await storage.createFlagSubmission({
        submittedFlag: submittedFlag.substring(0, 100),
        isCorrect,
      });

      const sessionId = req.ip || 'default';
      const state = challengeStates.get(sessionId);
      
      if (isCorrect && state?.keyRotationInterval) {
        clearInterval(state.keyRotationInterval);
        state.keyRotationInterval = null;
      }

      if (isCorrect) {
        res.json({
          success: true,
          message: "Congratulations! Flag is correct!",
          flag: CORRECT_FLAG
        });
      } else {
        res.json({
          success: false,
          message: "Incorrect flag. Keep trying!"
        });
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid submission format" });
      }
      res.status(500).json({ error: "Failed to submit flag" });
    }
  });

  app.get("/api/stats", generalRateLimit, async (_req, res) => {
    try {
      const allSubmissions = await storage.getAllFlagSubmissions();
      const correctSubmissions = await storage.getCorrectSubmissions();

      res.json({
        totalAttempts: allSubmissions.length,
        solves: correctSubmissions.length,
        successRate: allSubmissions.length > 0 
          ? (correctSubmissions.length / allSubmissions.length) * 100 
          : 0,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch statistics" });
    }
  });

  app.post("/api/verify-decryption", generalRateLimit, async (req, res) => {
    try {
      const { encryptedFlag, key } = z.object({
        encryptedFlag: z.string().max(10000),
        key: z.string().max(100),
      }).parse(req.body);

      const sanitizedKey = sanitizeInput(key, 100);
      
      let decrypted: string;
      let isCorrect: boolean;
      
      try {
        decrypted = xorDecrypt(encryptedFlag, sanitizedKey);
        isCorrect = flagManager.verifyFlag(decrypted, CORRECT_FLAG_HASH);
      } catch {
        return res.status(400).json({ 
          error: "Decryption failed. Invalid encrypted data or key." 
        });
      }

      res.json({
        decrypted: isCorrect ? decrypted : "Decryption complete (incorrect result)",
        isCorrect,
        message: isCorrect 
          ? "Decryption successful! This is the correct flag." 
          : "Decryption complete, but this is not the correct flag.",
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid request format" });
      }
      res.status(500).json({ error: "Failed to verify decryption" });
    }
  });

  app.get("/api/health", (_req, res) => {
    res.json({ 
      status: "ok", 
      challenge: "The Mimic", 
      difficulty: "master_hacker",
      version: "2.0.0"
    });
  });

  const httpServer = createServer(app);

  process.on('SIGTERM', () => {
    challengeStates.forEach(state => {
      if (state.keyRotationInterval) {
        clearInterval(state.keyRotationInterval);
      }
    });
    challengeStates.clear();
  });

  return httpServer;
}
