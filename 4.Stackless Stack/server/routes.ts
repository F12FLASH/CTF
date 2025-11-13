import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { flagSubmissionSchema } from "@shared/schema";
import path from "path";
import { randomUUID } from "crypto";

const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

function ensureSessionId(req: Request): string {
  if (!req.session.id) {
    req.session.id = randomUUID();
  }
  return req.session.id;
}

function getRateLimitIdentifier(req: Request): string {
  if (req.session?.id) {
    return `session:${req.session.id}`;
  }
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || 
             req.socket.remoteAddress || 
             'unknown';
  return `ip:${ip}`;
}

function rateLimit(maxRequests: number, windowMs: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    ensureSessionId(req);
    const identifier = getRateLimitIdentifier(req);
    const now = Date.now();
    const record = rateLimitStore.get(identifier);

    if (!record || now > record.resetTime) {
      rateLimitStore.set(identifier, { count: 1, resetTime: now + windowMs });
      return next();
    }

    if (record.count >= maxRequests) {
      return res.status(429).json({ 
        error: "Quá nhiều yêu cầu", 
        message: "Vui lòng đợi trước khi thử lại",
        retryAfter: Math.ceil((record.resetTime - now) / 1000)
      });
    }

    record.count++;
    next();
  };
}

function validateInput(req: Request, res: Response, next: NextFunction) {
  if (req.body) {
    for (const [key, value] of Object.entries(req.body)) {
      if (typeof value === 'string') {
        if (value.length > 10000) {
          return res.status(400).json({ 
            error: "Dữ liệu quá lớn", 
            field: key,
            message: "Dữ liệu vượt quá độ dài tối đa cho phép"
          });
        }
      }
    }
  }
  next();
}

function sanitizeChallengeId(id: string): string | null {
  const sanitized = id.replace(/[^a-zA-Z0-9-_]/g, '');
  if (sanitized.length === 0 || sanitized.length > 100) {
    return null;
  }
  return sanitized;
}

export async function registerRoutes(app: Express): Promise<Server> {
  app.use(validateInput);

  const getSessionId = (req: Request): string => {
    return ensureSessionId(req);
  };

  app.get("/api/challenge/:id", rateLimit(60, 60000), async (req: Request, res: Response) => {
    try {
      const sanitizedId = sanitizeChallengeId(req.params.id);
      if (!sanitizedId) {
        return res.status(400).json({ error: "Định dạng ID thử thách không hợp lệ" });
      }

      const challenge = await storage.getChallenge(sanitizedId);
      
      if (!challenge) {
        return res.status(404).json({ error: "Không tìm thấy thử thách" });
      }
      
      const { flag, ...challengeWithoutFlag } = challenge;
      return res.json(challengeWithoutFlag);
    } catch (error) {
      console.error("Error fetching challenge:", error);
      return res.status(500).json({ error: "Lỗi máy chủ nội bộ" });
    }
  });

  app.get("/api/hints/:challengeId", rateLimit(60, 60000), async (req: Request, res: Response) => {
    try {
      const sanitizedId = sanitizeChallengeId(req.params.challengeId);
      if (!sanitizedId) {
        return res.status(400).json({ error: "Định dạng ID thử thách không hợp lệ" });
      }

      const sessionId = getSessionId(req);
      const allHints = await storage.getHintsByChallenge(sanitizedId);
      const unlockedHintIds = await storage.getUnlockedHints(sessionId, sanitizedId);
      
      const hints = allHints.map(hint => {
        const isUnlocked = unlockedHintIds.includes(hint.id);
        return {
          id: hint.id,
          challengeId: hint.challengeId,
          order: hint.order,
          content: isUnlocked ? hint.content : null,
          pointsCost: hint.pointsCost,
          unlocked: isUnlocked,
        };
      });
      
      return res.json(hints);
    } catch (error) {
      console.error("Error fetching hints:", error);
      return res.status(500).json({ error: "Lỗi máy chủ nội bộ" });
    }
  });

  app.post("/api/unlock-hint", rateLimit(10, 60000), async (req: Request, res: Response) => {
    try {
      const { challengeId, hintId } = req.body;
      
      if (!challengeId || !hintId) {
        return res.status(400).json({ error: "Thiếu challengeId hoặc hintId" });
      }

      const sanitizedChallengeId = sanitizeChallengeId(challengeId);
      if (!sanitizedChallengeId) {
        return res.status(400).json({ error: "Định dạng ID thử thách không hợp lệ" });
      }

      if (typeof hintId !== 'string' || hintId.length === 0 || hintId.length > 100) {
        return res.status(400).json({ error: "Định dạng ID gợi ý không hợp lệ" });
      }

      const allHints = await storage.getHintsByChallenge(sanitizedChallengeId);
      const hint = allHints.find(h => h.id === hintId);
      
      if (!hint) {
        return res.status(404).json({ error: "Không tìm thấy gợi ý cho thử thách này" });
      }

      if (hint.challengeId !== sanitizedChallengeId) {
        return res.status(400).json({ error: "Gợi ý không thuộc về thử thách này" });
      }

      const sessionId = getSessionId(req);
      await storage.unlockHint(sessionId, sanitizedChallengeId, hintId);

      return res.json({
        success: true,
        hint: {
          id: hint.id,
          challengeId: hint.challengeId,
          order: hint.order,
          content: hint.content,
          pointsCost: hint.pointsCost,
          unlocked: true,
        },
      });
    } catch (error) {
      console.error("Error unlocking hint:", error);
      return res.status(500).json({ error: "Lỗi máy chủ nội bộ" });
    }
  });

  app.post("/api/submit-flag", rateLimit(5, 60000), async (req: Request, res: Response) => {
    try {
      const validation = flagSubmissionSchema.safeParse(req.body);
      
      if (!validation.success) {
        return res.status(400).json({ 
          error: "Yêu cầu không hợp lệ",
          details: validation.error.issues 
        });
      }

      const { challengeId, flag } = validation.data;

      const sanitizedChallengeId = sanitizeChallengeId(challengeId);
      if (!sanitizedChallengeId) {
        return res.status(400).json({ error: "Định dạng ID thử thách không hợp lệ" });
      }
      
      if (flag.length > 500) {
        return res.status(400).json({ error: "Flag quá dài" });
      }
      
      const challenge = await storage.getChallenge(sanitizedChallengeId);
      
      if (!challenge) {
        return res.status(404).json({ error: "Không tìm thấy thử thách" });
      }

      const isCorrect = flag === challenge.flag;
      
      await storage.createSubmission({
        challengeId: sanitizedChallengeId,
        flag,
        correct: isCorrect,
      });

      if (isCorrect) {
        await storage.updateChallengeSolves(sanitizedChallengeId, challenge.solves + 1);
        
        return res.json({
          correct: true,
          message: "Chúc mừng! Flag chính xác. Bạn đã khai thác thành công stackless stack!",
        });
      } else {
        return res.json({
          correct: false,
          message: "Flag không đúng. Hãy tiếp tục phân tích binary và cải thiện khai thác của bạn.",
        });
      }
    } catch (error) {
      console.error("Error submitting flag:", error);
      return res.status(500).json({ error: "Lỗi máy chủ nội bộ" });
    }
  });

  app.get("/api/writeup/:challengeId", rateLimit(30, 60000), async (req: Request, res: Response) => {
    try {
      const sanitizedId = sanitizeChallengeId(req.params.challengeId);
      if (!sanitizedId) {
        return res.status(400).json({ error: "Định dạng ID thử thách không hợp lệ" });
      }

      const sections = await storage.getWriteupSectionsByChallenge(sanitizedId);
      return res.json(sections);
    } catch (error) {
      console.error("Error fetching writeup:", error);
      return res.status(500).json({ error: "Lỗi máy chủ nội bộ" });
    }
  });

  app.get("/api/download/:filename", rateLimit(20, 60000), async (req: Request, res: Response) => {
    try {
      const filename = req.params.filename;
      const allowedFiles = ['stackless_stack.c', 'README.txt'];
      
      const sanitizedFilename = filename.replace(/[^a-zA-Z0-9._-]/g, '');
      
      if (!allowedFiles.includes(sanitizedFilename)) {
        return res.status(404).json({ error: "Không tìm thấy file" });
      }

      const filePath = path.join(process.cwd(), 'public', 'downloads', sanitizedFilename);
      
      if (!filePath.startsWith(path.join(process.cwd(), 'public', 'downloads'))) {
        return res.status(403).json({ error: "Truy cập bị từ chối" });
      }

      return res.download(filePath, sanitizedFilename);
    } catch (error) {
      console.error("Error downloading file:", error);
      return res.status(500).json({ error: "Lỗi máy chủ nội bộ" });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}
