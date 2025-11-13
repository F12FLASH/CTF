import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { validateURL } from "./ssrf-filter";
import { startFlagServer } from "./flag-server";
import { 
  fetchRequestSchema, 
  flagSubmissionSchema,
  type FetchResponse, 
  type FlagSubmissionResponse,
  type FlagSubmissionRecord,
  type SSRFAttempt 
} from "@shared/schema";
import { randomUUID, createHash } from "crypto";
import { rateLimiter, sanitizeInput, constantTimeCompare } from "./security";

const CORRECT_FLAG = 'VNFLAG{VANG_MAIVIETNAM_DAU_TUONG_ANH_HUNG_3K7r1P9m4Q8z6L2f0B5yXcG}';
const FLAG_HASH = createHash('sha256').update(CORRECT_FLAG).digest('hex');

export async function registerRoutes(app: Express): Promise<Server> {
  // Start the flag server on port 1337
  startFlagServer();

  // SSRF Fetch endpoint với rate limiting
  app.post("/api/fetch", rateLimiter(60000, 20), async (req, res) => {
    try {
      const startTime = Date.now();
      
      // Validate request body
      const parseResult = fetchRequestSchema.safeParse(req.body);
      if (!parseResult.success) {
        const response: FetchResponse = {
          success: false,
          status: 'error',
          message: 'Invalid request: URL is required',
        };
        return res.status(400).json(response);
      }

      const { url } = parseResult.data;
      
      const sanitizedUrl = sanitizeInput(url);
      if (!sanitizedUrl) {
        const response: FetchResponse = {
          success: false,
          status: 'error',
          message: 'URL không hợp lệ',
        };
        return res.status(400).json(response);
      }
      
      // Apply SSRF filter
      const filterResult = validateURL(sanitizedUrl);
      
      if (!filterResult.allowed) {
        // Log blocked attempt
        const attempt: SSRFAttempt = {
          id: randomUUID(),
          url: sanitizedUrl,
          timestamp: Date.now(),
          status: 'blocked',
          technique: 'N/A',
        };
        await storage.addAttempt(attempt);
        
        const response: FetchResponse = {
          success: false,
          status: 'blocked',
          message: 'Request blocked by filter',
          blockedReason: filterResult.reason,
          timing: Date.now() - startTime,
        };
        return res.status(403).json(response);
      }

      // Filter passed - attempt to fetch the URL
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        
        // Add challenge User-Agent - flag server uses this to verify requests
        // Disable automatic redirects to prevent redirect-based SSRF bypass
        const fetchResponse = await fetch(sanitizedUrl, {
          method: 'GET',
          signal: controller.signal,
          redirect: 'manual',
          headers: {
            'User-Agent': 'SSRF-to-Mars-CTF/1.0',
          },
        });
        
        clearTimeout(timeout);
        
        const responseText = await fetchResponse.text();
        const timing = Date.now() - startTime;
        
        // Capture all response headers
        const responseHeaders: Record<string, string> = {};
        fetchResponse.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });
        
        // Log successful attempt
        const attempt: SSRFAttempt = {
          id: randomUUID(),
          url: sanitizedUrl,
          timestamp: Date.now(),
          status: fetchResponse.ok ? 'success' : 'error',
          response: responseText.substring(0, 1000), // Limit stored response
          statusCode: fetchResponse.status,
        };
        await storage.addAttempt(attempt);
        
        const response: FetchResponse = {
          success: true,
          status: fetchResponse.ok ? 'success' : 'error',
          message: fetchResponse.ok 
            ? 'Request successful!' 
            : `Request completed with status ${fetchResponse.status}`,
          response: responseText,
          statusCode: fetchResponse.status,
          headers: responseHeaders,
          timing,
        };
        
        return res.json(response);
        
      } catch (fetchError: any) {
        const timing = Date.now() - startTime;
        
        // Log error attempt
        const attempt: SSRFAttempt = {
          id: randomUUID(),
          url: sanitizedUrl,
          timestamp: Date.now(),
          status: 'error',
          response: fetchError.message,
        };
        await storage.addAttempt(attempt);
        
        const response: FetchResponse = {
          success: false,
          status: 'error',
          message: 'Failed to fetch URL',
          response: `Error: ${fetchError.message}`,
          timing,
        };
        
        return res.status(500).json(response);
      }
      
    } catch (error: any) {
      console.error('[API] Error in /api/fetch:', error);
      const response: FetchResponse = {
        success: false,
        status: 'error',
        message: 'Internal server error',
        response: error.message,
      };
      return res.status(500).json(response);
    }
  });

  // Get attempt history (optional, for debugging)
  app.get("/api/attempts", async (req, res) => {
    try {
      const attempts = await storage.getAttempts();
      res.json(attempts);
    } catch (error) {
      res.status(500).json({ error: 'Failed to retrieve attempts' });
    }
  });

  // Flag submission endpoint with rate limiting
  app.post("/api/flag", rateLimiter(60000, 10), async (req, res) => {
    try {
      const parseResult = flagSubmissionSchema.safeParse(req.body);
      if (!parseResult.success) {
        const response: FlagSubmissionResponse = {
          success: false,
          message: 'Dữ liệu không hợp lệ: Flag phải có độ dài từ 1-200 ký tự',
        };
        return res.json(response);
      }

      const { flag, userAlias } = parseResult.data;
      const sanitizedFlag = sanitizeInput(flag);
      
      const submittedHash = createHash('sha256').update(sanitizedFlag).digest('hex');
      const isCorrect = constantTimeCompare(submittedHash, FLAG_HASH);
      
      const record: FlagSubmissionRecord = {
        id: randomUUID(),
        userAlias: userAlias ? sanitizeInput(userAlias) : undefined,
        timestamp: Date.now(),
        result: isCorrect ? 'success' : 'failure',
        ip: req.ip || req.socket.remoteAddress,
      };
      
      await storage.addFlagSubmission(record);
      
      if (isCorrect) {
        const response: FlagSubmissionResponse = {
          success: true,
          message: 'Chúc mừng! Bạn đã hoàn thành thử thách SSRF to Mars!',
          points: 500,
          timestamp: record.timestamp,
        };
        return res.json(response);
      } else {
        const response: FlagSubmissionResponse = {
          success: false,
          message: 'Flag không chính xác. Hãy thử lại!',
        };
        return res.json(response);
      }
    } catch (error: any) {
      console.error('[API] Error in /api/flag:', error);
      const response: FlagSubmissionResponse = {
        success: false,
        message: 'Lỗi hệ thống',
      };
      return res.status(500).json(response);
    }
  });

  // Get flag submission stats (doesn't reveal the flag)
  app.get("/api/flag/stats", async (req, res) => {
    try {
      const successCount = await storage.getSuccessCount();
      const submissions = await storage.getFlagSubmissions();
      res.json({
        totalSubmissions: submissions.length,
        successfulSubmissions: successCount,
        recentSubmissions: submissions.slice(-5).map(s => ({
          id: s.id,
          userAlias: s.userAlias || 'Anonymous',
          result: s.result,
          timestamp: s.timestamp,
        })),
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to retrieve stats' });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
