import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertSubmissionSchema } from "@shared/schema";
import { z } from "zod";
import { createRateLimit, getClientIp, sanitizeInput } from "./middleware/rate-limit";

export async function registerRoutes(app: Express): Promise<Server> {
  // Rate limiting: 10 attempts per 5 minutes per IP
  const submitRateLimit = createRateLimit({
    windowMinutes: 5,
    maxAttempts: 10,
    message: "Quá nhiều lần thử. Vui lòng đợi 5 phút trước khi thử lại.",
  });

  // Submit flag endpoint with rate limiting and IP tracking
  app.post("/api/submissions", submitRateLimit, async (req, res) => {
    try {
      const validatedData = insertSubmissionSchema.parse(req.body);
      
      // Sanitize input to prevent injection attacks
      const sanitizedFlag = sanitizeInput(validatedData.attemptedFlag);
      
      // Get client IP for tracking
      const clientIp = getClientIp(req);
      
      // Create submission with IP tracking
      const submission = await storage.createSubmission(
        { attemptedFlag: sanitizedFlag },
        clientIp
      );
      
      res.json({
        success: submission.isCorrect,
        message: submission.isCorrect 
          ? "🎉 Chúc mừng! Flag chính xác! Bạn đã hoàn thành thử thách này." 
          : "❌ Flag không đúng. Hãy phân tích kỹ hơn và thử lại!"
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ 
          error: "Dữ liệu không hợp lệ", 
          message: "Flag phải có định dạng đúng" 
        });
      } else {
        console.error("Submission error:", error);
        res.status(500).json({ error: "Lỗi hệ thống" });
      }
    }
  });

  // Get all submissions (for history) - limited for security
  app.get("/api/submissions", async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
      const submissions = await storage.getSubmissions(limit);
      res.json(submissions);
    } catch (error) {
      console.error("Fetch submissions error:", error);
      res.status(500).json({ error: "Không thể tải lịch sử" });
    }
  });

  // Get submission statistics
  app.get("/api/submissions/stats", async (req, res) => {
    try {
      const stats = await storage.getSubmissionStats();
      res.json(stats);
    } catch (error) {
      console.error("Fetch stats error:", error);
      res.status(500).json({ error: "Không thể tải thống kê" });
    }
  });

  // Binary download endpoint
  // NOTE: This is a placeholder/demo implementation. In a production CTF,
  // you would serve the actual compiled binary executable here.
  app.get("/api/download/binary", async (req, res) => {
    try {
      // Demo file with challenge information
      // TODO: Replace with actual binary file in production
      const challengeReadme = `
Quantum Crackme - Master Level CTF Challenge
============================================

⚠️  DEMO MODE: This is a placeholder file for demonstration purposes.
    In a real CTF deployment, this would be the actual binary executable.

Challenge Information:
- Name: Quantum Crackme
- Difficulty: ⭐⭐⭐⭐⭐ (Master)
- Category: Reverse Engineering
- Type: Binary Exploitation / CPU Emulation

Challenge Description:
A binary that exhibits different execution behavior depending on CPU type.
The program only reveals the flag when running in QEMU with a special
CPU type called "quantum".

Technical Requirements:
- CPUID instruction analysis
- QEMU emulation knowledge
- Binary patching skills
- Low-level debugging experience

Solution Approaches:
1. Patch CPUID checks in the binary
2. Reverse engineer QEMU source code
3. Dynamic analysis with custom QEMU build

Tools Needed:
- IDA Pro / Ghidra / Binary Ninja
- QEMU with source code
- GDB debugger
- Hex editor for patching

Flag Format: VNFLAG{...}

For more information, visit the challenge page.
Good luck!
`;

      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', 'attachment; filename="quantum_crackme_readme.txt"');
      res.send(challengeReadme);
    } catch (error) {
      res.status(500).json({ error: "Failed to download challenge file" });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}
