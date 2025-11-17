import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import {
  encryptRequestSchema,
  knownPlaintextAttackSchema,
  flagVerificationSchema,
  challengeGenerateSchema,
} from "@shared/schema";
import {
  encryptOTP,
  encryptOTPSecure,
  sha256,
  calculateEntropy,
  calculateByteFrequency,
  calculateAverageByteValue,
  performXorAnalysis,
  recoverKeystreamFromKnownPlaintext,
} from "./crypto-utils";
import {
  getExpectedFlag,
  generateChallengeData,
  sanitizeInput,
  validateHexString,
  validateInteger,
  checkRateLimit,
} from "./security";

function isValidHex(str: string): boolean {
  return validateHexString(str);
}

export async function registerRoutes(app: Express): Promise<Server> {
  app.post("/api/encrypt", async (req, res) => {
    try {
      const ip = req.ip || 'unknown';
      if (!checkRateLimit(ip, '/api/encrypt')) {
        return res.status(429).json({ error: 'Too many requests for this endpoint' });
      }
      
      const { plaintext } = encryptRequestSchema.parse(req.body);
      
      const sanitizedPlaintext = sanitizeInput(plaintext, 50000);
      
      const result = encryptOTP(sanitizedPlaintext);
      
      await storage.addCiphertext(result.ciphertext, result.ciphertext.length);
      
      res.json(result);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.post("/api/ciphertexts/upload", async (req, res) => {
    try {
      const ip = req.ip || 'unknown';
      if (!checkRateLimit(ip, '/api/ciphertexts/upload')) {
        return res.status(429).json({ error: 'Too many requests for this endpoint' });
      }
      
      const { data } = req.body;
      
      if (!data || typeof data !== "string") {
        return res.status(400).json({ error: "Invalid ciphertext data" });
      }
      
      const cleanData = sanitizeInput(data).replace(/\s+/g, "");
      
      if (cleanData.length > 100000) {
        return res.status(400).json({ error: "Ciphertext too large (max 100KB)" });
      }
      
      if (!validateHexString(cleanData)) {
        return res.status(400).json({ 
          error: "Ciphertext must be in hexadecimal format (0-9, a-f, A-F)" 
        });
      }
      
      const existingCiphertexts = await storage.getAllCiphertexts();
      if (existingCiphertexts.length >= 1000) {
        return res.status(400).json({ error: "Maximum 1000 ciphertexts allowed" });
      }
      
      if (existingCiphertexts.length > 0) {
        const expectedLength = existingCiphertexts[0].data.length;
        if (cleanData.length !== expectedLength) {
          return res.status(400).json({ 
            error: `Ciphertext length mismatch. Expected ${expectedLength} hex chars, got ${cleanData.length}` 
          });
        }
      }
      
      const ciphertext = await storage.addCiphertext(cleanData, cleanData.length);
      res.json(ciphertext);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.get("/api/ciphertexts", async (_req, res) => {
    try {
      const ciphertexts = await storage.getAllCiphertexts();
      res.json(ciphertexts);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.delete("/api/ciphertexts", async (_req, res) => {
    try {
      await storage.clearCiphertexts();
      res.json({ message: "All ciphertexts cleared" });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.post("/api/analysis/statistical", async (_req, res) => {
    try {
      const ciphertexts = await storage.getAllCiphertexts();
      
      if (ciphertexts.length === 0) {
        return res.status(400).json({ error: "No ciphertexts to analyze" });
      }
      
      const buffers: Buffer[] = [];
      for (const ct of ciphertexts) {
        try {
          buffers.push(Buffer.from(ct.data, "hex"));
        } catch (err) {
          return res.status(400).json({ 
            error: `Invalid hex data in ciphertext ${ct.id}` 
          });
        }
      }
      
      if (buffers.length === 0) {
        return res.status(400).json({ error: "No valid ciphertexts to analyze" });
      }
      
      const keyLength = buffers[0].length;
      for (let i = 1; i < buffers.length; i++) {
        if (buffers[i].length !== keyLength) {
          return res.status(400).json({ 
            error: `Ciphertext length mismatch. First ciphertext has ${keyLength} bytes, but ciphertext ${i} has ${buffers[i].length} bytes. All ciphertexts must have the same length.` 
          });
        }
      }
      
      let totalEntropy = 0;
      for (const buffer of buffers) {
        totalEntropy += calculateEntropy(buffer);
      }
      const averageEntropy = totalEntropy / buffers.length;
      
      const byteFrequency = calculateByteFrequency(buffers);
      const averageByteValue = calculateAverageByteValue(buffers);
      
      const analysis = {
        totalCiphertexts: ciphertexts.length,
        keyLength,
        entropy: averageEntropy,
        byteFrequency,
        averageByteValue,
      };
      
      await storage.saveStatisticalAnalysis(analysis);
      res.json(analysis);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/analysis/statistical", async (_req, res) => {
    try {
      const analysis = await storage.getStatisticalAnalysis();
      if (!analysis) {
        return res.status(404).json({ error: "No statistical analysis found" });
      }
      res.json(analysis);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.post("/api/analysis/xor", async (req, res) => {
    try {
      const ip = req.ip || 'unknown';
      if (!checkRateLimit(ip, '/api/analysis/xor')) {
        return res.status(429).json({ error: 'Too many requests for this endpoint' });
      }
      
      const { index1, index2 } = req.body;
      
      if (!validateInteger(index1, 0) || !validateInteger(index2, 0)) {
        return res.status(400).json({ error: "Indices must be non-negative integers" });
      }
      
      if (index1 === index2) {
        return res.status(400).json({ error: "Cannot XOR ciphertext with itself" });
      }
      
      const ciphertexts = await storage.getAllCiphertexts();
      
      if (ciphertexts.length === 0) {
        return res.status(400).json({ error: "No ciphertexts available for analysis" });
      }
      
      if (index1 >= ciphertexts.length || index2 >= ciphertexts.length) {
        return res.status(400).json({ error: `Index out of range. Available ciphertexts: 0-${ciphertexts.length - 1}` });
      }
      
      let ct1: Buffer, ct2: Buffer;
      try {
        ct1 = Buffer.from(ciphertexts[index1].data, "hex");
        ct2 = Buffer.from(ciphertexts[index2].data, "hex");
      } catch (err) {
        return res.status(400).json({ 
          error: "Invalid hex data in ciphertext" 
        });
      }
      
      if (ct1.length !== ct2.length) {
        return res.status(400).json({ 
          error: `Ciphertext length mismatch. CT[${index1}] has ${ct1.length} bytes, CT[${index2}] has ${ct2.length} bytes` 
        });
      }
      
      const { xorResult, patterns } = performXorAnalysis(ct1, ct2);
      
      const analysis = {
        pairIndex1: index1,
        pairIndex2: index2,
        xorResult,
        patterns,
      };
      
      await storage.saveXorAnalysis(analysis);
      res.json(analysis);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/analysis/xor", async (_req, res) => {
    try {
      const analyses = await storage.getAllXorAnalyses();
      res.json(analyses);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.post("/api/attack/known-plaintext", async (req, res) => {
    try {
      const ip = req.ip || 'unknown';
      if (!checkRateLimit(ip, '/api/attack/known-plaintext')) {
        return res.status(429).json({ error: 'Too many requests for this endpoint' });
      }
      
      const { knownPrefix } = knownPlaintextAttackSchema.parse(req.body);
      const sanitizedPrefix = sanitizeInput(knownPrefix, 1000);
      
      const ciphertexts = await storage.getAllCiphertexts();
      
      if (ciphertexts.length === 0) {
        return res.status(400).json({ error: "No ciphertexts available for attack" });
      }
      
      const buffers: Buffer[] = [];
      for (const ct of ciphertexts) {
        try {
          buffers.push(Buffer.from(ct.data, "hex"));
        } catch (err) {
          return res.status(400).json({ 
            error: "Invalid hex data in ciphertext" 
          });
        }
      }
      
      const recovery = recoverKeystreamFromKnownPlaintext(buffers, sanitizedPrefix);
      
      await storage.saveKeystreamRecovery(recovery);
      res.json(recovery);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.get("/api/attack/keystream", async (_req, res) => {
    try {
      const recovery = await storage.getKeystreamRecovery();
      if (!recovery) {
        return res.status(404).json({ error: "No keystream recovery found" });
      }
      res.json(recovery);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.post("/api/flag/verify", async (req, res) => {
    try {
      const ip = req.ip || 'unknown';
      if (!checkRateLimit(ip, '/api/flag/verify')) {
        return res.status(429).json({ error: 'Too many requests for this endpoint' });
      }
      
      const { flag } = flagVerificationSchema.parse(req.body);
      const sanitizedFlag = sanitizeInput(flag, 500);
      
      const providedHash = sha256(sanitizedFlag);
      const expectedFlag = getExpectedFlag();
      const expectedHash = sha256(expectedFlag);
      
      const valid = providedHash === expectedHash;
      
      res.json({
        valid,
        providedHash,
        expectedHash: valid ? expectedHash : undefined,
        message: valid
          ? "Congratulations! You've successfully solved the One-Time-Pad Revenge challenge!"
          : "The provided flag is incorrect. Continue analyzing the ciphertexts.",
      });
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.post("/api/challenge/generate", async (req, res) => {
    try {
      const ip = req.ip || 'unknown';
      if (!checkRateLimit(ip, '/api/challenge/generate')) {
        return res.status(429).json({ error: 'Too many requests for this endpoint' });
      }
      
      const { count } = challengeGenerateSchema.parse(req.body);
      
      if (!validateInteger(count, 1, 1000)) {
        return res.status(400).json({ error: "Count must be between 1 and 1000" });
      }
      
      const { plaintext, keyHash } = generateChallengeData();
      
      await storage.clearCiphertexts();
      
      const ciphertexts: string[] = [];
      
      for (let i = 0; i < count; i++) {
        const ciphertext = encryptOTPSecure(plaintext, keyHash);
        await storage.addCiphertext(ciphertext, ciphertext.length);
        ciphertexts.push(ciphertext);
      }
      
      res.json({
        message: `Successfully generated ${count} ciphertexts`,
        count: ciphertexts.length,
        plaintextHint: plaintext.substring(0, 50) + "...",
      });
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  app.get("/api/ciphertexts/download", async (_req, res) => {
    try {
      const ciphertexts = await storage.getAllCiphertexts();
      
      if (ciphertexts.length === 0) {
        return res.status(400).json({ error: "No ciphertexts to download" });
      }
      
      const data = ciphertexts.map(ct => ct.data).join("\n");
      
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", "attachment; filename=ciphertexts.txt");
      res.send(data);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
