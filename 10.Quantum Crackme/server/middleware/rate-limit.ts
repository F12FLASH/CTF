import { Request, Response, NextFunction } from "express";
import { storage } from "../storage";

/**
 * Rate limiting configuration
 */
interface RateLimitConfig {
  windowMinutes: number;
  maxAttempts: number;
  message?: string;
}

/**
 * In-memory rate limit tracker for additional protection
 * Tracks attempts per IP address
 */
class RateLimiter {
  private attempts: Map<string, { count: number; resetTime: number }> = new Map();

  /**
   * Check if IP address has exceeded rate limit
   */
  isRateLimited(ip: string, config: RateLimitConfig): boolean {
    const now = Date.now();
    const record = this.attempts.get(ip);

    if (!record || now > record.resetTime) {
      // Reset or create new record
      this.attempts.set(ip, {
        count: 1,
        resetTime: now + config.windowMinutes * 60 * 1000,
      });
      return false;
    }

    // Increment attempts
    record.count++;

    // Check if exceeded limit
    if (record.count > config.maxAttempts) {
      return true;
    }

    return false;
  }

  /**
   * Clean up old entries (prevent memory leak)
   */
  cleanup() {
    const now = Date.now();
    const entries = Array.from(this.attempts.entries());
    for (const [ip, record] of entries) {
      if (now > record.resetTime) {
        this.attempts.delete(ip);
      }
    }
  }
}

const rateLimiter = new RateLimiter();

// Cleanup every 5 minutes
setInterval(() => rateLimiter.cleanup(), 5 * 60 * 1000);

/**
 * Rate limiting middleware factory
 * Prevents brute force attacks on flag submission
 */
export function createRateLimit(config: RateLimitConfig) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const ip = getClientIp(req);

    // Check in-memory rate limit first (fast)
    if (rateLimiter.isRateLimited(ip, config)) {
      return res.status(429).json({
        error: "Too many attempts",
        message: config.message || `Vui lòng đợi ${config.windowMinutes} phút trước khi thử lại`,
        retryAfter: config.windowMinutes * 60,
      });
    }

    // Check database for persistent rate limiting
    try {
      const recentAttempts = await storage.getRecentSubmissionsByIP(
        ip,
        config.windowMinutes
      );

      if (recentAttempts >= config.maxAttempts) {
        return res.status(429).json({
          error: "Too many attempts",
          message: config.message || `Bạn đã vượt quá giới hạn ${config.maxAttempts} lần thử trong ${config.windowMinutes} phút`,
          retryAfter: config.windowMinutes * 60,
        });
      }
    } catch (error) {
      // Log error but don't block request
      console.error("Rate limit check failed:", error);
    }

    next();
  };
}

/**
 * Get client IP address from request
 * Handles proxies and load balancers
 */
export function getClientIp(req: Request): string {
  // Check various headers for real IP
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const ips = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    return ips.split(",")[0].trim();
  }

  const realIp = req.headers["x-real-ip"];
  if (realIp) {
    return Array.isArray(realIp) ? realIp[0] : realIp;
  }

  return req.ip || req.socket.remoteAddress || "unknown";
}

/**
 * Sanitize input to prevent injection attacks
 */
export function sanitizeInput(input: string): string {
  // Remove any HTML tags and dangerous characters
  return input
    .replace(/[<>]/g, "")
    .replace(/javascript:/gi, "")
    .replace(/on\w+=/gi, "")
    .trim()
    .substring(0, 200); // Limit length
}
