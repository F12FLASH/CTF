import type { Request, Response, NextFunction } from "express";

// Rate limiting store
interface RateLimitEntry {
  count: number;
  firstRequest: number;
  blocked: boolean;
  blockExpiry?: number;
}

class RateLimiter {
  private limits: Map<string, RateLimitEntry> = new Map();
  private readonly windowMs: number;
  private readonly maxRequests: number;
  private readonly blockDurationMs: number;

  constructor(windowMs: number = 60000, maxRequests: number = 10, blockDurationMs: number = 300000) {
    this.windowMs = windowMs; // 1 minute window
    this.maxRequests = maxRequests; // 10 requests per window
    this.blockDurationMs = blockDurationMs; // 5 minutes block

    // Cleanup old entries every minute
    setInterval(() => this.cleanup(), 60000);
  }

  private cleanup() {
    const now = Date.now();
    const entries = Array.from(this.limits.entries());
    for (const [key, entry] of entries) {
      // Remove entries older than window or expired blocks
      if (
        (!entry.blocked && now - entry.firstRequest > this.windowMs) ||
        (entry.blocked && entry.blockExpiry && now > entry.blockExpiry)
      ) {
        this.limits.delete(key);
      }
    }
  }

  check(identifier: string): { allowed: boolean; retryAfter?: number } {
    const now = Date.now();
    const entry = this.limits.get(identifier);

    if (!entry) {
      this.limits.set(identifier, {
        count: 1,
        firstRequest: now,
        blocked: false,
      });
      return { allowed: true };
    }

    // Check if currently blocked
    if (entry.blocked && entry.blockExpiry) {
      if (now < entry.blockExpiry) {
        const retryAfter = Math.ceil((entry.blockExpiry - now) / 1000);
        return { allowed: false, retryAfter };
      } else {
        // Block expired, reset
        this.limits.delete(identifier);
        return this.check(identifier);
      }
    }

    // Check if window has expired
    if (now - entry.firstRequest > this.windowMs) {
      entry.count = 1;
      entry.firstRequest = now;
      return { allowed: true };
    }

    // Increment count
    entry.count++;

    if (entry.count > this.maxRequests) {
      // Block the identifier
      entry.blocked = true;
      entry.blockExpiry = now + this.blockDurationMs;
      const retryAfter = Math.ceil(this.blockDurationMs / 1000);
      return { allowed: false, retryAfter };
    }

    return { allowed: true };
  }
}

// Global rate limiters
const flagSubmissionLimiter = new RateLimiter(60000, 5, 600000); // 5 attempts per minute, 10 min block
const generalLimiter = new RateLimiter(60000, 100, 60000); // 100 requests per minute, 1 min block

// Get client identifier (IP address)
function getClientIdentifier(req: Request): string {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.socket.remoteAddress ||
    'unknown'
  );
}

// Rate limiting middleware for flag submissions
export function flagSubmissionRateLimit(req: Request, res: Response, next: NextFunction) {
  const identifier = getClientIdentifier(req);
  const result = flagSubmissionLimiter.check(identifier);

  if (!result.allowed) {
    return res.status(429).json({
      correct: false,
      message: `Quá nhiều lần thử. Vui lòng đợi ${result.retryAfter} giây trước khi thử lại.`,
      retryAfter: result.retryAfter,
    });
  }

  next();
}

// General rate limiting middleware
export function generalRateLimit(req: Request, res: Response, next: NextFunction) {
  // Skip rate limiting for Vite dev server resources
  if (req.path.startsWith('/@') || 
      req.path.startsWith('/node_modules') || 
      req.path.includes('.vite') ||
      req.path.endsWith('.js') ||
      req.path.endsWith('.css') ||
      req.path.endsWith('.ts') ||
      req.path.endsWith('.tsx')) {
    return next();
  }

  const identifier = getClientIdentifier(req);
  const result = generalLimiter.check(identifier);

  if (!result.allowed) {
    return res.status(429).json({
      error: 'Too many requests',
      retryAfter: result.retryAfter,
    });
  }

  next();
}

// Security headers middleware
export function securityHeaders(req: Request, res: Response, next: NextFunction) {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Prevent MIME sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // XSS Protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Referrer Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Content Security Policy
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;"
  );

  next();
}

// Input sanitization middleware
export function sanitizeInput(req: Request, res: Response, next: NextFunction) {
  if (req.body) {
    for (const key in req.body) {
      if (typeof req.body[key] === 'string') {
        // Remove potential XSS patterns
        req.body[key] = req.body[key]
          .replace(/<script[^>]*>.*?<\/script>/gi, '')
          .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
          .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
          .trim();
      }
    }
  }
  next();
}

// Request size limiter
export function requestSizeLimit(maxSize: number = 100 * 1024) {
  return (req: Request, res: Response, next: NextFunction) => {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    
    if (contentLength > maxSize) {
      return res.status(413).json({
        error: 'Request entity too large',
      });
    }
    
    next();
  };
}

// Logging middleware for security events
export function securityLogger(req: Request, res: Response, next: NextFunction) {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const identifier = getClientIdentifier(req);
    
    // Log suspicious activity
    if (res.statusCode === 429 || res.statusCode === 413) {
      console.warn(`[SECURITY] ${new Date().toISOString()} - ${req.method} ${req.path} - Status: ${res.statusCode} - IP: ${identifier} - Duration: ${duration}ms`);
    }
    
    // Log flag submissions
    if (req.path === '/api/submit-flag' && req.method === 'POST') {
      console.log(`[FLAG_SUBMISSION] ${new Date().toISOString()} - IP: ${identifier} - Status: ${res.statusCode}`);
    }
  });
  
  next();
}
