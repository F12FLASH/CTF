import type { Request, Response, NextFunction } from "express";

interface RateLimitStore {
  [key: string]: {
    count: number;
    resetTime: number;
    blocked: boolean;
    attempts: number[];
    failedAttempts: number[];
  };
}

const store: RateLimitStore = {};
const RATE_LIMIT_WINDOW = 60 * 1000;
const MAX_REQUESTS = 10;
const MAX_FAILED_ATTEMPTS = 5;
const BLOCK_DURATION = 5 * 60 * 1000;

export function getRateLimiter() {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    
    if (!store[ip]) {
      store[ip] = {
        count: 0,
        resetTime: now + RATE_LIMIT_WINDOW,
        blocked: false,
        attempts: [],
        failedAttempts: []
      };
    }
    
    const record = store[ip];
    
    if (record.blocked && now < record.resetTime) {
      return res.status(429).json({
        success: false,
        message: 'Quá nhiều yêu cầu. IP của bạn đã bị chặn tạm thời. Vui lòng thử lại sau.',
        retryAfter: Math.ceil((record.resetTime - now) / 1000)
      });
    }
    
    if (record.blocked && now >= record.resetTime) {
      record.count = 0;
      record.blocked = false;
      record.attempts = [];
      record.failedAttempts = [];
      record.resetTime = now + RATE_LIMIT_WINDOW;
    } else if (now > record.resetTime) {
      record.count = 0;
      record.resetTime = now + RATE_LIMIT_WINDOW;
      record.attempts = [];
      record.failedAttempts = record.failedAttempts.filter(t => now - t < RATE_LIMIT_WINDOW);
    }
    
    record.count++;
    record.attempts.push(now);
    
    if (record.count > MAX_REQUESTS) {
      record.blocked = true;
      record.resetTime = now + BLOCK_DURATION;
      
      console.warn(`[SECURITY] Rate limit exceeded for IP: ${ip}`);
      
      return res.status(429).json({
        success: false,
        message: 'Quá nhiều yêu cầu. Vui lòng chờ một chút.',
        retryAfter: Math.ceil(BLOCK_DURATION / 1000)
      });
    }
    
    res.setHeader('X-RateLimit-Limit', MAX_REQUESTS.toString());
    res.setHeader('X-RateLimit-Remaining', (MAX_REQUESTS - record.count).toString());
    res.setHeader('X-RateLimit-Reset', Math.ceil(record.resetTime / 1000).toString());
    
    next();
  };
}

export function trackFailedAttempt(ip: string): boolean {
  if (!store[ip]) {
    store[ip] = {
      count: 0,
      resetTime: Date.now() + RATE_LIMIT_WINDOW,
      blocked: false,
      attempts: [],
      failedAttempts: []
    };
  }
  
  const record = store[ip];
  const now = Date.now();
  
  record.failedAttempts = record.failedAttempts.filter(t => now - t < RATE_LIMIT_WINDOW);
  record.failedAttempts.push(now);
  
  if (record.failedAttempts.length >= MAX_FAILED_ATTEMPTS) {
    record.blocked = true;
    record.resetTime = now + BLOCK_DURATION;
    
    console.warn(`[SECURITY] Too many failed attempts for IP: ${ip} (${record.failedAttempts.length} failures)`);
    return true;
  }
  
  return false;
}

export function logSuspiciousActivity(ip: string, activity: string, details?: any) {
  const timestamp = new Date().toISOString();
  console.warn(`[SECURITY ALERT] ${timestamp} | IP: ${ip} | Activity: ${activity}`, details || '');
}

export function detectSQLInjection(input: string): boolean {
  const sqlPatterns = [
    /(\bor\b|\band\b).*[=<>]/i,
    /union.*select/i,
    /drop\s+table/i,
    /insert\s+into/i,
    /delete\s+from/i,
    /update\s+.*\s+set/i,
    /exec(\s|\()/i,
    /script.*>/i,
    /<.*script/i,
    /javascript:/i,
    /onerror\s*=/i,
    /onload\s*=/i
  ];
  
  return sqlPatterns.some(pattern => pattern.test(input));
}

export function sanitizeInput(input: any): any {
  if (typeof input === 'string') {
    return input
      .replace(/[<>]/g, '')
      .substring(0, 10000);
  }
  return input;
}

export function createHoneypotDetector() {
  const honeypotIPs = new Set<string>();
  
  return {
    mark: (ip: string) => {
      honeypotIPs.add(ip);
      console.warn(`[HONEYPOT] IP marked: ${ip}`);
    },
    isMarked: (ip: string): boolean => {
      return honeypotIPs.has(ip);
    }
  };
}

export const honeypot = createHoneypotDetector();
