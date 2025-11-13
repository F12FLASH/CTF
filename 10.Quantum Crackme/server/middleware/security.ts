import { Request, Response, NextFunction } from "express";

/**
 * Security headers middleware
 * Protects against common web vulnerabilities
 */
export function securityHeaders() {
  return (req: Request, res: Response, next: NextFunction) => {
    // Prevent clickjacking attacks
    res.setHeader("X-Frame-Options", "DENY");
    
    // Enable XSS protection
    res.setHeader("X-Content-Type-Options", "nosniff");
    
    // Prevent MIME type sniffing
    res.setHeader("X-XSS-Protection", "1; mode=block");
    
    // Referrer policy
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    
    // Content Security Policy
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: https:; " +
      "font-src 'self' data:; " +
      "connect-src 'self';"
    );
    
    // Remove server header
    res.removeHeader("X-Powered-By");
    
    next();
  };
}

/**
 * CORS configuration for CTF application
 */
export function corsHeaders() {
  return (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
    
    if (origin && (allowedOrigins.includes(origin) || process.env.NODE_ENV === 'development')) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
    
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    
    // Handle preflight
    if (req.method === "OPTIONS") {
      res.sendStatus(204);
      return;
    }
    
    next();
  };
}

/**
 * Request logging middleware for security monitoring
 */
export function securityLogger() {
  return (req: Request, res: Response, next: NextFunction) => {
    const timestamp = new Date().toISOString();
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const method = req.method;
    const path = req.path;
    
    // Log security-relevant events
    if (path.startsWith("/api/submissions")) {
      console.log(`[SECURITY] ${timestamp} | IP: ${ip} | ${method} ${path}`);
    }
    
    next();
  };
}
