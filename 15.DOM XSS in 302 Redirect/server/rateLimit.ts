import type { Request, Response, NextFunction } from "express";

interface RateLimitStore {
  [key: string]: {
    count: number;
    resetTime: number;
  };
}

const store: RateLimitStore = {};

const CLEANUP_INTERVAL = 60000;

setInterval(() => {
  const now = Date.now();
  for (const key in store) {
    if (store[key].resetTime < now) {
      delete store[key];
    }
  }
}, CLEANUP_INTERVAL);

export function createRateLimiter(options: {
  windowMs: number;
  max: number;
  message?: string;
}) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = req.ip || req.socket.remoteAddress || "unknown";
    const key = `${req.path}:${ip}`;
    const now = Date.now();

    if (!store[key]) {
      store[key] = {
        count: 1,
        resetTime: now + options.windowMs,
      };
      return next();
    }

    if (store[key].resetTime < now) {
      store[key] = {
        count: 1,
        resetTime: now + options.windowMs,
      };
      return next();
    }

    if (store[key].count >= options.max) {
      return res.status(429).json({
        error: options.message || "Too many requests, please try again later.",
      });
    }

    store[key].count++;
    next();
  };
}
