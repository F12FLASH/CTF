import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const configSchema = z.object({
  nodeEnv: z.enum(['development', 'production', 'test']).default('development'),
  port: z.string().transform(Number).pipe(z.number().positive()).default('5000'),
  
  jwtSecret: z.string().min(32).default('your-super-secret-jwt-key-change-this-in-production'),
  sessionSecret: z.string().min(32).default('your-super-secret-session-key-change-this-in-production'),
  
  rateLimitWindowMs: z.string().transform(Number).pipe(z.number().positive()).default('900000'),
  rateLimitMaxRequests: z.string().transform(Number).pipe(z.number().positive()).default('100'),
  
  corsOrigin: z.string().default('*'),
  
  flagCiphertext: z.string().min(32).default('DOzdyQmtgPNnP+yK6bVr8k3U771KVI5is7YFnJGzm9eZL0i7OvSUW7XKaV1DOh0Z3wG4nD7obMjpsrgJbJjQFtcPl1Uy/zyJsIqFAA0UQKQ='),
  flagKey: z.string().min(16).default('VN-CTF-2024-SECURE-ENCRYPTION-KEY-FOR-FLAG-PROTECTION'),
  flagSalt: z.string().min(8).default('vietnam-ctf-salt-2024'),
});

const parseConfig = () => {
  try {
    return configSchema.parse({
      nodeEnv: process.env.NODE_ENV,
      port: process.env.PORT,
      jwtSecret: process.env.JWT_SECRET,
      sessionSecret: process.env.SESSION_SECRET,
      rateLimitWindowMs: process.env.RATE_LIMIT_WINDOW_MS,
      rateLimitMaxRequests: process.env.RATE_LIMIT_MAX_REQUESTS,
      corsOrigin: process.env.CORS_ORIGIN,
      flagCiphertext: process.env.FLAG_CIPHERTEXT,
      flagKey: process.env.FLAG_KEY,
      flagSalt: process.env.FLAG_SALT,
    });
  } catch (error) {
    console.error('❌ Invalid environment configuration:');
    if (error instanceof z.ZodError) {
      error.errors.forEach((err) => {
        console.error(`  - ${err.path.join('.')}: ${err.message}`);
      });
    }
    throw new Error('Configuration validation failed');
  }
};

export const config = parseConfig();

export const isDevelopment = config.nodeEnv === 'development';
export const isProduction = config.nodeEnv === 'production';
