import type { Express } from "express";
import { createServer, type Server } from "http";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import type { ChallengeInfo, JwtValidationResponse, JwtSubmission } from "@shared/schema";
import { jwtSubmissionSchema } from "@shared/schema";
import { honeypot, logSuspiciousActivity, trackFailedAttempt, detectSQLInjection } from "./security";
import { registerHoneypotRoutes, FAKE_FLAGS, DECOY_HINTS } from "./traps";

const FLAG = "VNFLAG{DAN_TOC_VIET_NAM_DOAN_KET_CHIEN_DAU_VINH_QUANG_4k9Z2p7F1m6Q8r3B0sL}";

const RS256_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCfPKKzVmN80HRs
GAoUxK++RO3CW8Gxomrtq3AD6TN5U5WlVbCRZ1WFrizfxcz+lr/Kvjtq/v7PdVOa
8NHIAdxpP3bCFEQWku/1yPmVN4lKJvKv8yub9i2MJlVaBo5giHCtfAouo+v/XWKd
awCR8jK28dZPFlgRxcuABcW5S5pLe4X2ASI1DDMZNTT/QWqSpMGvgHydbccI3jtd
S7S3xjR76V/izg7FBrBYPv0n3/l3dHLS9tXcCbUW0YmIm87BGwh9UKEOlhK1Nwdl
IirW9ZtXovXUFaSnMZdJbge/jepr4ZJg4PZBX7gxvn2hKTY4H4G04ukmh+ZsYQaC
+bDIIj0zAgMBAAECggEAKIBGrbCSW2O1yOyQW9nvDUkA5EdsS58Q7US7bvM4h9vl
vNGfwBxUZmtgC1rJlIHOBtYcOBTNfYle2JZCLdR1IcWLY7Jfw12ycWzIHKgJVD7K
sAMYBtgzGEIHb9DNIZ6d2JO6mRcdJVP1jnLPpBLgdMRPoJcQCyKwHBd3jvqfNV7b
i5I6yR3P2mP9NJQlDQjHUhKBBZVDPRj6hDCNrvCu5W3RUxpvOkXWPyLQXPPJyUvM
K5C+dT2BnBZb8AQGnS5yLT7Hcj6FxWKzNwpFz8qBKJ23WDM1xLRLvhWS0Kqp7X0F
rYqvnHq1QxAbGKa8VbVE/BW1i5D0G1HpWy9QLFuYQQKBgQDL0RYBVvN7bZb5xzQp
W5ggZRQ5HQFM89Jtv1uDHvh3sKNfKoN+N95V7ZXCb2NE3E4sYyPGa0J8wqD7wMEp
3bJqnJPZHQdBL0+0+RKS4N6I0RQSsV6fWw3ywY8UjF5Jfp8xHvI8E8HpRE6+yPfZ
YkPGa5jGFj6F/S8f7EJEvQKWMQKBgQDH1jHKLQkZqVHRlPc3m2zjJxQBvv7mG9wN
Qhv3yqMCkPvjZ6kFNnhCpF6F1g5CuPvbGmPiQ1K6xPJjLYHsKjVq7qhg9RxKQ8Iv
M2E6SoQXX7vqjQ7RzLHwHNd2EzpKGiqjK7sQ0AXH4hGgU9WPPXgM+Kf9jKCKjK+P
0q9SzI5FswKBgFRmW+U7Wa6oMvr9xN7ePQ7TBJiqTRseCPgRgUuNg2e7pPDqVq5E
D7i1mD6+k8JGSHHnN6VfJLdB5u9sKLXPBTVkLVdRU8ksJdqQyjU0YA2LKkIKz0k3
bQWinEYHRuqSKCqWwAtYJYxPi3PeNV5Q6hG4SV3lHf3TxqPfkPBqEG/xAoGAeprO
xbqBHrSJcK7U8P3P3Wy6l7PfI7aQMvSXbgEvZG6MhjfqCjEaANf0XRNrYrKLbD+u
XlHNOOsjBAVh2vMZnLxWLGQLCgqQLN5AIdVuRqr0x5q5K1CcuOGJsB2Uzk0Y9DP+
LIr7XtE0N3Z5qE7blnVx5+XamW9fU0LFiT+MqMsCgYBn5A8fQ4w4dXqm/4Jlp3vg
0fYC65MYiQB6LG7sJ2WQFQsY7TGr0NWZJQJwcIDX4kqdhTL3p17q5xdKdN9hYQPh
nMqD4aZvULPjMHXM/MNuL/J7s9rL6Kw8gBXQqT7R7Hb5FQf2TL6EKBZAmqFoLTdL
a4B7i1Fhpl35Kh3dBDSLng==
-----END PRIVATE KEY-----`;

const RS256_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----`;

const CHALLENGE_START_TIME = Date.now();

function generateChallengeToken(): string {
  const payload = {
    user: "guest",
    role: "user",
    level: 1,
    permissions: ["read"],
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: crypto.randomBytes(16).toString('hex'),
  };

  return jwt.sign(payload, RS256_PRIVATE_KEY, { 
    algorithm: "RS256",
    header: {
      alg: "RS256",
      typ: "JWT",
      kid: "rsa-key-2024"
    }
  });
}

function calculateScore(timeTaken: number): number {
  const baseScore = 1000;
  const timeBonus = Math.max(0, 500 - Math.floor(timeTaken / 60));
  return baseScore + timeBonus;
}

export async function registerRoutes(app: Express): Promise<Server> {
  app.use(cookieParser());

  app.get("/api/challenge", (_req, res) => {
    const challengeToken = generateChallengeToken();

    const challengeInfo: ChallengeInfo = {
      currentToken: challengeToken,
      publicKey: RS256_PUBLIC_KEY,
      description: "Máy chủ sử dụng JWT với thuật toán RS256 để xác thực. Token hiện tại của bạn được ký bằng RS256 với khóa bí mật. Bạn có thể khai thác lỗ hổng nhầm lẫn thuật toán để giành quyền truy cập quản trị viên không?",
      difficulty: "CAO THỦ",
      hints: [
        "JWT hỗ trợ nhiều thuật toán mã hóa khác nhau. RS256 sử dụng cặp khóa bất đối xứng (public/private), trong khi HS256 sử dụng khóa đối xứng. Điều gì xảy ra khi bạn thay đổi thuật toán trong header JWT?",
        "RS256: Khóa riêng để ký, khóa công khai để xác minh. HS256: Cùng một khóa bí mật cho cả ký và xác minh. Lỗ hổng xảy ra khi máy chủ chấp nhận cả hai thuật toán mà không kiểm tra chặt chẽ.",
        "Để khai thác lỗ hổng này: 1) Giải mã token hiện tại và phân tích cấu trúc, 2) Lấy khóa công khai RS256 từ máy chủ, 3) Thay đổi thuật toán từ RS256 sang HS256 trong header, 4) Thay đổi role thành 'admin' và level thành 99 trong payload, 5) Ký lại token bằng HS256 sử dụng khóa công khai RS256 làm secret.",
        "Máy chủ sẽ sử dụng khóa công khai để xác minh token. Nếu bạn ký bằng HS256 với khóa công khai làm secret, chữ ký sẽ khớp! Đây là lỗ hổng CVE-2016-5431 - Algorithm Confusion Attack.",
        "Công cụ gợi ý: Sử dụng jwt.io hoặc thư viện jsonwebtoken trong Node.js. Đảm bảo bạn đặt header.alg = 'HS256' và ký với khóa công khai RS256 làm secret. Thay đổi payload.role = 'admin' và payload.level = 99.",
      ],
    };

    res.cookie("session", challengeToken, {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000,
    });

    res.json(challengeInfo);
  });

  app.post("/api/validate", async (req, res) => {
    try {
      const ip = req.ip || req.socket.remoteAddress || 'unknown';
      
      if (honeypot.isMarked(ip)) {
        logSuspiciousActivity(ip, 'Honeypot-marked IP attempting validation', { token: req.body.token?.substring(0, 20) });
        
        return res.status(403).json({
          success: false,
          message: "Phát hiện hoạt động đáng ngờ. Hãy tập trung vào lỗ hổng JWT chính!",
          hint: DECOY_HINTS[Math.floor(Math.random() * DECOY_HINTS.length)],
          fake_flag: FAKE_FLAGS[Math.floor(Math.random() * FAKE_FLAGS.length)]
        });
      }
      
      const validationResult = jwtSubmissionSchema.safeParse(req.body);
      
      if (!validationResult.success) {
        const response: JwtValidationResponse = {
          success: false,
          message: "Yêu cầu không hợp lệ: Token là bắt buộc",
        };
        return res.status(400).json(response);
      }

      const { token } = validationResult.data;
      
      if (detectSQLInjection(token)) {
        logSuspiciousActivity(ip, 'SQL Injection attempt detected in token');
        trackFailedAttempt(ip);
        
        return res.status(400).json({
          success: false,
          message: "Token chứa ký tự không hợp lệ. SQL injection sẽ không hoạt động ở đây!",
          hint: "Hãy tập trung vào lỗ hổng JWT Algorithm Confusion."
        });
      }

      const decodedHeader = jwt.decode(token, { complete: true });
      
      if (!decodedHeader || typeof decodedHeader === 'string') {
        const response: JwtValidationResponse = {
          success: false,
          message: "Định dạng token không hợp lệ. JWT phải có header và payload hợp lệ.",
        };
        return res.status(400).json(response);
      }

      const algorithm = decodedHeader.header.alg;

      if (!algorithm || !['RS256', 'HS256'].includes(algorithm)) {
        const response: JwtValidationResponse = {
          success: false,
          message: `Thuật toán '${algorithm}' không được hỗ trợ. Chỉ chấp nhận RS256 hoặc HS256.`,
        };
        return res.status(400).json(response);
      }

      try {
        const decoded = jwt.verify(token, RS256_PUBLIC_KEY, {
          algorithms: ["RS256", "HS256"],
        }) as any;

        const isExploited = 
          algorithm === "HS256" && 
          decoded.role === "admin" && 
          decoded.level >= 99;

        if (!isExploited) {
          const response: JwtValidationResponse = {
            success: false,
            message: `Token hợp lệ nhưng bạn chưa khai thác thành công. Bạn cần role='admin' và level=99. Hiện tại: role='${decoded.role}', level=${decoded.level}`,
            details: {
              algorithm,
              payload: {
                user: decoded.user,
                role: decoded.role,
                level: decoded.level,
                permissions: decoded.permissions,
              },
            },
          };
          return res.status(403).json(response);
        }

        const timeTaken = Math.floor((Date.now() - CHALLENGE_START_TIME) / 1000);
        const score = calculateScore(timeTaken);

        const response: JwtValidationResponse = {
          success: true,
          message: "Chúc mừng! Bạn đã khai thác thành công lỗ hổng Algorithm Confusion trong JWT!",
          flag: FLAG,
          details: {
            algorithm,
            payload: decoded,
            score,
            timeTaken,
            vulnerability: "CVE-2016-5431: JWT Algorithm Confusion Attack",
          },
        };
        return res.json(response);
      } catch (verifyError: any) {
        trackFailedAttempt(ip);
        
        const response: JwtValidationResponse = {
          success: false,
          message: `Xác minh token thất bại: ${verifyError.message}. Kiểm tra lại cách bạn ký token.`,
          details: {
            algorithm,
            hint: algorithm === "RS256" 
              ? "Bạn đang sử dụng RS256. Hãy thử chuyển sang HS256 và sử dụng khóa công khai làm secret." 
              : "Đảm bảo bạn sử dụng khóa công khai RS256 chính xác làm secret cho HS256.",
          },
        };
        return res.status(401).json(response);
      }
    } catch (error: any) {
      const response: JwtValidationResponse = {
        success: false,
        message: `Lỗi máy chủ: ${error.message}`,
      };
      return res.status(500).json(response);
    }
  });

  app.get("/api/health", (_req, res) => {
    res.json({ 
      status: "healthy", 
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    });
  });
  
  registerHoneypotRoutes(app);

  const httpServer = createServer(app);
  return httpServer;
}
