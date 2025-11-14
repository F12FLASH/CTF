import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { ENCRYPTED_FLAG, ADMIN_COOKIE_VALUE, ADMIN_COOKIE_HASH, generateVisitNonce } from "./config";
import { decryptFlag, hashCookie } from "./crypto";
import { createRateLimiter } from "./rateLimit";

let botStatus: "idle" | "visiting" | "completed" = "idle";
let botVisitCount = 0;
let lastBotVisit: Date | null = null;

const activeNonces = new Map<string, { timestamp: number, used: boolean }>();

setInterval(() => {
  const now = Date.now();
  for (const [nonce, data] of activeNonces.entries()) {
    if (now - data.timestamp > 300000) {
      activeNonces.delete(nonce);
    }
  }
}, 60000);

const botVisitLimiter = createRateLimiter({
  windowMs: 60000,
  max: 10,
  message: "Too many bot visit requests. Please wait a minute.",
});

const captureLimiter = createRateLimiter({
  windowMs: 60000,
  max: 50,
  message: "Too many capture requests. Please wait a minute.",
});

export async function registerRoutes(app: Express): Promise<Server> {
  app.use((req, res, next) => {
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    if (req.path === "/api/redirect") {
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; sandbox allow-scripts allow-top-navigation-by-user-activation"
      );
    } else if (isDevelopment) {
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws: wss:; worker-src 'self' blob:"
      );
    } else {
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
      );
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-Frame-Options", "DENY");
      res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
      res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
      res.setHeader("X-XSS-Protection", "1; mode=block");
    }
    next();
  });

  app.get("/api/redirect", (req, res) => {
    const url = req.query.url as string;
    
    if (!url) {
      return res.status(400).json({ error: "URL parameter is required" });
    }

    if (url.length > 2048) {
      return res.status(400).json({ error: "URL too long" });
    }

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Redirecting...</title>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'">
      </head>
      <body>
        <h1>Redirecting...</h1>
        <p>You will be redirected shortly...</p>
        <script>
          // Vulnerable redirect handler - DOM XSS vulnerability (intentional for CTF)
          var redirectUrl = "${url.replace(/"/g, '\\"')}";
          
          // Simulating vulnerable DOM manipulation
          setTimeout(function() {
            // This is the vulnerability - directly using user input in location
            window.location.href = redirectUrl;
          }, 1000);
        </script>
      </body>
      </html>
    `);
  });

  app.post("/api/exploit/submit", async (req, res) => {
    try {
      const { payload } = req.body;
      
      if (!payload) {
        return res.status(400).json({ error: "Payload is required" });
      }

      if (typeof payload !== 'string') {
        return res.status(400).json({ error: "Payload must be a string" });
      }

      if (payload.length > 10000) {
        return res.status(400).json({ error: "Payload too long" });
      }

      const attempt = await storage.createExploitAttempt({
        payload: payload.substring(0, 10000),
        success: payload.toLowerCase().includes("javascript:") || payload.toLowerCase().includes("document.cookie"),
      });

      res.json(attempt);
    } catch (error) {
      res.status(500).json({ error: "Failed to submit exploit" });
    }
  });

  app.get("/api/exploits", async (req, res) => {
    try {
      const attempts = await storage.getExploitAttempts();
      res.json(attempts);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch exploits" });
    }
  });

  app.post("/api/bot/visit", botVisitLimiter, async (req, res) => {
    try {
      const { url } = req.body;
      
      if (!url) {
        return res.status(400).json({ error: "URL is required" });
      }

      if (typeof url !== 'string') {
        return res.status(400).json({ error: "URL must be a string" });
      }

      if (url.length > 2048) {
        return res.status(400).json({ error: "URL too long" });
      }

      let parsedUrl;
      try {
        parsedUrl = new URL(url);
      } catch {
        return res.status(400).json({ error: "Invalid URL format" });
      }

      const nonce = generateVisitNonce();
      activeNonces.set(nonce, { timestamp: Date.now(), used: false });
      console.log(`[Bot] Generated nonce: ${nonce.substring(0, 8)}... for visit #${botVisitCount + 1}`);

      botStatus = "visiting";
      botVisitCount++;
      lastBotVisit = new Date();

      setTimeout(async () => {
        try {
          const isRedirectEndpoint = parsedUrl.pathname === '/api/redirect' || 
                                    parsedUrl.pathname.endsWith('/api/redirect');
          
          if (isRedirectEndpoint) {
            const redirectTarget = parsedUrl.searchParams.get('url');
            
            if (redirectTarget && redirectTarget.startsWith('javascript:') && redirectTarget.includes('/api/capture')) {
              await fetch('http://localhost:5000/api/capture', {
                method: 'POST',
                headers: { 
                  'Content-Type': 'application/json',
                  'X-Bot-Nonce': nonce
                },
                body: JSON.stringify({ 
                  cookie: ADMIN_COOKIE_VALUE,
                  nonce 
                }),
              });
            }
          }
        } catch (error) {
          console.error("Error simulating bot visit:", error);
        }

        botStatus = "completed";
        setTimeout(() => {
          botStatus = "idle";
        }, 3000);
      }, 2000);

      res.json({ 
        message: "Bot visit triggered", 
        status: "visiting",
        nonce
      });
    } catch (error) {
      botStatus = "idle";
      res.status(500).json({ error: "Failed to trigger bot" });
    }
  });

  app.get("/api/bot/status", (req, res) => {
    res.json({
      status: botStatus,
      visitCount: botVisitCount,
      lastVisit: lastBotVisit?.toISOString(),
    });
  });

  app.post("/api/capture", captureLimiter, async (req, res) => {
    try {
      const { cookie, nonce } = req.body;
      const sourceUrl = req.query.url as string || req.headers.referer;
      const botNonce = req.headers['x-bot-nonce'] as string;
      
      if (!cookie) {
        return res.status(400).json({ error: "Cookie is required" });
      }

      if (typeof cookie !== 'string') {
        return res.status(400).json({ error: "Cookie must be a string" });
      }

      if (cookie.length > 10000) {
        return res.status(400).json({ error: "Cookie data too long" });
      }

      const effectiveNonce = nonce || botNonce;
      
      if (effectiveNonce && activeNonces.has(effectiveNonce)) {
        const nonceData = activeNonces.get(effectiveNonce);
        if (nonceData && !nonceData.used) {
          nonceData.used = true;
          activeNonces.set(effectiveNonce, nonceData);
          console.log(`[Capture] Nonce ${effectiveNonce.substring(0, 8)}... marked as used`);
        }
      }

      await storage.createCapturedCookie({
        cookie: cookie.substring(0, 10000),
        sourceUrl: sourceUrl ? sourceUrl.substring(0, 2048) : undefined,
      });

      console.log(`[Capture] Cookie captured successfully (length: ${cookie.length})`);
      res.json({ message: "Cookie captured successfully" });
    } catch (error) {
      console.error("[Capture] Error:", error);
      res.status(500).json({ error: "Failed to capture cookie" });
    }
  });

  app.get("/api/cookies", async (req, res) => {
    try {
      const cookies = await storage.getCapturedCookies();
      res.json(cookies);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch cookies" });
    }
  });

  app.delete("/api/cookies", async (req, res) => {
    try {
      await storage.clearData();
      res.json({ message: "All cookies cleared" });
    } catch (error) {
      res.status(500).json({ error: "Failed to clear cookies" });
    }
  });

  app.get("/api/hints", async (req, res) => {
    try {
      const hints = await storage.getHints();
      res.json(hints);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch hints" });
    }
  });

  app.post("/api/hints/:id/reveal", async (req, res) => {
    try {
      const { id } = req.params;
      const hint = await storage.revealHint(id);
      
      if (!hint) {
        return res.status(404).json({ error: "Hint not found" });
      }

      res.json(hint);
    } catch (error) {
      res.status(500).json({ error: "Failed to reveal hint" });
    }
  });

  app.post("/api/flag/validate", async (req, res) => {
    try {
      const { flag } = req.body;
      
      if (!flag) {
        return res.status(400).json({ error: "Flag is required" });
      }

      if (typeof flag !== 'string') {
        return res.status(400).json({ error: "Flag must be a string" });
      }

      if (flag.length > 500) {
        return res.status(400).json({ error: "Flag too long" });
      }

      if (!/^VNFLAG\{.+\}$/.test(flag.trim())) {
        return res.json({
          valid: false,
          message: "Định dạng flag không đúng. Định dạng mong đợi: VNFLAG{...}",
        });
      }

      const cookies = await storage.getCapturedCookies();
      
      function extractFlagFromCookie(cookieString: string): string | null {
        const flagMatch = cookieString.match(/flag=([^;]+)/);
        return flagMatch ? flagMatch[1] : null;
      }
      
      const hasAdminCookie = cookies.some(c => {
        const capturedFlag = extractFlagFromCookie(c.cookie);
        return capturedFlag && capturedFlag.startsWith('VNFLAG{');
      });

      if (!hasAdminCookie) {
        return res.json({
          valid: false,
          message: "Bạn cần capture cookie của admin trước! Hãy khai thác lỗ hổng XSS để lấy cookie.",
        });
      }

      const hasUsedNonce = Array.from(activeNonces.values()).some(data => data.used);
      
      if (!hasUsedNonce) {
        return res.json({
          valid: false,
          message: "Cookie phải được capture thông qua bot visit exploitation! Không chấp nhận cookie được seed thủ công.",
        });
      }

      const decryptedFlag = decryptFlag(ENCRYPTED_FLAG);
      const isValid = flag.trim() === decryptedFlag;
      
      if (isValid) {
        console.log(`[Flag] ✓ Correct flag submitted`);
      } else {
        console.log(`[Flag] ✗ Incorrect flag attempt: ${flag.substring(0, 20)}...`);
      }
      
      res.json({
        valid: isValid,
        message: isValid 
          ? "Chúc mừng! Flag chính xác! Bạn đã hoàn thành thử thách!" 
          : "Flag không chính xác. Hãy thử lại! Kiểm tra lại cookie đã capture.",
        flag: isValid ? decryptedFlag : undefined,
      });
    } catch (error) {
      console.error("[Flag] Validation error:", error);
      res.status(500).json({ error: "Failed to validate flag" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
