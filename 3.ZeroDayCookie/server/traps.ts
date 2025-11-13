import type { Express } from "express";
import { honeypot, logSuspiciousActivity } from "./security";

export const FAKE_FLAGS = [
  "VNFLAG{nice_try_but_this_is_a_decoy}",
  "VNFLAG{you_found_a_fake_flag_keep_trying}",
  "VNFLAG{this_is_not_the_flag_you_are_looking_for}",
  "VNFLAG{close_but_no_cigar}",
  "VNFLAG{wrong_path_try_algorithm_confusion}",
  "FLAG{AAAA1111BBBB2222CCCC3333}",
  "CTF{test_flag_not_real}",
  "VNFLAG{HS256_is_the_key_but_this_is_fake}"
];

export const DECOY_HINTS = [
  "Bạn có thể thử sử dụng thuật toán 'none' để bypass authentication",
  "Secret key được lưu trong file .env với tên SECRET_KEY", 
  "Thử brute force private key từ public key",
  "Server chấp nhận thuật toán HS512, hãy thử sử dụng nó",
  "Flag được mã hóa bằng Base64 trong cookie session",
  "Bạn cần tìm private key trong source code để giải mã",
  "SQL injection có thể giúp bạn lấy được flag từ database",
  "Thử XSS payload để steal admin token"
];

export function registerHoneypotRoutes(app: Express) {
  app.get('/api/.env', (req, res) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    honeypot.mark(ip);
    logSuspiciousActivity(ip, 'Attempted to access .env file');
    
    res.status(403).send('Forbidden');
  });
  
  app.get('/api/config', (req, res) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    honeypot.mark(ip);
    logSuspiciousActivity(ip, 'Attempted to access config endpoint');
    
    res.json({
      message: 'Config không available tại endpoint này',
      hint: 'Hãy đọc kỹ hints trong challenge'
    });
  });
  
  app.get('/api/admin', (req, res) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    honeypot.mark(ip);
    logSuspiciousActivity(ip, 'Attempted to access admin endpoint');
    
    res.status(401).json({
      success: false,
      message: 'Unauthorized. Admin access denied.',
      fake_flag: FAKE_FLAGS[Math.floor(Math.random() * FAKE_FLAGS.length)]
    });
  });
  
  app.get('/api/flag', (req, res) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    honeypot.mark(ip);
    logSuspiciousActivity(ip, 'Attempted direct flag access');
    
    res.status(403).json({
      success: false,
      message: 'Flag không thể lấy trực tiếp. Hãy khai thác lỗ hổng JWT!',
      decoy_flag: FAKE_FLAGS[Math.floor(Math.random() * FAKE_FLAGS.length)]
    });
  });
  
  app.get('/api/private-key', (req, res) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    honeypot.mark(ip);
    logSuspiciousActivity(ip, 'Attempted to access private key');
    
    res.status(403).json({
      success: false,
      message: 'Private key is... private! 🔒'
    });
  });
  
  app.post('/api/debug', (req, res) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    honeypot.mark(ip);
    logSuspiciousActivity(ip, 'Attempted to access debug endpoint', req.body);
    
    res.status(404).json({
      message: 'Debug mode is disabled in production'
    });
  });
  
  app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.send(`User-agent: *
Disallow: /api/admin
Disallow: /api/flag  
Disallow: /api/config
Disallow: /.env
Disallow: /api/private-key

# Interesting endpoints
Allow: /api/challenge
Allow: /api/validate
Allow: /api/health
`);
  });
  
  app.get('/.well-known/security.txt', (req, res) => {
    res.type('text/plain');
    res.send(`Contact: security@example.com
Expires: 2025-12-31T23:59:59.000Z
Preferred-Languages: vi, en
Canonical: https://example.com/.well-known/security.txt

# This is a CTF challenge
# Report: Find the JWT Algorithm Confusion vulnerability!
`);
  });
}

export function addDecoyHeaders(app: Express) {
  app.use((req, res, next) => {
    res.setHeader('X-Powered-By', 'Express 4.21.2');
    res.setHeader('X-CTF-Challenge', 'JWT Algorithm Confusion');
    res.setHeader('X-Hint', 'RS256 vs HS256');
    next();
  });
}
