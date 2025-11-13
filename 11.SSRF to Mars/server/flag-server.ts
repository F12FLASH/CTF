import { createServer } from 'http';
import type { Server } from 'http';

const FLAG = 'VNFLAG{VANG_MAIVIETNAM_DAU_TUONG_ANH_HUNG_3K7r1P9m4Q8z6L2f0B5yXcG}';
const FLAG_PORT = 1337;

let flagServerInstance: Server | null = null;

/**
 * Flag server running on localhost:1337
 * This is the target that players need to reach via SSRF
 * Singleton pattern to prevent EADDRINUSE errors on hot reload
 */
export function startFlagServer() {
  // Return existing instance if already running
  if (flagServerInstance) {
    return flagServerInstance;
  }
  const server = createServer((req, res) => {
    // CORS headers to allow access
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, User-Agent');
    
    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
    
    // Verify request comes from challenge server (check User-Agent)
    // Only requests from the challenge server will have this specific User-Agent
    const userAgent = req.headers['user-agent'];
    if (userAgent !== 'SSRF-to-Mars-CTF/1.0') {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: false,
        error: 'Unauthorized',
        message: 'Bạn cần bypass SSRF filter thông qua challenge server để lấy flag!',
        hint: 'Không thể truy cập trực tiếp từ trình duyệt. Hãy sử dụng URL Fetcher trên trang challenge!'
      }));
      return;
    }
    
    if (req.url === '/flag' || req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        message: 'Chúc mừng! Bạn đã bypass thành công SSRF filter!',
        flag: FLAG,
        challenge: 'SSRF to Mars',
        difficulty: 'Expert',
        points: 500
      }));
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'Not found',
        hint: 'Thử endpoint /flag'
      }));
    }
  });
  
  server.listen(FLAG_PORT, '127.0.0.1', () => {
    console.log(`[FLAG SERVER] Running on http://127.0.0.1:${FLAG_PORT}`);
    console.log(`[FLAG SERVER] Flag endpoint: http://127.0.0.1:${FLAG_PORT}/flag`);
  });
  
  flagServerInstance = server;
  return server;
}
