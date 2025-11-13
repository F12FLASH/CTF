/**
 * SSRF Filter - Hardened version for CTF challenge
 * Blocks multiple bypass techniques but still vulnerable to advanced techniques
 */

export interface FilterResult {
  allowed: boolean;
  reason?: string;
}

export function validateURL(url: string): FilterResult {
  try {
    const parsed = new URL(url);
    
    const hostname = parsed.hostname.toLowerCase();
    const originalUrl = url.toLowerCase();
    
    // Block localhost keyword and variations
    if (hostname.includes('localhost') || originalUrl.includes('localhost')) {
      return {
        allowed: false,
        reason: 'Chặn: Phát hiện từ khóa "localhost"'
      };
    }
    
    // Block .local and common DNS tricks
    const blockedDomains = ['.local', 'localtest.me', 'lvh.me', 'nip.io', 'xip.io', 'sslip.io'];
    for (const domain of blockedDomains) {
      if (hostname.endsWith(domain) || hostname.includes(domain)) {
        return {
          allowed: false,
          reason: `Chặn: Domain ${domain} không được phép`
        };
      }
    }
    
    // Block IPv6 loopback representations
    const ipv6Loopback = ['::1', '::ffff:127.0.0.1', '0:0:0:0:0:0:0:1', '0000:0000:0000:0000:0000:0000:0000:0001'];
    for (const ipv6 of ipv6Loopback) {
      if (hostname === ipv6 || hostname === `[${ipv6}]`) {
        return {
          allowed: false,
          reason: 'Chặn: IPv6 loopback không được phép'
        };
      }
    }
    
    // Block common localhost IP representations
    const blockedIPs = [
      '127.0.0.1',
      '0.0.0.0',
      '127.0.0.0',
      '127.1',
      '127.0.1',
    ];
    
    if (blockedIPs.includes(hostname)) {
      return {
        allowed: false,
        reason: `Chặn: IP ${hostname} nằm trong blacklist`
      };
    }
    
    // Block 127.0.0.0/8 range
    if (hostname.match(/^127\.\d+\.\d+\.\d+$/)) {
      return {
        allowed: false,
        reason: 'Chặn: Phát hiện dải IP loopback 127.0.0.0/8'
      };
    }
    
    // Block decimal IP representation of 127.0.0.1 (2130706433)
    // and range 2130706432-2147483647 (127.0.0.0/8 in decimal)
    if (hostname.match(/^\d+$/)) {
      const decimalIP = parseInt(hostname, 10);
      if (decimalIP >= 2130706432 && decimalIP <= 2147483647) {
        return {
          allowed: false,
          reason: 'Chặn: Phát hiện IP dạng decimal trong dải loopback'
        };
      }
    }
    
    // Block hexadecimal IP representations (0x7f000001, 0x7f.0x0.0x0.0x1, etc.)
    if (hostname.match(/0x[0-9a-f]/i)) {
      return {
        allowed: false,
        reason: 'Chặn: Phát hiện IP dạng hexadecimal'
      };
    }
    
    // Block octal IP representations (0177.0.0.1, 017700000001, etc.)
    if (hostname.match(/^0\d/) || hostname.includes('.0')) {
      return {
        allowed: false,
        reason: 'Chặn: Phát hiện IP dạng octal'
      };
    }
    
    // Block URL encoding tricks in hostname
    if (originalUrl.match(/%[0-9a-f]{2}/i)) {
      return {
        allowed: false,
        reason: 'Chặn: Phát hiện URL encoding'
      };
    }
    
    // Block @ symbol (user:pass@localhost tricks)
    if (originalUrl.includes('@')) {
      return {
        allowed: false,
        reason: 'Chặn: Ký tự @ không được phép trong URL'
      };
    }
    
    // Block backslash (Windows path tricks)
    if (originalUrl.includes('\\')) {
      return {
        allowed: false,
        reason: 'Chặn: Ký tự \\ không được phép trong URL'
      };
    }
    
    // Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    if (hostname.match(/^10\.\d+\.\d+\.\d+$/)) {
      return {
        allowed: false,
        reason: 'Chặn: Dải IP private 10.0.0.0/8'
      };
    }
    
    if (hostname.match(/^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$/)) {
      return {
        allowed: false,
        reason: 'Chặn: Dải IP private 172.16.0.0/12'
      };
    }
    
    if (hostname.match(/^192\.168\.\d+\.\d+$/)) {
      return {
        allowed: false,
        reason: 'Chặn: Dải IP private 192.168.0.0/16'
      };
    }
    
    // If we get here, the URL passed all filters
    // (But advanced techniques like DNS rebinding, TOCTOU, etc. might still work)
    return { allowed: true };
    
  } catch (error) {
    return {
      allowed: false,
      reason: 'Định dạng URL không hợp lệ'
    };
  }
}
