import { z } from "zod";

export const progressStepSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  completed: z.boolean(),
});

export const progressSchema = z.object({
  currentStep: z.number(),
  steps: z.array(progressStepSchema),
  startTime: z.number(),
});

export const flagSubmissionSchema = z.object({
  flag: z.string()
    .min(1, "Flag cannot be empty")
    .max(200, "Flag is too long")
    .regex(/^VNFLAG\{.*\}$/, "Flag must be in format VNFLAG{...}")
    .refine((flag) => {
      const sanitized = flag.replace(/[^\x20-\x7E]/g, '');
      return sanitized === flag;
    }, "Flag contains invalid characters"),
});

export const flagResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
  attempts: z.number(),
  hintsUnlocked: z.number(),
});

export const hintSchema = z.object({
  id: z.string(),
  title: z.string(),
  content: z.string(),
  unlockAttempts: z.number(),
  unlocked: z.boolean(),
});

export const terminalCommandSchema = z.object({
  command: z.string(),
});

export const terminalResponseSchema = z.object({
  output: z.string(),
  timestamp: z.number(),
});

export const ubTypeSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  color: z.string(),
  codeExample: z.string(),
  explanation: z.string(),
});

export type ProgressStep = z.infer<typeof progressStepSchema>;
export type Progress = z.infer<typeof progressSchema>;
export type FlagSubmission = z.infer<typeof flagSubmissionSchema>;
export type FlagResponse = z.infer<typeof flagResponseSchema>;
export type Hint = z.infer<typeof hintSchema>;
export type TerminalCommand = z.infer<typeof terminalCommandSchema>;
export type TerminalResponse = z.infer<typeof terminalResponseSchema>;
export type UBType = z.infer<typeof ubTypeSchema>;

export const CORRECT_FLAG = "VNFLAG{TAM_HUYET_YEU_NUOC_VIETNAM_GIUP_XAY_DUNG_8p2R7k1M4Q9z3L6f0B5yXc}";

const UB_TYPES: UBType[] = [
  {
    id: "uninitialized",
    title: "Uninitialized Memory",
    description: "Sử dụng biến chưa được khởi tạo",
    color: "orange",
    codeExample: `int secret_key;
// secret_key chưa được khởi tạo
return secret_key; // UB - giá trị không xác định`,
    explanation: "Khi một biến được khai báo nhưng không được gán giá trị ban đầu, giá trị của nó là không xác định (undefined). Compiler có thể tối ưu hóa code theo nhiều cách khác nhau, dẫn đến hành vi không thể đoán trước.",
  },
  {
    id: "type-punning",
    title: "Type Punning",
    description: "Vi phạm quy tắc strict aliasing",
    color: "purple",
    codeExample: `uint32_t a = 0x12345678;
float* b = (float*)&a; // UB - type punning
float secret = *b; // Giá trị phụ thuộc vào compiler`,
    explanation: "Type punning là kỹ thuật truy cập cùng một vùng nhớ thông qua các con trỏ có kiểu dữ liệu khác nhau. Điều này vi phạm strict aliasing rules và có thể dẫn đến kết quả không mong muốn.",
  },
  {
    id: "signed-overflow",
    title: "Signed Integer Overflow",
    description: "Tràn số nguyên có dấu",
    color: "red",
    codeExample: `int x = INT_MAX;
x += 1; // UB - kết quả không xác định`,
    explanation: "Tràn số nguyên có dấu (signed integer overflow) là undefined behavior trong C/C++. Khi một phép toán số học gây ra tràn số, compiler có thể tối ưu hóa code theo cách mà lập trình viên không mong đợi.",
  },
  {
    id: "memory-order",
    title: "Memory Order / Race Conditions",
    description: "Điều kiện tranh chấp bộ nhớ",
    color: "blue",
    codeExample: `// Thread 1
data = compute_value();
ready = true;

// Thread 2  
if (ready) {
    use(data); // Race condition
}`,
    explanation: "Race conditions xảy ra khi nhiều luồng truy cập cùng một vùng nhớ mà không có đồng bộ hóa phù hợp. Thứ tự thực thi của các thao tác bộ nhớ có thể không như mong đợi.",
  },
];

const INITIAL_PROGRESS: Progress = {
  currentStep: 0,
  steps: [
    {
      id: "binary-analysis",
      title: "Binary Analysis",
      description: "Xác định vị trí UB trong code",
      completed: false,
    },
    {
      id: "environment-control",
      title: "Environment Control",
      description: "Kiểm soát môi trường thực thi",
      completed: false,
    },
    {
      id: "reproducible-execution",
      title: "Reproducible Execution",
      description: "Tạo môi trường reproducible",
      completed: false,
    },
    {
      id: "key-extraction",
      title: "Key Extraction",
      description: "Trích xuất encryption key",
      completed: false,
    },
    {
      id: "flag",
      title: "Flag",
      description: "Giải mã và submit flag",
      completed: false,
    },
  ],
  startTime: Date.now(),
};

const HINTS: Hint[] = [
  {
    id: "hint-1",
    title: "Hint 1: UB Detection",
    content: "Sử dụng công cụ static analysis như Clang Static Analyzer hoặc compiler warnings (-Wall -Wextra) để phát hiện các UB patterns trong code.",
    unlockAttempts: 2,
    unlocked: false,
  },
  {
    id: "hint-2",
    title: "Hint 2: Environment Variables",
    content: "Thử kiểm soát môi trường với: MALLOC_PERTURB_=0, LD_PRELOAD, và disable ASLR. Key có thể phụ thuộc vào memory layout.",
    unlockAttempts: 4,
    unlocked: false,
  },
  {
    id: "hint-3",
    title: "Hint 3: Memory Dump",
    content: "Sử dụng GDB để dump memory tại thời điểm encryption. Key thường nằm ở địa chỉ cố định khi ASLR bị disable.",
    unlockAttempts: 6,
    unlocked: false,
  },
  {
    id: "hint-4",
    title: "Hint 4: XOR Decryption",
    content: "Flag được mã hóa bằng XOR. Nếu bạn có một phần flag (ví dụ: format 'VNFLAG{'), bạn có thể reverse engineer để tìm key.",
    unlockAttempts: 8,
    unlocked: false,
  },
];

export { UB_TYPES, INITIAL_PROGRESS, HINTS };
