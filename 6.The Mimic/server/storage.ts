import {
  type ChallengeState,
  type InsertChallengeState,
  type FlagSubmission,
  type InsertFlagSubmission,
  type Hint,
  type InsertHint,
} from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  // Challenge State
  getChallengeState(id: string): Promise<ChallengeState | undefined>;
  getCurrentChallengeState(): Promise<ChallengeState | undefined>;
  createChallengeState(state: InsertChallengeState): Promise<ChallengeState>;
  updateChallengeState(id: string, state: Partial<InsertChallengeState>): Promise<ChallengeState | undefined>;

  // Flag Submissions
  createFlagSubmission(submission: InsertFlagSubmission): Promise<FlagSubmission>;
  getAllFlagSubmissions(): Promise<FlagSubmission[]>;
  getCorrectSubmissions(): Promise<FlagSubmission[]>;

  // Hints
  getAllHints(): Promise<Hint[]>;
  revealHint(id: string): Promise<Hint | undefined>;
  initializeHints(): Promise<void>;
}

export class MemStorage implements IStorage {
  private challengeStates: Map<string, ChallengeState>;
  private flagSubmissions: Map<string, FlagSubmission>;
  private hints: Map<string, Hint>;
  private currentChallengeId: string | null;

  constructor() {
    this.challengeStates = new Map();
    this.flagSubmissions = new Map();
    this.hints = new Map();
    this.currentChallengeId = null;
    this.initializeHints();
  }

  // Challenge State Methods
  async getChallengeState(id: string): Promise<ChallengeState | undefined> {
    return this.challengeStates.get(id);
  }

  async getCurrentChallengeState(): Promise<ChallengeState | undefined> {
    if (!this.currentChallengeId) return undefined;
    return this.challengeStates.get(this.currentChallengeId);
  }

  async createChallengeState(insertState: InsertChallengeState): Promise<ChallengeState> {
    const id = randomUUID();
    const state: ChallengeState = {
      encryptedFlag: insertState.encryptedFlag,
      currentKey: insertState.currentKey,
      keyRotationCount: insertState.keyRotationCount ?? 0,
      isTimeHooked: insertState.isTimeHooked ?? false,
      wasmExecutionStatus: insertState.wasmExecutionStatus ?? 'idle',
      id,
      createdAt: new Date(),
    };
    this.challengeStates.set(id, state);
    this.currentChallengeId = id;
    return state;
  }

  async updateChallengeState(
    id: string,
    updates: Partial<InsertChallengeState>
  ): Promise<ChallengeState | undefined> {
    const existing = this.challengeStates.get(id);
    if (!existing) return undefined;

    const updated: ChallengeState = {
      ...existing,
      ...updates,
    };
    this.challengeStates.set(id, updated);
    return updated;
  }

  // Flag Submission Methods
  async createFlagSubmission(insertSubmission: InsertFlagSubmission): Promise<FlagSubmission> {
    const id = randomUUID();
    const submission: FlagSubmission = {
      ...insertSubmission,
      id,
      timestamp: new Date(),
    };
    this.flagSubmissions.set(id, submission);
    return submission;
  }

  async getAllFlagSubmissions(): Promise<FlagSubmission[]> {
    return Array.from(this.flagSubmissions.values()).sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
    );
  }

  async getCorrectSubmissions(): Promise<FlagSubmission[]> {
    return Array.from(this.flagSubmissions.values())
      .filter(sub => sub.isCorrect)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  // Hints Methods
  async getAllHints(): Promise<Hint[]> {
    return Array.from(this.hints.values()).sort((a, b) => a.order - b.order);
  }

  async revealHint(id: string): Promise<Hint | undefined> {
    const hint = this.hints.get(id);
    if (!hint) return undefined;

    const revealed: Hint = {
      ...hint,
      isRevealed: true,
    };
    this.hints.set(id, revealed);
    return revealed;
  }

  async initializeHints(): Promise<void> {
    const defaultHints: InsertHint[] = [
      {
        order: 1,
        title: "Hiểu Về Thử Thách",
        content: "Flag được mã hóa bằng XOR cipher. Khóa mã hóa thay đổi mỗi 10 mili giây, khiến việc giải mã trở nên bất khả thi nếu không đóng băng thời gian.",
        isRevealed: false,
      },
      {
        order: 2,
        title: "Hàm time()",
        content: "Trong C/C++, hàm time() trả về Unix timestamp hiện tại. Nhiều thuật toán mã hóa sử dụng nó làm seed. Nếu bạn có thể hook hàm này để trả về giá trị cố định, việc tạo khóa sẽ bị đóng băng.",
        isRevealed: false,
      },
      {
        order: 3,
        title: "Chiến Lược Hooking",
        content: "Sử dụng nút 'Hook time()' để đóng băng hàm time(). Một khi đã hook, khóa mã hóa sẽ ngừng xoay vòng, cho phép bạn capture và giải mã flag.",
        isRevealed: false,
      },
      {
        order: 4,
        title: "Quá Trình Giải Mã",
        content: "Sau khi hook time(), ghi nhận khóa mã hóa đã ổn định. Mã hóa XOR là đối xứng - mã hóa flag đã mã hóa với cùng khóa để lấy flag gốc. Format flag là VNFLAG{...}",
        isRevealed: false,
      },
    ];

    for (const hintData of defaultHints) {
      const id = randomUUID();
      const hint: Hint = {
        order: hintData.order,
        title: hintData.title,
        content: hintData.content,
        isRevealed: hintData.isRevealed ?? false,
        id,
      };
      this.hints.set(id, hint);
    }
  }
}

export const storage = new MemStorage();
