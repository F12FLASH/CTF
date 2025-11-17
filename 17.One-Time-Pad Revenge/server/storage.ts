import type { Ciphertext, StatisticalAnalysis, XorAnalysis, KeystreamRecovery } from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  addCiphertext(data: string, size: number): Promise<Ciphertext>;
  getCiphertext(id: string): Promise<Ciphertext | undefined>;
  getAllCiphertexts(): Promise<Ciphertext[]>;
  clearCiphertexts(): Promise<void>;
  
  saveStatisticalAnalysis(analysis: StatisticalAnalysis): Promise<void>;
  getStatisticalAnalysis(): Promise<StatisticalAnalysis | undefined>;
  
  saveXorAnalysis(analysis: XorAnalysis): Promise<void>;
  getAllXorAnalyses(): Promise<XorAnalysis[]>;
  
  saveKeystreamRecovery(recovery: KeystreamRecovery): Promise<void>;
  getKeystreamRecovery(): Promise<KeystreamRecovery | undefined>;
}

export class MemStorage implements IStorage {
  private ciphertexts: Map<string, Ciphertext>;
  private statisticalAnalysis: StatisticalAnalysis | undefined;
  private xorAnalyses: XorAnalysis[];
  private keystreamRecovery: KeystreamRecovery | undefined;

  constructor() {
    this.ciphertexts = new Map();
    this.xorAnalyses = [];
  }

  async addCiphertext(data: string, size: number): Promise<Ciphertext> {
    const id = randomUUID();
    const ciphertext: Ciphertext = {
      id,
      data,
      size,
      uploadedAt: new Date(),
    };
    this.ciphertexts.set(id, ciphertext);
    return ciphertext;
  }

  async getCiphertext(id: string): Promise<Ciphertext | undefined> {
    return this.ciphertexts.get(id);
  }

  async getAllCiphertexts(): Promise<Ciphertext[]> {
    return Array.from(this.ciphertexts.values());
  }

  async clearCiphertexts(): Promise<void> {
    this.ciphertexts.clear();
    this.statisticalAnalysis = undefined;
    this.xorAnalyses = [];
    this.keystreamRecovery = undefined;
  }

  async saveStatisticalAnalysis(analysis: StatisticalAnalysis): Promise<void> {
    this.statisticalAnalysis = analysis;
  }

  async getStatisticalAnalysis(): Promise<StatisticalAnalysis | undefined> {
    return this.statisticalAnalysis;
  }

  async saveXorAnalysis(analysis: XorAnalysis): Promise<void> {
    this.xorAnalyses.push(analysis);
  }

  async getAllXorAnalyses(): Promise<XorAnalysis[]> {
    return this.xorAnalyses;
  }

  async saveKeystreamRecovery(recovery: KeystreamRecovery): Promise<void> {
    this.keystreamRecovery = recovery;
  }

  async getKeystreamRecovery(): Promise<KeystreamRecovery | undefined> {
    return this.keystreamRecovery;
  }
}

export const storage = new MemStorage();
