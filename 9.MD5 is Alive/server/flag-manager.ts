import { decrypt, obfuscate, deobfuscate, constantTimeCompare } from "./crypto-utils";

class FlagManager {
  private decryptedFlag: string | null = null;
  private initialized: boolean = false;

  /**
   * Initialize and decrypt the flag
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    const encryptedFlag = process.env.ENCRYPTED_FLAG;
    const encryptionKey = process.env.ENCRYPTION_KEY;
    const obfuscationKey = process.env.OBFUSCATION_KEY || "default-obfuscation";

    if (!encryptionKey) {
      console.warn("======================================================================");
      console.warn("SECURITY WARNING: ENCRYPTION_KEY not set!");
      console.warn("Using UNENCRYPTED fallback mode - FLAG is stored in cleartext.");
      console.warn("This is NOT SECURE for production use.");
      console.warn("For production: Generate encryption key and encrypt your FLAG.");
      console.warn("See SECURITY.md for instructions.");
      console.warn("======================================================================");
      const fallbackFlag = process.env.FLAG || "VNFLAG{TO_QUOC_GHI_CONG_VOI_NHAN_DAN_VIETNAM_9m2K7p1R4q8L3z6F0b5yXc}";
      this.decryptedFlag = fallbackFlag;
      console.log("✓ Flag loaded from environment (unencrypted fallback mode)");
      this.initialized = true;
      return;
    }

    if (!encryptedFlag) {
      console.warn("======================================================================");
      console.warn("SECURITY WARNING: ENCRYPTED_FLAG not set!");
      console.warn("Using UNENCRYPTED fallback mode - FLAG is stored in cleartext.");
      console.warn("This is NOT SECURE for production use.");
      console.warn("For production: Encrypt your FLAG with the encryption utility.");
      console.warn("See SECURITY.md for instructions.");
      console.warn("======================================================================");
      const fallbackFlag = process.env.FLAG || "VNFLAG{TO_QUOC_GHI_CONG_VOI_NHAN_DAN_VIETNAM_9m2K7p1R4q8L3z6F0b5yXc}";
      this.decryptedFlag = fallbackFlag;
      console.log("✓ Flag loaded from environment (unencrypted fallback mode)");
      this.initialized = true;
      return;
    }

    try {
      const deobfuscatedFlag = deobfuscate(encryptedFlag, obfuscationKey);
      this.decryptedFlag = await decrypt(deobfuscatedFlag, encryptionKey);
      console.log("✓ Flag successfully decrypted and loaded (encrypted mode)");
      this.initialized = true;
    } catch (error) {
      console.error("CRITICAL: Failed to decrypt flag. Verify ENCRYPTION_KEY and ENCRYPTED_FLAG are correct.");
      console.error("Error type:", error instanceof Error ? error.message : "Unknown error");
      throw new Error("Flag decryption failed. Check ENCRYPTION_KEY and ENCRYPTED_FLAG configuration.");
    }
  }

  /**
   * Get the decrypted flag
   */
  getFlag(): string {
    if (!this.initialized || !this.decryptedFlag) {
      throw new Error("FlagManager not initialized. Call initialize() first.");
    }
    return this.decryptedFlag;
  }

  /**
   * Validate a submitted flag using constant-time comparison
   */
  validateFlag(submittedFlag: string): boolean {
    if (!this.initialized || !this.decryptedFlag) {
      throw new Error("FlagManager not initialized.");
    }
    
    return constantTimeCompare(submittedFlag.trim(), this.decryptedFlag);
  }

  /**
   * Check if flag manager is initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }
}

export const flagManager = new FlagManager();
