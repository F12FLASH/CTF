#!/usr/bin/env tsx
/**
 * Utility script to encrypt a flag for secure storage
 * 
 * Usage:
 *   npm run encrypt-flag -- "YOUR_FLAG_HERE" "YOUR_ENCRYPTION_KEY"
 * 
 * Or generate a new encryption key:
 *   npm run encrypt-flag -- --generate-key
 */

import { encrypt, obfuscate, generateEncryptionKey } from "../server/crypto-utils";

async function main() {
  const args = process.argv.slice(2);

  if (args.includes("--generate-key") || args.includes("-g")) {
    const key = generateEncryptionKey();
    console.log("\nGenerated Encryption Key:");
    console.log(key);
    console.log("\nStore this securely in your ENCRYPTION_KEY environment variable.");
    return;
  }

  if (args.length < 2) {
    console.error("Usage:");
    console.error("  Generate key:    npm run encrypt-flag -- --generate-key");
    console.error("  Encrypt flag:    npm run encrypt-flag -- 'YOUR_FLAG' 'YOUR_ENCRYPTION_KEY'");
    process.exit(1);
  }

  const [flag, encryptionKey] = args;
  const obfuscationKey = args[2] || "default-obfuscation";

  try {
    console.log("\nEncrypting flag...");
    
    const encrypted = await encrypt(flag, encryptionKey);
    const obfuscated = obfuscate(encrypted, obfuscationKey);

    console.log("\n" + "=".repeat(80));
    console.log("ENCRYPTED FLAG (store this in ENCRYPTED_FLAG environment variable):");
    console.log("=".repeat(80));
    console.log(obfuscated);
    console.log("=".repeat(80));
    
    console.log("\nEnvironment Variables to set:");
    console.log(`ENCRYPTION_KEY=${encryptionKey}`);
    console.log(`ENCRYPTED_FLAG=${obfuscated}`);
    if (args[2]) {
      console.log(`OBFUSCATION_KEY=${obfuscationKey}`);
    }
    console.log("\n");
  } catch (error) {
    console.error("Encryption failed:", error);
    process.exit(1);
  }
}

main();
