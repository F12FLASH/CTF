import { createHash, randomBytes } from "crypto";

export function xorBytes(a: Buffer, b: Buffer): Buffer {
  const length = Math.min(a.length, b.length);
  const result = Buffer.alloc(length);
  for (let i = 0; i < length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

export function sha256(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

export function generateRandomKey(length: number): Buffer {
  return randomBytes(length);
}

export function encryptOTP(plaintext: string, key?: string): {
  ciphertext: string;
  key: string;
  keyHash: string;
} {
  const plaintextBuffer = Buffer.from(plaintext, "utf-8");
  
  let keyBuffer: Buffer;
  let keyHashString: string;
  
  if (key) {
    const providedKey = Buffer.from(key, "hex");
    keyHashString = sha256(providedKey);
    
    if (providedKey.length < plaintextBuffer.length) {
      keyBuffer = Buffer.alloc(plaintextBuffer.length);
      for (let i = 0; i < plaintextBuffer.length; i++) {
        keyBuffer[i] = providedKey[i % providedKey.length];
      }
    } else {
      keyBuffer = providedKey.slice(0, plaintextBuffer.length);
    }
  } else {
    keyBuffer = generateRandomKey(plaintextBuffer.length);
    keyHashString = sha256(keyBuffer);
  }
  
  const ciphertextBuffer = xorBytes(plaintextBuffer, keyBuffer);
  
  return {
    ciphertext: ciphertextBuffer.toString("hex"),
    key: keyBuffer.toString("hex"),
    keyHash: keyHashString,
  };
}

export function encryptOTPSecure(plaintext: string, keyHex: string): string {
  const plaintextBuffer = Buffer.from(plaintext, "utf-8");
  const providedKey = Buffer.from(keyHex, "hex");
  
  let keyBuffer: Buffer;
  if (providedKey.length < plaintextBuffer.length) {
    keyBuffer = Buffer.alloc(plaintextBuffer.length);
    for (let i = 0; i < plaintextBuffer.length; i++) {
      keyBuffer[i] = providedKey[i % providedKey.length];
    }
  } else {
    keyBuffer = providedKey.slice(0, plaintextBuffer.length);
  }
  
  const ciphertextBuffer = xorBytes(plaintextBuffer, keyBuffer);
  return ciphertextBuffer.toString("hex");
}

export function calculateEntropy(data: Buffer): number {
  const frequency = new Array(256).fill(0);
  
  for (let i = 0; i < data.length; i++) {
    frequency[data[i]]++;
  }
  
  let entropy = 0;
  const length = data.length;
  
  for (let i = 0; i < frequency.length; i++) {
    const count = frequency[i];
    if (count > 0) {
      const p = count / length;
      entropy -= p * Math.log2(p);
    }
  }
  
  return entropy;
}

export function calculateByteFrequency(buffers: Buffer[]): Record<string, number>[] {
  if (buffers.length === 0) return [];
  
  const keyLength = buffers[0].length;
  const positionFrequency: Record<string, number>[] = [];
  
  for (let pos = 0; pos < keyLength; pos++) {
    const freq: Record<string, number> = {};
    
    for (const buffer of buffers) {
      if (buffer.length > pos) {
        const byte = buffer[pos];
        const key = byte.toString(16).padStart(2, "0");
        freq[key] = (freq[key] || 0) + 1;
      }
    }
    
    positionFrequency.push(freq);
  }
  
  return positionFrequency;
}

export function calculateAverageByteValue(buffers: Buffer[]): number {
  if (buffers.length === 0) return 0;
  
  let sum = 0;
  let count = 0;
  
  for (let i = 0; i < buffers.length; i++) {
    const buffer = buffers[i];
    for (let j = 0; j < buffer.length; j++) {
      sum += buffer[j];
      count++;
    }
  }
  
  return count > 0 ? sum / count : 0;
}

export function performXorAnalysis(ct1: Buffer, ct2: Buffer): {
  xorResult: string;
  patterns: Array<{ position: number; value: string; frequency: number }>;
} {
  const xorResult = xorBytes(ct1, ct2);
  
  const patternMap = new Map<string, { positions: number[]; frequency: number }>();
  
  for (let i = 0; i < xorResult.length; i++) {
    const value = xorResult[i].toString(16).padStart(2, "0");
    
    if (!patternMap.has(value)) {
      patternMap.set(value, { positions: [], frequency: 0 });
    }
    
    const pattern = patternMap.get(value)!;
    pattern.positions.push(i);
    pattern.frequency++;
  }
  
  const patterns = Array.from(patternMap.entries())
    .filter(([_, data]) => data.frequency > 1)
    .map(([value, data]) => ({
      position: data.positions[0],
      value,
      frequency: data.frequency,
    }))
    .sort((a, b) => b.frequency - a.frequency)
    .slice(0, 10);
  
  return {
    xorResult: xorResult.toString("hex"),
    patterns,
  };
}

export function recoverKeystreamFromKnownPlaintext(
  ciphertexts: Buffer[],
  knownPlaintext: string
): {
  recoveredKeystream: string;
  confidence: number;
  matchedCiphertexts: number;
  recoveredPlaintext?: string;
} {
  const knownBuffer = Buffer.from(knownPlaintext, "utf-8");
  const keystreamCandidates: Buffer[] = [];
  
  for (const ct of ciphertexts) {
    if (ct.length >= knownBuffer.length) {
      const keystreamPart = xorBytes(ct.slice(0, knownBuffer.length), knownBuffer);
      keystreamCandidates.push(keystreamPart);
    }
  }
  
  if (keystreamCandidates.length === 0) {
    return {
      recoveredKeystream: "",
      confidence: 0,
      matchedCiphertexts: 0,
    };
  }
  
  const consensusKeystream = keystreamCandidates[0];
  
  let matchCount = 0;
  for (const candidate of keystreamCandidates) {
    if (candidate.equals(consensusKeystream)) {
      matchCount++;
    }
  }
  
  const confidence = (matchCount / keystreamCandidates.length) * 100;
  
  let recoveredPlaintext: string | undefined;
  if (ciphertexts.length > 0 && confidence > 50) {
    try {
      const fullKeystream = Buffer.concat([
        consensusKeystream,
        Buffer.alloc(ciphertexts[0].length - consensusKeystream.length),
      ]);
      
      const plaintext = xorBytes(ciphertexts[0], fullKeystream);
      recoveredPlaintext = plaintext.toString("utf-8", 0, consensusKeystream.length);
    } catch {
      recoveredPlaintext = undefined;
    }
  }
  
  return {
    recoveredKeystream: consensusKeystream.toString("hex"),
    confidence,
    matchedCiphertexts: matchCount,
    recoveredPlaintext,
  };
}
