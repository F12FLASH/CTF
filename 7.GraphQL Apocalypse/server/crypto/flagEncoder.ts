function rot13(str: string): string {
  return str.replace(/[a-zA-Z]/g, (char) => {
    const code = char.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(((code - base + 13) % 26) + base);
  });
}

function rot13Reverse(str: string): string {
  return rot13(str);
}

function xorEncode(str: string, key: number): string {
  return str
    .split('')
    .map((char) => String.fromCharCode(char.charCodeAt(0) ^ key))
    .join('');
}

export function encodeFlag(flag: string): string {
  const step1 = rot13(flag);
  const step2 = xorEncode(step1, 42);
  const step3 = Buffer.from(step2).toString('base64');
  
  return step3;
}

export function decodeFlag(encoded: string): string {
  const step1 = Buffer.from(encoded, 'base64').toString('utf-8');
  const step2 = xorEncode(step1, 42);
  const step3 = rot13Reverse(step2);
  
  return step3;
}

export function getFlagHint(): string {
  return "Gợi ý giải mã: Flag đã được mã hóa qua 3 lớp - Base64 → XOR(key=42) → ROT13. Hãy giải ngược lại!";
}
