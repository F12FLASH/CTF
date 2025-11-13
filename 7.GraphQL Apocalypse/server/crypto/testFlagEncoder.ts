import { encodeFlag, decodeFlag, getFlagHint } from './flagEncoder';

const testFlag = 'VNFLAG{VIETNAM_DOAN_KET_VA_PHAT_TRIEN_BEN_VUNG_6k1R9p4M7q2L8z0F3b5yXc}';

console.log('Testing Flag Encoder...\n');
console.log('Original Flag:', testFlag);

const encoded = encodeFlag(testFlag);
console.log('\nEncoded Flag:', encoded);
console.log('Encoded Length:', encoded.length, 'characters');

const decoded = decodeFlag(encoded);
console.log('\nDecoded Flag:', decoded);

console.log('\nHint:', getFlagHint());

if (decoded === testFlag) {
  console.log('\n✓ Encoding/Decoding test PASSED!');
} else {
  console.log('\n✗ Encoding/Decoding test FAILED!');
  console.log('Expected:', testFlag);
  console.log('Got:', decoded);
}
