import { FlagVault } from './flagVault';

const FLAG = 'VNFLAG{VIETNAM_DOAN_KET_VA_PHAT_TRIEN_BEN_VUNG_6k1R9p4M7q2L8z0F3b5yXc}';
const KEY = 'VN-CTF-2024-SECURE-ENCRYPTION-KEY-FOR-FLAG-PROTECTION';
const SALT = 'vietnam-ctf-salt-2024';

console.log('Generating encrypted flag...\n');
console.log('Original Flag:', FLAG);
console.log('\nAdd these to your .env file:\n');
console.log(`FLAG_CIPHERTEXT="${FlagVault.encryptFlag(FLAG, KEY, SALT)}"`);
console.log(`FLAG_KEY="${KEY}"`);
console.log(`FLAG_SALT="${SALT}"`);
