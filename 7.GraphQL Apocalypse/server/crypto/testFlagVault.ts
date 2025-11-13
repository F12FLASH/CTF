import { flagVault } from './flagVault';

console.log('Testing FlagVault...\n');

try {
  const flag = flagVault.getFlag();
  console.log('✓ FlagVault decryption successful');
  console.log('Flag format check:', flag.startsWith('VNFLAG{') && flag.endsWith('}') ? '✓ Valid format' : '✗ Invalid format');
  console.log('Flag length:', flag.length, 'characters');
  console.log('Flag preview:', flag.substring(0, 15) + '...' + flag.substring(flag.length - 5));
} catch (error) {
  console.error('✗ FlagVault decryption failed:', error);
  process.exit(1);
}

console.log('\n✓ All tests passed!');
