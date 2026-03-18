/**
 * BIP39 Seed generation from mnemonic
 * Uses PBKDF2-HMAC-SHA512 with 2048 iterations
 */

import { pbkdf2 } from '../utils/crypto.js';
import { bytesToHex } from '../utils/encoding.js';

/**
 * Convert mnemonic (and optional passphrase) to seed
 * @param {string} mnemonic - BIP39 mnemonic phrase
 * @param {string} passphrase - Optional passphrase (default: '')
 * @returns {Promise<Uint8Array>} 64-byte seed
 */
export async function mnemonicToSeed(mnemonic, passphrase = '') {
  // Normalize strings to NFKD form (Unicode normalization)
  const mnemonicNormalized = mnemonic.normalize('NFKD');
  const passphraseNormalized = passphrase.normalize('NFKD');
  
  // Create salt: "mnemonic" + passphrase
  const salt = 'mnemonic' + passphraseNormalized;
  
  // PBKDF2-HMAC-SHA512
  // password: mnemonic, salt: "mnemonic" + passphrase, iterations: 2048, keyLen: 64 bytes
  const seed = await pbkdf2(
    mnemonicNormalized,
    salt,
    2048,
    64,
    'SHA-512'
  );
  
  return seed;
}

/**
 * Convert mnemonic to seed and return both bytes and hex
 * @param {string} mnemonic 
 * @param {string} passphrase 
 * @returns {Promise<object>} { seed, seedHex }
 */
export async function mnemonicToSeedWithHex(mnemonic, passphrase = '') {
  const seed = await mnemonicToSeed(mnemonic, passphrase);
  return {
    seed,
    seedHex: bytesToHex(seed)
  };
}

/**
 * Validate that a seed is the correct length
 * @param {Uint8Array} seed 
 * @returns {boolean}
 */
export function isValidSeed(seed) {
  return seed instanceof Uint8Array && seed.length === 64;
}

