/**
 * Entropy generation using Web Crypto API
 */

import { getRandomBytes, testEntropyQuality } from '../utils/crypto.js';
import { bytesToHex } from '../utils/encoding.js';

/**
 * Generate cryptographically secure entropy
 * @param {number} bits - Entropy size in bits (128 for 12 words, 256 for 24 words)
 * @returns {Uint8Array} Random entropy bytes
 */
export function generateEntropy(bits) {
  if (![128, 256].includes(bits)) {
    throw new Error('Entropy size must be 128 or 256 bits');
  }
  
  const bytes = bits / 8;
  return getRandomBytes(bytes);
}

/**
 * Generate entropy and return both raw and hex format
 * @param {number} bits - Entropy size in bits
 * @returns {object} { bytes, hex }
 */
export function generateEntropyWithHex(bits) {
  const bytes = generateEntropy(bits);
  return {
    bytes,
    hex: bytesToHex(bytes)
  };
}

/**
 * Test the quality of entropy generation (optional, for user confidence)
 * @param {number} samples - Number of random bytes to test
 * @returns {object} Statistics about the random bytes
 */
export function testEntropy(samples = 10000) {
  return testEntropyQuality(samples);
}

/**
 * Validate entropy bytes
 * @param {Uint8Array} entropy 
 * @returns {boolean}
 */
export function isValidEntropy(entropy) {
  if (!(entropy instanceof Uint8Array)) return false;
  const bits = entropy.length * 8;
  return [128, 160, 192, 224, 256].includes(bits);
}

