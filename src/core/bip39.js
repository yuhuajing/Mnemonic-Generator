/**
 * BIP39 Mnemonic generation and validation
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */

import { sha256 } from '../utils/crypto.js';
import { bytesToHex, hexToBytes } from '../utils/encoding.js';
import { sanitizeMnemonic, isValidWordCount } from '../utils/validation.js';

let WORDLIST = null;

/**
 * Load BIP39 English wordlist from text
 * @param {string} text - Wordlist text (one word per line)
 * @returns {string[]} Array of 2048 words
 */
export function loadWordlist(text) {
  const words = text.trim().split('\n').map(w => w.trim());
  if (words.length !== 2048) {
    throw new Error(`Invalid wordlist: expected 2048 words, got ${words.length}`);
  }
  WORDLIST = words;
  return words;
}

/**
 * Get the loaded wordlist
 * @returns {string[]}
 */
export function getWordlist() {
  if (!WORDLIST) {
    throw new Error('Wordlist not loaded. Call loadWordlist() first.');
  }
  return WORDLIST;
}

/**
 * Convert bytes to binary string
 * @param {Uint8Array} bytes 
 * @returns {string} Binary string
 */
function bytesToBinary(bytes) {
  return Array.from(bytes)
    .map(byte => byte.toString(2).padStart(8, '0'))
    .join('');
}

/**
 * Convert binary string to bytes
 * @param {string} binary 
 * @returns {Uint8Array}
 */
function binaryToBytes(binary) {
  const bytes = [];
  for (let i = 0; i < binary.length; i += 8) {
    bytes.push(parseInt(binary.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

/**
 * Generate mnemonic from entropy
 * @param {Uint8Array} entropy - Entropy bytes (16 or 32 bytes)
 * @returns {Promise<string>} Mnemonic phrase
 */
export async function entropyToMnemonic(entropy) {
  const wordlist = getWordlist();
  
  // Validate entropy length
  const entropyBits = entropy.length * 8;
  if (![128, 160, 192, 224, 256].includes(entropyBits)) {
    throw new Error('Invalid entropy length');
  }
  
  // Calculate checksum
  const hash = await sha256(entropy);
  const checksumBits = entropyBits / 32;
  const checksumBinary = bytesToBinary(hash).slice(0, checksumBits);
  
  // Combine entropy and checksum
  const entropyBinary = bytesToBinary(entropy);
  const fullBinary = entropyBinary + checksumBinary;
  
  // Split into 11-bit groups and map to words
  const words = [];
  for (let i = 0; i < fullBinary.length; i += 11) {
    const index = parseInt(fullBinary.slice(i, i + 11), 2);
    words.push(wordlist[index]);
  }
  
  return words.join(' ');
}

/**
 * Convert mnemonic to entropy
 * @param {string} mnemonic - Mnemonic phrase
 * @returns {Promise<Uint8Array>} Entropy bytes
 */
export async function mnemonicToEntropy(mnemonic) {
  const wordlist = getWordlist();
  const words = sanitizeMnemonic(mnemonic).split(' ');
  
  if (!isValidWordCount(words.length)) {
    throw new Error(`Invalid mnemonic: expected 12, 15, 18, 21, or 24 words, got ${words.length}`);
  }
  
  // Convert words to indices
  const indices = words.map(word => {
    const index = wordlist.indexOf(word);
    if (index === -1) {
      throw new Error(`Invalid word: ${word}`);
    }
    return index;
  });
  
  // Convert indices to binary
  const binary = indices.map(i => i.toString(2).padStart(11, '0')).join('');
  
  // Split entropy and checksum
  const checksumBits = words.length / 3;
  const entropyBits = binary.length - checksumBits;
  const entropyBinary = binary.slice(0, entropyBits);
  const checksumBinary = binary.slice(entropyBits);
  
  // Convert entropy binary to bytes
  const entropy = binaryToBytes(entropyBinary);
  
  // Verify checksum
  const hash = await sha256(entropy);
  const expectedChecksumBinary = bytesToBinary(hash).slice(0, checksumBits);
  
  if (checksumBinary !== expectedChecksumBinary) {
    throw new Error('Invalid mnemonic: checksum mismatch');
  }
  
  return entropy;
}

/**
 * Validate mnemonic phrase
 * @param {string} mnemonic - Mnemonic phrase
 * @returns {Promise<boolean>} True if valid
 */
export async function validateMnemonic(mnemonic) {
  try {
    await mnemonicToEntropy(mnemonic);
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Generate a random mnemonic
 * @param {number} wordCount - Number of words (12 or 24)
 * @returns {Promise<object>} { mnemonic, entropy, entropyHex }
 */
export async function generateMnemonic(wordCount = 12) {
  if (![12, 24].includes(wordCount)) {
    throw new Error('Word count must be 12 or 24');
  }
  
  const bits = wordCount === 12 ? 128 : 256;
  const { generateEntropy } = await import('./entropy.js');
  const entropy = generateEntropy(bits);
  const mnemonic = await entropyToMnemonic(entropy);
  
  return {
    mnemonic,
    entropy,
    entropyHex: bytesToHex(entropy)
  };
}

/**
 * Get the word at a specific index in the wordlist
 * @param {number} index - Word index (0-2047)
 * @returns {string} Word
 */
export function getWordAtIndex(index) {
  const wordlist = getWordlist();
  if (index < 0 || index >= 2048) {
    throw new Error('Index must be between 0 and 2047');
  }
  return wordlist[index];
}

/**
 * Get the index of a word in the wordlist
 * @param {string} word 
 * @returns {number} Index or -1 if not found
 */
export function getWordIndex(word) {
  const wordlist = getWordlist();
  return wordlist.indexOf(word.toLowerCase());
}

/**
 * Check if a word is in the wordlist
 * @param {string} word 
 * @returns {boolean}
 */
export function isValidWord(word) {
  return getWordIndex(word) !== -1;
}

/**
 * Find words that match a prefix (for autocomplete)
 * @param {string} prefix 
 * @returns {string[]} Matching words
 */
export function findWords(prefix) {
  const wordlist = getWordlist();
  const lowerPrefix = prefix.toLowerCase();
  return wordlist.filter(word => word.startsWith(lowerPrefix));
}

