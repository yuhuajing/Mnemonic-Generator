/**
 * Tron address derivation
 * Uses secp256k1 curve, Keccak-256 hashing, and Base58Check encoding
 */

import { HDNode, DERIVATION_PATHS } from '../core/bip32.js';
import { keccak256, sha256 } from '../utils/crypto.js';
import { base58Encode, bytesToHex } from '../utils/encoding.js';

/**
 * Generate Tron address from public key
 * @param {Uint8Array} publicKey - Uncompressed public key (65 bytes with 0x04 prefix)
 * @returns {Promise<string>} Tron address (Base58Check)
 */
async function publicKeyToTronAddress(publicKey) {
  // Remove 0x04 prefix if present
  const pubKeyWithoutPrefix = publicKey.length === 65 ? publicKey.slice(1) : publicKey;
  
  if (pubKeyWithoutPrefix.length !== 64) {
    throw new Error('Invalid public key length for Tron');
  }
  
  // Keccak-256 hash
  const hash = await keccak256(pubKeyWithoutPrefix);
  
  // Take last 20 bytes
  const addressBytes = hash.slice(-20);
  
  // Add Tron prefix (0x41 for mainnet)
  const addressWithPrefix = new Uint8Array(21);
  addressWithPrefix[0] = 0x41;
  addressWithPrefix.set(addressBytes, 1);
  
  // Double SHA-256 for checksum
  const hash1 = await sha256(addressWithPrefix);
  const hash2 = await sha256(hash1);
  const checksum = hash2.slice(0, 4);
  
  // Combine and encode
  const addressWithChecksum = new Uint8Array(25);
  addressWithChecksum.set(addressWithPrefix);
  addressWithChecksum.set(checksum, 21);
  
  return base58Encode(addressWithChecksum);
}

/**
 * Derive Tron address
 * @param {HDNode} rootNode - Root HD node from seed
 * @param {number} account - Account index (default: 0)
 * @param {number} index - Address index (default: 0)
 * @returns {Promise<object>} Address info
 */
export async function deriveTronAddress(rootNode, account = 0, index = 0) {
  // Tron path: m/44'/195'/account'/0/index
  const path = DERIVATION_PATHS.tron(account, index);
  
  // Derive child node
  const node = await rootNode.derive(path);
  
  // Get keys
  const privateKey = node.privateKey;
  const publicKey = await node.getPublicKey(false); // Uncompressed
  
  // Generate address
  const address = await publicKeyToTronAddress(publicKey);
  
  return {
    address,
    privateKey: '0x' + bytesToHex(privateKey),
    publicKey: '0x' + bytesToHex(publicKey),
    path,
    account,
    index
  };
}

/**
 * Derive multiple Tron addresses
 * @param {HDNode} rootNode 
 * @param {number} account 
 * @param {number} startIndex 
 * @param {number} count 
 * @returns {Promise<object[]>}
 */
export async function deriveTronAddresses(rootNode, account = 0, startIndex = 0, count = 5) {
  const addresses = [];
  for (let i = startIndex; i < startIndex + count; i++) {
    const addr = await deriveTronAddress(rootNode, account, i);
    addresses.push(addr);
  }
  return addresses;
}

/**
 * Validate Tron address
 * @param {string} address 
 * @returns {boolean}
 */
export function isValidTronAddress(address) {
  // Starts with 'T', Base58Check, 34 characters
  return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address);
}

