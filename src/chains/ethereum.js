/**
 * Ethereum address derivation
 * Uses secp256k1 curve and Keccak-256 hashing
 */

import { HDNode, DERIVATION_PATHS } from '../core/bip32.js';
import { keccak256, privateKeyToPublicKey } from '../utils/crypto.js';
import { bytesToHex } from '../utils/encoding.js';

/**
 * Convert Ethereum address to EIP-55 checksum format
 * @param {string} address - Hex address (with or without 0x prefix)
 * @returns {Promise<string>} Checksummed address
 */
async function toChecksumAddress(address) {
  const addr = address.toLowerCase().replace('0x', '');
  const hash = await keccak256(new TextEncoder().encode(addr));
  const hashHex = bytesToHex(hash);
  
  let checksummed = '0x';
  for (let i = 0; i < addr.length; i++) {
    if (parseInt(hashHex[i], 16) >= 8) {
      checksummed += addr[i].toUpperCase();
    } else {
      checksummed += addr[i];
    }
  }
  
  return checksummed;
}

/**
 * Generate Ethereum address from public key
 * @param {Uint8Array} publicKey - Uncompressed public key (65 bytes with 0x04 prefix)
 * @returns {Promise<string>} Ethereum address with checksum
 */
async function publicKeyToAddress(publicKey) {
  // Remove 0x04 prefix if present
  const pubKeyWithoutPrefix = publicKey.length === 65 ? publicKey.slice(1) : publicKey;
  
  if (pubKeyWithoutPrefix.length !== 64) {
    throw new Error('Invalid public key length for Ethereum');
  }
  
  // Keccak-256 hash
  const hash = await keccak256(pubKeyWithoutPrefix);
  
  // Take last 20 bytes
  const addressBytes = hash.slice(-20);
  const address = '0x' + bytesToHex(addressBytes);
  
  // Apply EIP-55 checksum
  return await toChecksumAddress(address);
}

/**
 * Derive Ethereum address
 * @param {HDNode} rootNode - Root HD node from seed
 * @param {number} account - Account index (default: 0)
 * @param {number} index - Address index (default: 0)
 * @returns {Promise<object>} Address info
 */
export async function deriveEthereumAddress(rootNode, account = 0, index = 0) {
  // Get derivation path: m/44'/60'/account'/0/index
  const path = DERIVATION_PATHS.ethereum(account, index);
  
  // Derive child node
  const node = await rootNode.derive(path);
  
  // Get keys
  const privateKey = node.privateKey;
  const publicKey = await node.getPublicKey(false); // Uncompressed
  
  // Generate address
  const address = await publicKeyToAddress(publicKey);
  
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
 * Derive multiple Ethereum addresses
 * @param {HDNode} rootNode 
 * @param {number} account 
 * @param {number} startIndex 
 * @param {number} count 
 * @returns {Promise<object[]>}
 */
export async function deriveEthereumAddresses(rootNode, account = 0, startIndex = 0, count = 5) {
  const addresses = [];
  for (let i = startIndex; i < startIndex + count; i++) {
    const addr = await deriveEthereumAddress(rootNode, account, i);
    addresses.push(addr);
  }
  return addresses;
}

/**
 * Validate Ethereum address
 * @param {string} address 
 * @returns {boolean}
 */
export function isValidEthereumAddress(address) {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

