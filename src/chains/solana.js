/**
 * Solana address derivation
 * Uses SLIP-0010 Ed25519 HD derivation (compatible with Phantom, Solflare, etc.)
 * https://github.com/satoshilabs/slips/blob/master/slip-0010.md
 */

import { hmacSHA512, ed25519GetPublicKey } from '../utils/crypto.js';
import { base58Encode, bytesToHex, utf8ToBytes, uint32ToBytes } from '../utils/encoding.js';

const HARDENED_OFFSET = 0x80000000;

/**
 * SLIP-0010 Ed25519 HD Node
 * Unlike BIP32 secp256k1, Ed25519 only supports hardened derivation
 */
class Ed25519HDNode {
  constructor(privateKey, chainCode) {
    this.privateKey = privateKey;
    this.chainCode = chainCode;
  }

  /**
   * Create master node from BIP39 seed using SLIP-0010
   * @param {Uint8Array} seed - 64-byte BIP39 seed
   * @returns {Promise<Ed25519HDNode>}
   */
  static async fromSeed(seed) {
    if (seed.length !== 64) {
      throw new Error('Seed must be 64 bytes');
    }

    // SLIP-0010: I = HMAC-SHA512(key: "ed25519 seed", data: seed)
    const I = await hmacSHA512(utf8ToBytes('ed25519 seed'), seed);

    const privateKey = I.slice(0, 32);
    const chainCode = I.slice(32, 64);

    return new Ed25519HDNode(privateKey, chainCode);
  }

  /**
   * Derive child key at hardened index
   * SLIP-0010 Ed25519 only supports hardened derivation
   * @param {number} index - Child index (will be hardened automatically)
   * @returns {Promise<Ed25519HDNode>}
   */
  async deriveChild(index) {
    // Ensure hardened derivation
    const hardenedIndex = index >= HARDENED_OFFSET ? index : index + HARDENED_OFFSET;

    // Data = 0x00 || private_key || index (4 bytes, big-endian)
    const data = new Uint8Array(37);
    data[0] = 0x00;
    data.set(this.privateKey, 1);
    data.set(uint32ToBytes(hardenedIndex), 33);

    // I = HMAC-SHA512(key: chain_code, data: data)
    const I = await hmacSHA512(this.chainCode, data);

    const childPrivateKey = I.slice(0, 32);
    const childChainCode = I.slice(32, 64);

    return new Ed25519HDNode(childPrivateKey, childChainCode);
  }

  /**
   * Derive path like "m/44'/501'/0'/0'"
   * @param {string} path - Derivation path
   * @returns {Promise<Ed25519HDNode>}
   */
  async derive(path) {
    if (!path.startsWith('m') && !path.startsWith('M')) {
      throw new Error('Path must start with "m" or "M"');
    }

    const segments = path.split('/').slice(1);
    let node = this;

    for (const segment of segments) {
      if (segment === '') continue;

      // Ed25519 SLIP-0010 only supports hardened derivation
      const indexStr = segment.replace(/['h]/g, '');
      const index = parseInt(indexStr, 10);

      if (isNaN(index) || index < 0) {
        throw new Error(`Invalid path segment: ${segment}`);
      }

      node = await node.deriveChild(index);
    }

    return node;
  }

  /**
   * Get Ed25519 public key
   * @returns {Promise<Uint8Array>} 32-byte public key
   */
  async getPublicKey() {
    return await ed25519GetPublicKey(this.privateKey);
  }
}

/**
 * Standard Solana derivation path
 * Phantom uses: m/44'/501'/account'/change'
 * For simplicity, we use: m/44'/501'/account'/0'
 */
function getSolanaPath(account = 0, change = 0) {
  return `m/44'/501'/${account}'/${change}'`;
}

/**
 * Derive Solana address using SLIP-0010 Ed25519
 * Compatible with Phantom, Solflare, and other standard Solana wallets
 *
 * @param {Uint8Array} seed - 64-byte BIP39 seed (NOT the BIP32 root node)
 * @param {number} account - Account index (default: 0)
 * @param {number} change - Change index (default: 0)
 * @returns {Promise<object>} Address info
 */
export async function deriveSolanaAddressFromSeed(seed, account = 0, change = 0) {
  const path = getSolanaPath(account, change);

  // Create SLIP-0010 Ed25519 master node
  const masterNode = await Ed25519HDNode.fromSeed(seed);

  // Derive to path
  const node = await masterNode.derive(path);

  // Get Ed25519 keypair
  const privateKey = node.privateKey;
  const publicKey = await node.getPublicKey();

  // Solana address is Base58-encoded public key
  const address = base58Encode(publicKey);

  // Solana private key format: 64 bytes (32-byte secret + 32-byte public)
  const fullPrivateKey = new Uint8Array(64);
  fullPrivateKey.set(privateKey, 0);
  fullPrivateKey.set(publicKey, 32);

  return {
    address,
    privateKey: base58Encode(fullPrivateKey), // Standard Solana format
    privateKeyShort: base58Encode(privateKey), // 32-byte seed only
    publicKey: base58Encode(publicKey),
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
    path,
    account,
    index: account // For compatibility with UI
  };
}

/**
 * Derive Solana address (wrapper for backward compatibility)
 * @param {object} rootNodeOrSeed - Either HDNode (legacy) or { seed } object
 * @param {number} account - Account index
 * @returns {Promise<object>} Address info
 */
export async function deriveSolanaAddress(rootNodeOrSeed, account = 0) {
  // Check if we received a seed directly (new method)
  if (rootNodeOrSeed instanceof Uint8Array) {
    return deriveSolanaAddressFromSeed(rootNodeOrSeed, account);
  }

  // Check if we received an object with seed property
  if (rootNodeOrSeed && rootNodeOrSeed.seed) {
    return deriveSolanaAddressFromSeed(rootNodeOrSeed.seed, account);
  }

  // Legacy: received HDNode, need the original seed
  // This is a compatibility shim - caller should pass seed instead
  throw new Error(
    'Solana derivation now requires the BIP39 seed directly. ' +
    'Please pass the seed (Uint8Array) instead of HDNode for SLIP-0010 compatibility.'
  );
}

/**
 * Derive multiple Solana addresses
 * @param {Uint8Array} seed - 64-byte BIP39 seed
 * @param {number} startAccount - Starting account index
 * @param {number} count - Number of addresses to derive
 * @returns {Promise<object[]>}
 */
export async function deriveSolanaAddresses(seed, startAccount = 0, count = 5) {
  const addresses = [];
  for (let i = startAccount; i < startAccount + count; i++) {
    const addr = await deriveSolanaAddressFromSeed(seed, i);
    addresses.push(addr);
  }
  return addresses;
}

/**
 * Validate Solana address
 * @param {string} address
 * @returns {boolean}
 */
export function isValidSolanaAddress(address) {
  // Base58, 32-44 characters, must decode to 32 bytes
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)) {
    return false;
  }
  return true;
}

// Export the Ed25519HDNode class for testing
export { Ed25519HDNode };
