/**
 * BIP32 Hierarchical Deterministic Wallets
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */

import { hmacSHA512, addPrivateKeys, privateKeyToPublicKey } from '../utils/crypto.js';
import { bytesToHex, hexToBytes, utf8ToBytes, uint32ToBytes } from '../utils/encoding.js';
import { sha256, hash160 } from '../utils/crypto.js';
import { secureZero } from '../utils/secure.js';

const HARDENED_OFFSET = 0x80000000;
const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

/**
 * HD Node class representing a key in the derivation tree
 */
export class HDNode {
  constructor(privateKey, chainCode, depth = 0, index = 0, parentFingerprint = 0x00000000) {
    this.privateKey = privateKey;
    this.chainCode = chainCode;
    this.depth = depth;
    this.index = index;
    this.parentFingerprint = parentFingerprint;
    this._publicKey = null; // Cached
    this._fingerprint = null; // Cached
  }
  
  /**
   * Create HD node from seed
   * @param {Uint8Array} seed - BIP39 seed (64 bytes)
   * @returns {HDNode}
   */
  static async fromSeed(seed) {
    if (seed.length !== 64) {
      throw new Error('Seed must be 64 bytes');
    }
    
    // I = HMAC-SHA512(key: "Bitcoin seed", data: seed)
    const I = await hmacSHA512(utf8ToBytes('Bitcoin seed'), seed);
    
    const privateKey = I.slice(0, 32);
    const chainCode = I.slice(32, 64);
    
    // Validate private key
    const keyInt = BigInt('0x' + bytesToHex(privateKey));
    const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
    if (keyInt === BigInt(0) || keyInt >= n) {
      throw new Error('Invalid private key derived from seed');
    }
    
    return new HDNode(privateKey, chainCode, 0, 0, 0);
  }
  
  /**
   * Derive a child key at the given index
   * @param {number} index - Child index (use index + HARDENED_OFFSET for hardened)
   * @returns {Promise<HDNode>}
   */
  async deriveChild(index) {
    const hardened = index >= HARDENED_OFFSET;
    
    // Prepare data for HMAC
    let data;
    if (hardened) {
      // Data = 0x00 || private_key || index (4 bytes, big-endian)
      data = new Uint8Array(37);
      data[0] = 0x00;
      data.set(this.privateKey, 1);
      data.set(uint32ToBytes(index), 33);
    } else {
      // Data = public_key || index
      const publicKey = await this.getPublicKey(true);
      data = new Uint8Array(37);
      data.set(publicKey, 0);
      data.set(uint32ToBytes(index), 33);
    }
    
    // I = HMAC-SHA512(key: chain_code, data: data)
    const I = await hmacSHA512(this.chainCode, data);
    
    const IL = I.slice(0, 32);
    const IR = I.slice(32, 64);
    
    const ilInt = BigInt('0x' + bytesToHex(IL));
    if (ilInt >= SECP256K1_N) {
      throw new Error('Invalid child key: IL >= curve order');
    }

    // Child private key = (IL + parent_private_key) mod n
    const childPrivateKey = addPrivateKeys(IL, this.privateKey);
    const childInt = BigInt('0x' + bytesToHex(childPrivateKey));
    if (childInt === BigInt(0)) {
      throw new Error('Invalid child key: derived key is zero');
    }
    const childChainCode = IR;
    
    const fingerprint = await this.getFingerprint();
    
    return new HDNode(
      childPrivateKey,
      childChainCode,
      this.depth + 1,
      index,
      fingerprint
    );
  }
  
  /**
   * Derive a path like "m/44'/0'/0'/0/0"
   * @param {string} path - Derivation path
   * @returns {Promise<HDNode>}
   */
  async derive(path) {
    if (!path.startsWith('m') && !path.startsWith('M')) {
      throw new Error('Path must start with "m" or "M"');
    }
    
    const segments = path.split('/').slice(1); // Remove 'm'
    let node = this;
    
    for (const segment of segments) {
      if (segment === '') continue;
      
      const hardened = segment.endsWith("'") || segment.endsWith('h');
      const indexStr = segment.replace(/['h]/g, '');
      const index = parseInt(indexStr, 10);
      
      if (isNaN(index) || index < 0) {
        throw new Error(`Invalid path segment: ${segment}`);
      }
      
      const childIndex = hardened ? index + HARDENED_OFFSET : index;
      node = await node.deriveChild(childIndex);
    }
    
    return node;
  }
  
  /**
   * Get public key for this node
   * @param {boolean} compressed - Whether to return compressed public key
   * @returns {Promise<Uint8Array>}
   */
  async getPublicKey(compressed = true) {
    if (!this._publicKey || this._publicKey.length !== (compressed ? 33 : 65)) {
      this._publicKey = await privateKeyToPublicKey(this.privateKey, compressed);
    }
    return this._publicKey;
  }
  
  /**
   * Get fingerprint (first 4 bytes of hash160(pubkey))
   * @returns {Promise<number>}
   */
  async getFingerprint() {
    if (this._fingerprint === null) {
      const publicKey = await this.getPublicKey(true);
      const hash = await hash160(publicKey);
      const bytes = hash.slice(0, 4);
      this._fingerprint = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    }
    return this._fingerprint;
  }
  
  /**
   * Get extended private key (xprv)
   * @returns {Promise<string>}
   */
  async getExtendedPrivateKey() {
    // Version bytes for mainnet xprv
    const version = new Uint8Array([0x04, 0x88, 0xAD, 0xE4]);
    
    const depth = new Uint8Array([this.depth]);
    const parentFingerprintBytes = uint32ToBytes(this.parentFingerprint);
    const indexBytes = uint32ToBytes(this.index);
    
    // Serialize: version || depth || parent_fingerprint || index || chain_code || 0x00 || private_key
    const serialized = new Uint8Array(78);
    let offset = 0;
    
    serialized.set(version, offset);
    offset += 4;
    serialized.set(depth, offset);
    offset += 1;
    serialized.set(parentFingerprintBytes, offset);
    offset += 4;
    serialized.set(indexBytes, offset);
    offset += 4;
    serialized.set(this.chainCode, offset);
    offset += 32;
    serialized.set([0x00], offset);
    offset += 1;
    serialized.set(this.privateKey, offset);
    
    // Base58Check encode
    const { base58CheckEncode } = await import('../utils/encoding.js');
    const hash1 = await sha256(serialized);
    const hash2 = await sha256(hash1);
    const checksum = hash2.slice(0, 4);
    
    const withChecksum = new Uint8Array(82);
    withChecksum.set(serialized);
    withChecksum.set(checksum, 78);
    
    const { base58Encode } = await import('../utils/encoding.js');
    return base58Encode(withChecksum);
  }
  
  /**
   * Get extended public key (xpub)
   * @returns {Promise<string>}
   */
  async getExtendedPublicKey() {
    // Version bytes for mainnet xpub
    const version = new Uint8Array([0x04, 0x88, 0xB2, 0x1E]);
    
    const depth = new Uint8Array([this.depth]);
    const parentFingerprintBytes = uint32ToBytes(this.parentFingerprint);
    const indexBytes = uint32ToBytes(this.index);
    const publicKey = await this.getPublicKey(true);
    
    // Serialize: version || depth || parent_fingerprint || index || chain_code || public_key
    const serialized = new Uint8Array(78);
    let offset = 0;
    
    serialized.set(version, offset);
    offset += 4;
    serialized.set(depth, offset);
    offset += 1;
    serialized.set(parentFingerprintBytes, offset);
    offset += 4;
    serialized.set(indexBytes, offset);
    offset += 4;
    serialized.set(this.chainCode, offset);
    offset += 32;
    serialized.set(publicKey, offset);
    
    // Base58Check encode
    const hash1 = await sha256(serialized);
    const hash2 = await sha256(hash1);
    const checksum = hash2.slice(0, 4);
    
    const withChecksum = new Uint8Array(82);
    withChecksum.set(serialized);
    withChecksum.set(checksum, 78);
    
    const { base58Encode } = await import('../utils/encoding.js');
    return base58Encode(withChecksum);
  }
  
  /**
   * Export node info for debugging
   * @returns {Promise<object>}
   */
  async toJSON() {
    return {
      privateKey: bytesToHex(this.privateKey),
      publicKey: bytesToHex(await this.getPublicKey(true)),
      chainCode: bytesToHex(this.chainCode),
      depth: this.depth,
      index: this.index,
      parentFingerprint: this.parentFingerprint.toString(16).padStart(8, '0'),
      fingerprint: (await this.getFingerprint()).toString(16).padStart(8, '0')
    };
  }

  /**
   * Securely clear all sensitive data in this node
   * Call this when the node is no longer needed
   */
  secureCleanup() {
    if (this.privateKey) {
      secureZero(this.privateKey);
      this.privateKey = null;
    }
    if (this.chainCode) {
      secureZero(this.chainCode);
      this.chainCode = null;
    }
    if (this._publicKey) {
      secureZero(this._publicKey);
      this._publicKey = null;
    }
    this._fingerprint = null;
  }
}

/**
 * Parse a derivation path string into segments
 * @param {string} path - Path like "m/44'/0'/0'/0/0"
 * @returns {object[]} Array of { index, hardened }
 */
export function parseDerivationPath(path) {
  if (!path.startsWith('m') && !path.startsWith('M')) {
    throw new Error('Path must start with "m" or "M"');
  }
  
  const segments = path.split('/').slice(1);
  return segments.map(segment => {
    if (segment === '') return null;
    
    const hardened = segment.endsWith("'") || segment.endsWith('h');
    const indexStr = segment.replace(/['h]/g, '');
    const index = parseInt(indexStr, 10);
    
    if (isNaN(index) || index < 0) {
      throw new Error(`Invalid path segment: ${segment}`);
    }
    
    return {
      index: hardened ? index + HARDENED_OFFSET : index,
      hardened,
      displayIndex: index
    };
  }).filter(s => s !== null);
}

/**
 * Get standard derivation paths for different chains
 */
export const DERIVATION_PATHS = {
  bitcoin: {
    legacy: (account = 0, change = 0, index = 0) => `m/44'/0'/${account}'/${change}/${index}`,
    nestedSegwit: (account = 0, change = 0, index = 0) => `m/49'/0'/${account}'/${change}/${index}`,
    nativeSegwit: (account = 0, change = 0, index = 0) => `m/84'/0'/${account}'/${change}/${index}`,
    taproot: (account = 0, change = 0, index = 0) => `m/86'/0'/${account}'/${change}/${index}`,
  },
  ethereum: (account = 0, index = 0) => `m/44'/60'/${account}'/0/${index}`,
  solana: (account = 0) => `m/44'/501'/${account}'/0'`,
  tron: (account = 0, index = 0) => `m/44'/195'/${account}'/0/${index}`,
};

