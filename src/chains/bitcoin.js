/**
 * Bitcoin address derivation
 * Supports: Legacy (P2PKH), Nested SegWit (P2SH-P2WPKH), Native SegWit (P2WPKH), Taproot (P2TR)
 */

import { HDNode, DERIVATION_PATHS } from '../core/bip32.js';
import { hash160, sha256, privateKeyToWIF, taprootTweakPublicKey, taprootTweakPrivateKey } from '../utils/crypto.js';
import { bytesToHex, base58Encode, bech32Encode, convertBits } from '../utils/encoding.js';

/**
 * Generate Legacy (P2PKH) address
 * @param {Uint8Array} publicKey - Compressed public key
 * @returns {Promise<string>} Bitcoin address starting with '1'
 */
async function generateP2PKH(publicKey) {
  const pubKeyHash = await hash160(publicKey);
  
  // Version byte 0x00 for mainnet
  const versionedPayload = new Uint8Array(21);
  versionedPayload[0] = 0x00;
  versionedPayload.set(pubKeyHash, 1);
  
  // Double SHA256 checksum
  const hash1 = await sha256(versionedPayload);
  const hash2 = await sha256(hash1);
  const checksum = hash2.slice(0, 4);
  
  // Combine and encode
  const addressBytes = new Uint8Array(25);
  addressBytes.set(versionedPayload);
  addressBytes.set(checksum, 21);
  
  return base58Encode(addressBytes);
}

/**
 * Generate Nested SegWit (P2SH-P2WPKH) address
 * @param {Uint8Array} publicKey - Compressed public key
 * @returns {Promise<string>} Bitcoin address starting with '3'
 */
async function generateP2SH_P2WPKH(publicKey) {
  const pubKeyHash = await hash160(publicKey);
  
  // Create redeemScript: OP_0 (0x00) + OP_PUSH20 (0x14) + pubKeyHash
  const redeemScript = new Uint8Array(22);
  redeemScript[0] = 0x00;
  redeemScript[1] = 0x14;
  redeemScript.set(pubKeyHash, 2);
  
  // Hash the redeemScript
  const scriptHash = await hash160(redeemScript);
  
  // Version byte 0x05 for P2SH
  const versionedPayload = new Uint8Array(21);
  versionedPayload[0] = 0x05;
  versionedPayload.set(scriptHash, 1);
  
  // Double SHA256 checksum
  const hash1 = await sha256(versionedPayload);
  const hash2 = await sha256(hash1);
  const checksum = hash2.slice(0, 4);
  
  // Combine and encode
  const addressBytes = new Uint8Array(25);
  addressBytes.set(versionedPayload);
  addressBytes.set(checksum, 21);
  
  return base58Encode(addressBytes);
}

/**
 * Generate Native SegWit (P2WPKH) address
 * @param {Uint8Array} publicKey - Compressed public key
 * @returns {Promise<string>} Bitcoin address starting with 'bc1q'
 */
async function generateP2WPKH(publicKey) {
  const pubKeyHash = await hash160(publicKey);
  
  // Convert to 5-bit groups for bech32
  const words = convertBits(pubKeyHash, 8, 5, true);
  
  // Witness version 0
  const data = new Uint8Array(words.length + 1);
  data[0] = 0x00;
  data.set(words, 1);
  
  return bech32Encode('bc', Array.from(data), 'bech32');
}

/**
 * Generate Taproot (P2TR) address
 * @param {Uint8Array} publicKey - Compressed public key (33 bytes)
 * @returns {Promise<string>} Bitcoin address starting with 'bc1p'
 */
async function generateP2TR(publicKey) {
  // Taproot uses x-only pubkey (32 bytes, no prefix)
  const xOnlyPubkey = await taprootTweakPublicKey(publicKey);
  
  // Convert to 5-bit groups for bech32m
  const words = convertBits(xOnlyPubkey, 8, 5, true);
  
  // Witness version 1
  const data = new Uint8Array(words.length + 1);
  data[0] = 0x01;
  data.set(words, 1);
  
  return bech32Encode('bc', Array.from(data), 'bech32m');
}

/**
 * Derive Bitcoin address
 * @param {HDNode} rootNode - Root HD node from seed
 * @param {string} type - Address type: 'legacy', 'nested-segwit', 'native-segwit', 'taproot'
 * @param {number} account - Account index (default: 0)
 * @param {number} change - Change index (0 = receive, 1 = change, default: 0)
 * @param {number} index - Address index (default: 0)
 * @returns {Promise<object>} Address info
 */
export async function deriveBitcoinAddress(rootNode, type, account = 0, change = 0, index = 0) {
  // Get derivation path
  const pathFn = DERIVATION_PATHS.bitcoin[type === 'nested-segwit' ? 'nestedSegwit' : type === 'native-segwit' ? 'nativeSegwit' : type];
  if (!pathFn) {
    throw new Error(`Invalid Bitcoin address type: ${type}`);
  }
  
  const path = pathFn(account, change, index);
  
  // Derive child node
  const node = await rootNode.derive(path);
  
  // Get keys
  const privateKey = node.privateKey;
  const publicKey = await node.getPublicKey(true);
  
  // Generate address based on type
  let address;
  switch (type) {
    case 'legacy':
      address = await generateP2PKH(publicKey);
      break;
    case 'nested-segwit':
      address = await generateP2SH_P2WPKH(publicKey);
      break;
    case 'native-segwit':
      address = await generateP2WPKH(publicKey);
      break;
    case 'taproot':
      address = await generateP2TR(publicKey);
      break;
    default:
      throw new Error(`Unsupported address type: ${type}`);
  }
  
  let outputPrivateKey = privateKey;
  if (type === 'taproot') {
    outputPrivateKey = await taprootTweakPrivateKey(privateKey, publicKey);
  }

  // Convert private key to WIF
  const wif = await privateKeyToWIF(outputPrivateKey, true, false);
  
  return {
    address,
    privateKey: bytesToHex(outputPrivateKey),
    privateKeyWIF: wif,
    publicKey: bytesToHex(publicKey),
    privateKeyInternal: type === 'taproot' ? bytesToHex(privateKey) : undefined,
    path,
    type,
    account,
    change,
    index
  };
}

/**
 * Derive multiple Bitcoin addresses
 * @param {HDNode} rootNode 
 * @param {string} type 
 * @param {number} account 
 * @param {number} change 
 * @param {number} startIndex 
 * @param {number} count 
 * @returns {Promise<object[]>}
 */
export async function deriveBitcoinAddresses(rootNode, type, account = 0, change = 0, startIndex = 0, count = 5) {
  const addresses = [];
  for (let i = startIndex; i < startIndex + count; i++) {
    const addr = await deriveBitcoinAddress(rootNode, type, account, change, i);
    addresses.push(addr);
  }
  return addresses;
}

/**
 * Get all Bitcoin address types
 * @returns {string[]}
 */
export function getBitcoinAddressTypes() {
  return ['legacy', 'nested-segwit', 'native-segwit', 'taproot'];
}

/**
 * Get Bitcoin address type display name
 * @param {string} type 
 * @returns {string}
 */
export function getBitcoinAddressTypeDisplayName(type) {
  const names = {
    'legacy': 'Legacy (P2PKH)',
    'nested-segwit': 'Nested SegWit (P2SH-P2WPKH)',
    'native-segwit': 'Native SegWit (P2WPKH)',
    'taproot': 'Taproot (P2TR)'
  };
  return names[type] || type;
}

