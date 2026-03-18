/**
 * Cryptographic utilities using Web Crypto API and noble libraries
 *
 * Security: Dependencies are loaded from local vendor/ directory.
 * See vendor/README.md for instructions on bundling for offline use.
 */

import { bytesToHex, hexToBytes, utf8ToBytes } from './encoding.js';
import * as secp256k1Vendor from '../vendor/secp256k1.js';
import * as ed25519Vendor from '../vendor/ed25519.js';
import { sha512 as sha512Sync } from '../vendor/sha512.js';
import { keccak_256 } from '../vendor/sha3.js';
import { ripemd160 as ripemd160Async } from '../vendor/ripemd160.js';

// ========== SHA-256 ==========

export async function sha256(data) {
  const buffer = data instanceof Uint8Array ? data : utf8ToBytes(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return new Uint8Array(hashBuffer);
}

export async function sha256Hex(data) {
  const hash = await sha256(data);
  return bytesToHex(hash);
}

// ========== SHA-512 ==========

export async function sha512(data) {
  const buffer = data instanceof Uint8Array ? data : utf8ToBytes(data);
  const hashBuffer = await crypto.subtle.digest('SHA-512', buffer);
  return new Uint8Array(hashBuffer);
}

export async function sha512Hex(data) {
  const hash = await sha512(data);
  return bytesToHex(hash);
}

// ========= Synchronous SHA-512 helper (for Ed25519) =========
// Now using local vendor module

function concatBytes(...arrays) {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// ========== RIPEMD-160 ==========
// Using local vendor module

export async function ripemd160(data) {
  return ripemd160Async(data);
}

// ========== PBKDF2 ==========

export async function pbkdf2(password, salt, iterations, keyLen, hashAlgo = 'SHA-512') {
  const passwordBuffer = password instanceof Uint8Array ? password : utf8ToBytes(password);
  const saltBuffer = salt instanceof Uint8Array ? salt : utf8ToBytes(salt);
  
  const importedKey = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: iterations,
      hash: hashAlgo
    },
    importedKey,
    keyLen * 8
  );
  
  return new Uint8Array(derivedBits);
}

// ========== HMAC-SHA512 ==========

export async function hmacSHA512(key, data) {
  const keyBuffer = key instanceof Uint8Array ? key : utf8ToBytes(key);
  const dataBuffer = data instanceof Uint8Array ? data : utf8ToBytes(data);
  
  const importedKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', importedKey, dataBuffer);
  return new Uint8Array(signature);
}

// ========== Keccak-256 ==========
// Used by Ethereum and Tron - using local vendor module

export async function keccak256(data) {
  return keccak_256(data);
}

// ========== Hash160 (Bitcoin) ==========
// SHA256 followed by RIPEMD160

export async function hash160(data) {
  const sha = await sha256(data);
  return await ripemd160(sha);
}

// ========== Random Bytes Generation ==========

export function getRandomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

// Test entropy quality (optional, for user confidence)
export function testEntropyQuality(samples = 1000) {
  const stats = {
    samples,
    mean: 0,
    min: 255,
    max: 0,
    distribution: new Array(256).fill(0)
  };
  
  let sum = 0;
  for (let i = 0; i < samples; i++) {
    const byte = getRandomBytes(1)[0];
    sum += byte;
    stats.min = Math.min(stats.min, byte);
    stats.max = Math.max(stats.max, byte);
    stats.distribution[byte]++;
  }
  
  stats.mean = sum / samples;
  return stats;
}

// ========== Big Integer Operations ==========

// Modular addition for secp256k1 curve
const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

export function addPrivateKeys(key1, key2) {
  const k1 = BigInt('0x' + bytesToHex(key1));
  const k2 = BigInt('0x' + bytesToHex(key2));
  const sum = (k1 + k2) % SECP256K1_N;
  
  // Convert back to 32-byte array
  const hexStr = sum.toString(16).padStart(64, '0');
  return hexToBytes(hexStr);
}

// ========== Elliptic Curve Operations ==========
// Using local vendor modules

export async function loadSecp256k1() {
  return secp256k1Vendor;
}

export async function loadEd25519() {
  if (ed25519Vendor.etc && !ed25519Vendor.etc.sha512Sync) {
    ed25519Vendor.etc.sha512Sync = sha512Sync;
  }
  return ed25519Vendor;
}

export async function privateKeyToPublicKey(privateKey, compressed = true) {
  const secp = await loadSecp256k1();
  const publicKey = await secp.getPublicKey(privateKey, compressed);
  return new Uint8Array(publicKey);
}

export async function ed25519GetPublicKey(privateKey) {
  const ed = await loadEd25519();
  return await ed.getPublicKey(privateKey);
}

// ========== Taproot Tweaking (BIP341) ==========
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

/**
 * Compute tagged hash as per BIP340
 * tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
 * @param {string} tag - Tag string
 * @param {Uint8Array} msg - Message to hash
 * @returns {Promise<Uint8Array>}
 */
async function taggedHash(tag, msg) {
  const tagHash = await sha256(utf8ToBytes(tag));
  const combined = new Uint8Array(tagHash.length * 2 + msg.length);
  combined.set(tagHash, 0);
  combined.set(tagHash, tagHash.length);
  combined.set(msg, tagHash.length * 2);
  return await sha256(combined);
}

/**
 * Lift x-only public key to full point (with even y-coordinate)
 * @param {Uint8Array} xOnlyPubkey - 32-byte x-coordinate
 * @returns {Promise<Uint8Array>} 33-byte compressed public key
 */
async function liftX(xOnlyPubkey) {
  const secp = await loadSecp256k1();

  // Try with 02 prefix (even y)
  const compressed02 = new Uint8Array(33);
  compressed02[0] = 0x02;
  compressed02.set(xOnlyPubkey, 1);

  try {
    // Validate point is on curve by attempting to use it
    const point = secp.Point ? secp.Point.fromHex(bytesToHex(compressed02)) : null;
    if (point) return compressed02;
  } catch (e) {
    // If 02 fails, try 03 (odd y)
    const compressed03 = new Uint8Array(33);
    compressed03[0] = 0x03;
    compressed03.set(xOnlyPubkey, 1);
    return compressed03;
  }

  return compressed02;
}

/**
 * Check if a point has an even y-coordinate
 * @param {Uint8Array} publicKey - 33-byte compressed or 65-byte uncompressed
 * @returns {boolean}
 */
function hasEvenY(publicKey) {
  if (publicKey.length === 33) {
    return publicKey[0] === 0x02;
  } else if (publicKey.length === 65) {
    // Last byte of y-coordinate determines parity
    return publicKey[64] % 2 === 0;
  }
  return true;
}

/**
 * Taproot tweak public key according to BIP341/BIP86
 * For key-path only spending (no script tree):
 * 1. If P has odd y, use -P (negate)
 * 2. tweak = tagged_hash("TapTweak", P_x)
 * 3. Q = P + tweak * G
 *
 * @param {Uint8Array} publicKey - 33-byte compressed public key
 * @returns {Promise<Uint8Array>} 32-byte x-only tweaked public key
 */
export async function taprootTweakPublicKey(publicKey) {
  const secp = await loadSecp256k1();

  // Get x-only pubkey (remove prefix)
  const xOnlyPubkey = publicKey.length === 33 ? publicKey.slice(1) : publicKey;

  // BIP341: If P has odd y, we must use the negated point
  // For key-path only, we use the x-only key directly for the tweak
  // The internal key used must have even y
  let workingPubkey = publicKey;
  if (!hasEvenY(publicKey)) {
    // Negate by using 02 prefix instead of 03
    // The x-coordinate stays the same, only y changes
    workingPubkey = new Uint8Array(33);
    workingPubkey[0] = 0x02;
    workingPubkey.set(xOnlyPubkey, 1);
  }

  // For key-path only spending, merkle root is empty
  // tweak = tagged_hash("TapTweak", pubkey_x)
  const tweak = await taggedHash('TapTweak', xOnlyPubkey);

  // Validate tweak is less than curve order
  const tweakBigInt = BigInt('0x' + bytesToHex(tweak));
  const curveOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

  if (tweakBigInt >= curveOrder) {
    throw new Error('Tweak is too large');
  }

  const pubkeyHex = bytesToHex(workingPubkey);

  // Check if library supports ProjectivePoint operations (v2.0.0+)
  const PointClass = secp.ProjectivePoint || secp.Point;
  if (!PointClass || !PointClass.fromHex || !PointClass.BASE) {
    throw new Error('Taproot requires secp256k1 point operations');
  }

  const P = PointClass.fromHex(pubkeyHex);
  const tweakPoint = PointClass.BASE.multiply(tweakBigInt);
  const Q = P.add(tweakPoint);

  // Get x-coordinate only (BIP341 uses x-only pubkeys)
  return Q.toRawBytes(true).slice(1);
}

/**
 * Taproot tweak private key according to BIP341/BIP86
 * @param {Uint8Array} privateKey - 32-byte private key
 * @param {Uint8Array} publicKey - 33-byte compressed public key
 * @returns {Promise<Uint8Array>} 32-byte tweaked private key
 */
export async function taprootTweakPrivateKey(privateKey, publicKey) {
  const xOnlyPubkey = publicKey.length === 33 ? publicKey.slice(1) : publicKey;
  let keyInt = BigInt('0x' + bytesToHex(privateKey));

  if (!hasEvenY(publicKey)) {
    keyInt = (SECP256K1_N - keyInt) % SECP256K1_N;
  }

  const tweak = await taggedHash('TapTweak', xOnlyPubkey);
  const tweakBigInt = BigInt('0x' + bytesToHex(tweak));

  if (tweakBigInt >= SECP256K1_N) {
    throw new Error('Taproot tweak is too large');
  }

  const tweaked = (keyInt + tweakBigInt) % SECP256K1_N;
  if (tweaked === BigInt(0)) {
    throw new Error('Taproot tweak produced invalid key');
  }

  return hexToBytes(tweaked.toString(16).padStart(64, '0'));
}

/**
 * Compute full Taproot output key with optional script tree
 * @param {Uint8Array} internalPubkey - 32-byte x-only internal public key
 * @param {Uint8Array|null} merkleRoot - 32-byte merkle root of script tree (null for key-path only)
 * @returns {Promise<Uint8Array>} 32-byte x-only output public key
 */
export async function computeTaprootOutputKey(internalPubkey, merkleRoot = null) {
  // Lift the x-only key to a full point
  const fullPubkey = await liftX(internalPubkey);

  if (merkleRoot === null) {
    // Key-path only: tweak with just the internal key
    return taprootTweakPublicKey(fullPubkey);
  }

  // With script tree: tweak = tagged_hash("TapTweak", internal_key || merkle_root)
  const tweakData = new Uint8Array(internalPubkey.length + merkleRoot.length);
  tweakData.set(internalPubkey, 0);
  tweakData.set(merkleRoot, internalPubkey.length);

  const tweak = await taggedHash('TapTweak', tweakData);

  // Compute Q = P + tweak * G
  const secp = await loadSecp256k1();
  const tweakBigInt = BigInt('0x' + bytesToHex(tweak));

  const PointClass = secp.ProjectivePoint || secp.Point;
  if (PointClass && PointClass.fromHex && PointClass.BASE) {
    const P = PointClass.fromHex(bytesToHex(fullPubkey));
    const tweakPoint = PointClass.BASE.multiply(tweakBigInt);
    const Q = P.add(tweakPoint);
    return Q.toRawBytes(true).slice(1);
  }

  // Fallback
  return internalPubkey;
}

// ========== WIF Encoding (Bitcoin Private Key) ==========

export async function privateKeyToWIF(privateKey, compressed = true, testnet = false) {
  const version = testnet ? 0xef : 0x80;
  let payload;
  
  if (compressed) {
    payload = new Uint8Array(33);
    payload.set(privateKey);
    payload[32] = 0x01;
  } else {
    payload = privateKey;
  }
  
  const { base58CheckEncode } = await import('./encoding.js');
  return await base58CheckEncode(payload, version);
}

export async function WIFToPrivateKey(wif) {
  const { base58CheckDecode } = await import('./encoding.js');
  const { version, payload } = await base58CheckDecode(wif);
  
  const testnet = version === 0xef;
  const compressed = payload.length === 33;
  const privateKey = compressed ? payload.slice(0, 32) : payload;
  
  return { privateKey, compressed, testnet };
}

