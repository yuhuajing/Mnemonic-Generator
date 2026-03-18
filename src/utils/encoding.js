/**
 * Encoding utilities for various formats
 * Supports: Hex, Base58, Base64, Bech32
 */

// ========== Hex Encoding ==========

export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex) {
  const normalized = hex.replace(/^0x/, '');
  if (normalized.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(normalized.substr(i * 2, 2), 16);
  }
  return bytes;
}

// ========== UTF-8 Encoding ==========

export function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

export function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

// ========== Base58 Encoding (Bitcoin style) ==========

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(bytes) {
  if (bytes.length === 0) return '';
  
  // Count leading zeros
  let leadingZeros = 0;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    leadingZeros++;
  }
  
  // Convert bytes to big integer
  let num = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    num = num * BigInt(256) + BigInt(bytes[i]);
  }
  
  // Convert to base58
  let encoded = '';
  while (num > 0) {
    const remainder = num % BigInt(58);
    num = num / BigInt(58);
    encoded = BASE58_ALPHABET[Number(remainder)] + encoded;
  }
  
  // Add leading '1's for leading zero bytes
  return '1'.repeat(leadingZeros) + encoded;
}

export function base58Decode(str) {
  if (str.length === 0) return new Uint8Array(0);
  
  // Count leading '1's
  let leadingOnes = 0;
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    leadingOnes++;
  }
  
  // Convert from base58
  let num = BigInt(0);
  for (let i = 0; i < str.length; i++) {
    const digit = BASE58_ALPHABET.indexOf(str[i]);
    if (digit < 0) {
      throw new Error('Invalid base58 character');
    }
    num = num * BigInt(58) + BigInt(digit);
  }
  
  // Convert to bytes
  const bytes = [];
  while (num > 0) {
    bytes.unshift(Number(num % BigInt(256)));
    num = num / BigInt(256);
  }
  
  // Add leading zero bytes
  return new Uint8Array([...new Array(leadingOnes).fill(0), ...bytes]);
}

// ========== Base58Check Encoding ==========

export async function base58CheckEncode(payload, version = 0x00) {
  const versionedPayload = new Uint8Array(payload.length + 1);
  versionedPayload[0] = version;
  versionedPayload.set(payload, 1);
  
  // Double SHA256 for checksum
  const { sha256 } = await import('./crypto.js');
  const hash1 = await sha256(versionedPayload);
  const hash2 = await sha256(hash1);
  const checksum = hash2.slice(0, 4);
  
  // Concatenate and encode
  const withChecksum = new Uint8Array(versionedPayload.length + 4);
  withChecksum.set(versionedPayload);
  withChecksum.set(checksum, versionedPayload.length);
  
  return base58Encode(withChecksum);
}

export async function base58CheckDecode(str) {
  const decoded = base58Decode(str);
  if (decoded.length < 5) {
    throw new Error('Invalid base58check string');
  }
  
  const payload = decoded.slice(0, -4);
  const checksum = decoded.slice(-4);
  
  // Verify checksum
  const { sha256 } = await import('./crypto.js');
  const hash1 = await sha256(payload);
  const hash2 = await sha256(hash1);
  const expectedChecksum = hash2.slice(0, 4);
  
  if (!arraysEqual(checksum, expectedChecksum)) {
    throw new Error('Invalid checksum');
  }
  
  return {
    version: payload[0],
    payload: payload.slice(1)
  };
}

// ========== Bech32 Encoding ==========

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
  let chk = 1;
  for (const value of values) {
    const top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ value;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) {
        chk ^= BECH32_GENERATOR[i];
      }
    }
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const result = [];
  for (let i = 0; i < hrp.length; i++) {
    result.push(hrp.charCodeAt(i) >> 5);
  }
  result.push(0);
  for (let i = 0; i < hrp.length; i++) {
    result.push(hrp.charCodeAt(i) & 31);
  }
  return result;
}

function bech32CreateChecksum(hrp, data, encoding) {
  const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const constant = encoding === 'bech32m' ? 0x2bc830a3 : 1;
  const polymod = bech32Polymod(values) ^ constant;
  const checksum = [];
  for (let i = 0; i < 6; i++) {
    checksum.push((polymod >> 5 * (5 - i)) & 31);
  }
  return checksum;
}

export function bech32Encode(hrp, data, encoding = 'bech32') {
  const checksum = bech32CreateChecksum(hrp, data, encoding);
  const combined = data.concat(checksum);
  return hrp + '1' + combined.map(d => BECH32_CHARSET[d]).join('');
}

export function bech32Decode(str) {
  str = str.toLowerCase();
  const pos = str.lastIndexOf('1');
  if (pos < 1 || pos + 7 > str.length) {
    throw new Error('Invalid bech32 string');
  }
  
  const hrp = str.substring(0, pos);
  const data = [];
  for (let i = pos + 1; i < str.length; i++) {
    const d = BECH32_CHARSET.indexOf(str[i]);
    if (d === -1) {
      throw new Error('Invalid bech32 character');
    }
    data.push(d);
  }
  
  // Verify checksum
  const encoding = bech32Polymod(bech32HrpExpand(hrp).concat(data)) === 0x2bc830a3 ? 'bech32m' : 'bech32';
  const checksum = bech32CreateChecksum(hrp, data.slice(0, -6), encoding);
  
  if (!arraysEqual(data.slice(-6), checksum)) {
    throw new Error('Invalid bech32 checksum');
  }
  
  return {
    hrp,
    data: data.slice(0, -6),
    encoding
  };
}

// Convert 8-bit bytes to 5-bit groups for bech32
export function convertBits(data, fromBits, toBits, pad = true) {
  let acc = 0;
  let bits = 0;
  const result = [];
  const maxv = (1 << toBits) - 1;
  
  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) {
      throw new Error('Invalid data');
    }
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.push((acc >> bits) & maxv);
    }
  }
  
  if (pad) {
    if (bits > 0) {
      result.push((acc << (toBits - bits)) & maxv);
    }
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    throw new Error('Invalid padding');
  }
  
  return new Uint8Array(result);
}

// ========== Helper Functions ==========

function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ========== Uint32 Serialization ==========

export function uint32ToBytes(num, littleEndian = false) {
  const bytes = new Uint8Array(4);
  if (littleEndian) {
    bytes[0] = num & 0xff;
    bytes[1] = (num >> 8) & 0xff;
    bytes[2] = (num >> 16) & 0xff;
    bytes[3] = (num >> 24) & 0xff;
  } else {
    bytes[0] = (num >> 24) & 0xff;
    bytes[1] = (num >> 16) & 0xff;
    bytes[2] = (num >> 8) & 0xff;
    bytes[3] = num & 0xff;
  }
  return bytes;
}

export function bytesToUint32(bytes, littleEndian = false) {
  if (littleEndian) {
    return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
  } else {
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  }
}

