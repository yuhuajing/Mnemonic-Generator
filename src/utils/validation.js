/**
 * Input validation utilities
 */

// ========== Mnemonic Validation ==========

export function isValidWordCount(wordCount) {
  return [12, 15, 18, 21, 24].includes(wordCount);
}

export function sanitizeMnemonic(mnemonic) {
  return mnemonic
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

export function getMnemonicWordCount(mnemonic) {
  return sanitizeMnemonic(mnemonic).split(' ').length;
}

// ========== Derivation Path Validation ==========

export function isValidDerivationPath(path) {
  // BIP32 path format: m/44'/0'/0'/0/0
  const regex = /^m(\/\d+'?)+$/;
  return regex.test(path);
}

export function parseDerivationPath(path) {
  if (!isValidDerivationPath(path)) {
    throw new Error('Invalid derivation path');
  }
  
  const segments = path.split('/').slice(1); // Remove 'm'
  return segments.map(segment => {
    const hardened = segment.endsWith("'");
    const index = parseInt(segment);
    return {
      index: hardened ? index + 0x80000000 : index,
      hardened
    };
  });
}

// ========== Address Validation ==========

export function isValidBitcoinAddress(address) {
  // Basic format checks
  if (address.startsWith('bc1') || address.startsWith('tb1')) {
    // Bech32/Bech32m (SegWit/Taproot)
    return /^(bc1|tb1)[a-z0-9]{39,87}$/i.test(address);
  } else if (address.startsWith('1') || address.startsWith('3')) {
    // Base58Check (Legacy/P2SH)
    return /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address);
  }
  return false;
}

export function isValidEthereumAddress(address) {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

export function isValidSolanaAddress(address) {
  // Base58, typically 32-44 characters
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);
}

export function isValidTronAddress(address) {
  // Starts with 'T', Base58Check
  return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address);
}

// ========== Passphrase Validation ==========

export function validatePassphrase(passphrase) {
  // Passphrase can be any string, but warn about common issues
  const warnings = [];
  
  if (passphrase.length > 0 && passphrase.length < 8) {
    warnings.push('Passphrase is short (less than 8 characters)');
  }
  
  if (/^\s+|\s+$/.test(passphrase)) {
    warnings.push('Passphrase has leading or trailing spaces');
  }
  
  // Check for non-ASCII characters
  if (!/^[\x00-\x7F]*$/.test(passphrase)) {
    warnings.push('Passphrase contains non-ASCII characters (may cause compatibility issues)');
  }
  
  return {
    valid: true, // Passphrase is always technically valid
    warnings
  };
}

// ========== General Input Sanitization ==========

export function sanitizeInput(input) {
  // Remove potentially dangerous characters for display
  return input.replace(/[<>]/g, '');
}

export function isValidHex(hex) {
  return /^(0x)?[a-fA-F0-9]+$/.test(hex) && hex.replace('0x', '').length % 2 === 0;
}

export function isValidIndex(index) {
  return Number.isInteger(index) && index >= 0 && index < 0x80000000;
}

