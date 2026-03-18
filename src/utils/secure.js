/**
 * Secure memory utilities for handling sensitive cryptographic data
 *
 * IMPORTANT: JavaScript doesn't provide guaranteed memory zeroing due to:
 * - Garbage collection timing is unpredictable
 * - JIT compilation may optimize away zeroing operations
 * - String immutability means mnemonic strings cannot be truly cleared
 *
 * These utilities provide best-effort protection but cannot guarantee
 * complete erasure. For maximum security, use in an air-gapped environment.
 */

/**
 * Securely zero a Uint8Array
 * Uses crypto.getRandomValues to overwrite with random data first,
 * then zeros, to prevent potential recovery from memory.
 *
 * @param {Uint8Array} array - Array to zero
 */
export function secureZero(array) {
  if (!(array instanceof Uint8Array)) return;
  if (array.length === 0) return;

  try {
    // First pass: overwrite with random data
    crypto.getRandomValues(array);
    // Second pass: zero out
    array.fill(0);
  } catch (e) {
    // Fallback if crypto not available
    array.fill(0);
  }
}

/**
 * Securely zero multiple arrays
 * @param  {...Uint8Array} arrays - Arrays to zero
 */
export function secureZeroAll(...arrays) {
  for (const array of arrays) {
    if (array) secureZero(array);
  }
}

/**
 * Create a secure container for sensitive data
 * Provides automatic cleanup when done
 */
export class SecureBuffer {
  constructor(length) {
    this._buffer = new Uint8Array(length);
    this._cleared = false;
  }

  get buffer() {
    if (this._cleared) {
      throw new Error('SecureBuffer has been cleared');
    }
    return this._buffer;
  }

  get length() {
    return this._buffer.length;
  }

  /**
   * Set data into the secure buffer
   * @param {Uint8Array} data
   * @param {number} offset
   */
  set(data, offset = 0) {
    if (this._cleared) {
      throw new Error('SecureBuffer has been cleared');
    }
    this._buffer.set(data, offset);
  }

  /**
   * Get a slice of the buffer (creates a copy)
   * @param {number} start
   * @param {number} end
   * @returns {Uint8Array}
   */
  slice(start, end) {
    if (this._cleared) {
      throw new Error('SecureBuffer has been cleared');
    }
    return this._buffer.slice(start, end);
  }

  /**
   * Clear the buffer securely
   */
  clear() {
    if (!this._cleared) {
      secureZero(this._buffer);
      this._cleared = true;
    }
  }

  /**
   * Check if buffer has been cleared
   */
  get isCleared() {
    return this._cleared;
  }
}

/**
 * Clear sensitive string by attempting to overwrite (best effort)
 * Note: Due to JavaScript string immutability, this is not guaranteed
 *
 * @param {string} str - String to attempt to clear
 * @returns {string} Empty string
 */
export function clearString(str) {
  // We cannot truly clear strings in JS, but we can:
  // 1. Return an empty string for the caller to use
  // 2. Hope the original gets garbage collected
  return '';
}

/**
 * Mixin for adding secure cleanup to classes with private keys
 */
export const SecureCleanupMixin = {
  /**
   * Securely clear all sensitive data in this object
   */
  secureCleanup() {
    // Clear any Uint8Array properties
    for (const key of Object.keys(this)) {
      const value = this[key];
      if (value instanceof Uint8Array) {
        secureZero(value);
        this[key] = null;
      }
    }

    // Clear cached values
    if (this._publicKey instanceof Uint8Array) {
      secureZero(this._publicKey);
      this._publicKey = null;
    }
  }
};

/**
 * Register cleanup handlers for page unload
 * @param {Function} cleanupFn - Function to call on cleanup
 * @returns {Function} Function to unregister the handler
 */
export function registerCleanupHandler(cleanupFn) {
  const handler = () => {
    try {
      cleanupFn();
    } catch (e) {
      // Ignore errors during cleanup
    }
  };

  // Multiple events to catch different unload scenarios
  window.addEventListener('beforeunload', handler);
  window.addEventListener('unload', handler);
  window.addEventListener('pagehide', handler);

  // Return unregister function
  return () => {
    window.removeEventListener('beforeunload', handler);
    window.removeEventListener('unload', handler);
    window.removeEventListener('pagehide', handler);
  };
}

/**
 * Clear clipboard after a delay (security measure)
 * @param {number} delayMs - Delay in milliseconds before clearing
 */
export function clearClipboardAfterDelay(delayMs = 60000) {
  setTimeout(async () => {
    try {
      // Check if current clipboard content looks like a key or mnemonic
      const text = await navigator.clipboard.readText();
      // If it's hex or looks like mnemonic, clear it
      if (/^[a-f0-9]{64}$/i.test(text) || /^([a-z]+\s+){11,23}[a-z]+$/i.test(text)) {
        await navigator.clipboard.writeText('');
      }
    } catch (e) {
      // Clipboard access denied or other error - ignore
    }
  }, delayMs);
}
