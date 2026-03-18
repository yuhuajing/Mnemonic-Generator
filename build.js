/**
 * Build script - bundles all JS into a single HTML file
 * Run with: node build.js
 */

const fs = require("fs");
const path = require("path");

const SRC_DIR = path.join(__dirname, "src");
const OUTPUT_FILE = path.join(__dirname, "mnemonic-generator.html");

// Read all source files
function readFile(relativePath) {
  return fs.readFileSync(path.join(SRC_DIR, relativePath), "utf8");
}

// Remove import/export statements and module syntax
function processModule(code, moduleName) {
  // Remove import statements
  code = code.replace(/^import\s+.*?from\s+['"].*?['"];?\s*$/gm, "");
  code = code.replace(/^import\s+['"].*?['"];?\s*$/gm, "");

  // Remove export statements but keep the code
  code = code.replace(/^export\s+(async\s+)?function\s+/gm, "$1function ");
  code = code.replace(/^export\s+(const|let|var|class)\s+/gm, "$1 ");
  code = code.replace(/^export\s+\{[^}]*\};?\s*$/gm, "");
  code = code.replace(/^export\s+default\s+/gm, "");

  return `// ========== ${moduleName} ==========\n${code}\n`;
}

console.log("Building standalone HTML file...");

// Read wordlist
const wordlist = readFile("wordlist_english.txt");

// Read CSS
const css = readFile("ui/styles.css");

// Read vendor bundles (pre-bundled ESM files)
const vendorSecp256k1 = readFile("vendor/secp256k1.js");
const vendorEd25519 = readFile("vendor/ed25519.js");
const vendorSha512 = readFile("vendor/sha512.js");
const vendorSha3 = readFile("vendor/sha3.js");
const vendorRipemd160 = readFile("vendor/ripemd160.js");

function toDataUrl(code) {
  return `data:text/javascript;base64,${Buffer.from(code, "utf8").toString("base64")}`;
}

const vendorSecp256k1Url = toDataUrl(vendorSecp256k1);
const vendorEd25519Url = toDataUrl(vendorEd25519);
const vendorSha512Url = toDataUrl(vendorSha512);
const vendorSha3Url = toDataUrl(vendorSha3);
const vendorRipemd160Url = toDataUrl(vendorRipemd160);

// Read and process JS modules in dependency order
const modules = [
  ["utils/encoding.js", "Encoding"],
  ["utils/validation.js", "Validation"],
  ["utils/secure.js", "Secure"],
];

// Build the HTML
const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Secure offline mnemonic generator for Bitcoin, Ethereum, Solana, and Tron">
  <meta name="robots" content="noindex, nofollow">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:;">
  <title>Mnemonic Generator - Secure HD Wallet Tool</title>
  <style>
${css}
  </style>
</head>
<body>
  <div id="app">
    <div class="loading">
      <div class="spinner"></div>
      <div>Loading application...</div>
    </div>
  </div>

  <script>
    // Embedded wordlist
    window.EMBEDDED_WORDLIST = \`${wordlist}\`;
  </script>

  <script type="module">
    // Import all dependencies from embedded data URLs (offline)
    const secp256k1 = await import('${vendorSecp256k1Url}');
    const ed25519 = await import('${vendorEd25519Url}');
    const sha512Mod = await import('${vendorSha512Url}');
    const sha3Mod = await import('${vendorSha3Url}');
    const ripemd160Mod = await import('${vendorRipemd160Url}');

    // Store in window for global access
    window.secp256k1Lib = secp256k1;
    window.ed25519Lib = ed25519;
    window.noble_hashes_sha512 = sha512Mod.sha512;
    window.keccak256Fn = sha3Mod.keccak_256;
    window.ripemd160Fn = ripemd160Mod.ripemd160;

    // Set up Ed25519 sha512Sync
    if (ed25519.etc) {
      ed25519.etc.sha512Sync = (...msgs) => {
        const msg = msgs.length === 1 ? msgs[0] : msgs.reduce((acc, m) => {
          const result = new Uint8Array(acc.length + m.length);
          result.set(acc);
          result.set(m, acc.length);
          return result;
        }, new Uint8Array(0));
        return sha512Mod.sha512(msg);
      };
    }

    // Signal that libraries are loaded
    window.cryptoLibsLoaded = true;
    window.dispatchEvent(new Event('cryptoLibsLoaded'));
  </script>

  <script type="module">
    // Wait for crypto libraries
    async function waitForLibs() {
      if (window.cryptoLibsLoaded) return;
      return new Promise(resolve => {
        window.addEventListener('cryptoLibsLoaded', resolve, { once: true });
      });
    }

    await waitForLibs();

    // ==================== ENCODING ====================

    function bytesToHex(bytes) {
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function hexToBytes(hex) {
      const normalized = hex.replace(/^0x/, '');
      if (normalized.length % 2 !== 0) throw new Error('Invalid hex string');
      const bytes = new Uint8Array(normalized.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(normalized.substr(i * 2, 2), 16);
      }
      return bytes;
    }

    function utf8ToBytes(str) {
      return new TextEncoder().encode(str);
    }

    const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    function base58Encode(bytes) {
      if (bytes.length === 0) return '';
      let leadingZeros = 0;
      for (let i = 0; i < bytes.length && bytes[i] === 0; i++) leadingZeros++;
      let num = BigInt(0);
      for (let i = 0; i < bytes.length; i++) num = num * BigInt(256) + BigInt(bytes[i]);
      let encoded = '';
      while (num > 0) {
        encoded = BASE58_ALPHABET[Number(num % BigInt(58))] + encoded;
        num = num / BigInt(58);
      }
      return '1'.repeat(leadingZeros) + encoded;
    }

    function uint32ToBytes(num, littleEndian = false) {
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

    const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    function bech32Polymod(values) {
      let chk = 1;
      for (const value of values) {
        const top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ value;
        for (let i = 0; i < 5; i++) {
          if ((top >> i) & 1) chk ^= BECH32_GENERATOR[i];
        }
      }
      return chk;
    }

    function bech32HrpExpand(hrp) {
      const result = [];
      for (let i = 0; i < hrp.length; i++) result.push(hrp.charCodeAt(i) >> 5);
      result.push(0);
      for (let i = 0; i < hrp.length; i++) result.push(hrp.charCodeAt(i) & 31);
      return result;
    }

    function bech32CreateChecksum(hrp, data, encoding) {
      const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
      const constant = encoding === 'bech32m' ? 0x2bc830a3 : 1;
      const polymod = bech32Polymod(values) ^ constant;
      const checksum = [];
      for (let i = 0; i < 6; i++) checksum.push((polymod >> 5 * (5 - i)) & 31);
      return checksum;
    }

    function bech32Encode(hrp, data, encoding = 'bech32') {
      const checksum = bech32CreateChecksum(hrp, data, encoding);
      const combined = data.concat(checksum);
      return hrp + '1' + combined.map(d => BECH32_CHARSET[d]).join('');
    }

    function convertBits(data, fromBits, toBits, pad = true) {
      let acc = 0, bits = 0;
      const result = [];
      const maxv = (1 << toBits) - 1;
      for (const value of data) {
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
          bits -= toBits;
          result.push((acc >> bits) & maxv);
        }
      }
      if (pad && bits > 0) result.push((acc << (toBits - bits)) & maxv);
      return new Uint8Array(result);
    }

    // ==================== CRYPTO ====================

    async function sha256(data) {
      const buffer = data instanceof Uint8Array ? data : utf8ToBytes(data);
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      return new Uint8Array(hashBuffer);
    }

    async function hmacSHA512(key, data) {
      const keyBuffer = key instanceof Uint8Array ? key : utf8ToBytes(key);
      const dataBuffer = data instanceof Uint8Array ? data : utf8ToBytes(data);
      const importedKey = await crypto.subtle.importKey('raw', keyBuffer, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
      const signature = await crypto.subtle.sign('HMAC', importedKey, dataBuffer);
      return new Uint8Array(signature);
    }

    async function pbkdf2(password, salt, iterations, keyLen, hashAlgo = 'SHA-512') {
      const passwordBuffer = password instanceof Uint8Array ? password : utf8ToBytes(password);
      const saltBuffer = salt instanceof Uint8Array ? salt : utf8ToBytes(salt);
      const importedKey = await crypto.subtle.importKey('raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveBits']);
      const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBuffer, iterations, hash: hashAlgo }, importedKey, keyLen * 8);
      return new Uint8Array(derivedBits);
    }

    async function hash160(data) {
      const sha = await sha256(data);
      return window.ripemd160Fn(sha);
    }

    async function keccak256(data) {
      return window.keccak256Fn(data);
    }

    const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

    function addPrivateKeys(key1, key2) {
      const k1 = BigInt('0x' + bytesToHex(key1));
      const k2 = BigInt('0x' + bytesToHex(key2));
      const sum = (k1 + k2) % SECP256K1_N;
      return hexToBytes(sum.toString(16).padStart(64, '0'));
    }

    async function privateKeyToPublicKey(privateKey, compressed = true) {
      return window.secp256k1Lib.getPublicKey(privateKey, compressed);
    }

    async function ed25519GetPublicKey(privateKey) {
      return window.ed25519Lib.getPublicKey(privateKey);
    }

    async function taggedHash(tag, msg) {
      const tagHash = await sha256(utf8ToBytes(tag));
      const combined = new Uint8Array(tagHash.length * 2 + msg.length);
      combined.set(tagHash, 0);
      combined.set(tagHash, tagHash.length);
      combined.set(msg, tagHash.length * 2);
      return await sha256(combined);
    }

    function hasEvenY(publicKey) {
      if (publicKey.length === 33) return publicKey[0] === 0x02;
      if (publicKey.length === 65) return publicKey[64] % 2 === 0;
      return true;
    }

    async function taprootTweakPublicKey(publicKey) {
      const xOnlyPubkey = publicKey.length === 33 ? publicKey.slice(1) : publicKey;
      let workingPubkey = publicKey;
      if (!hasEvenY(publicKey)) {
        workingPubkey = new Uint8Array(33);
        workingPubkey[0] = 0x02;
        workingPubkey.set(xOnlyPubkey, 1);
      }
      const tweak = await taggedHash('TapTweak', xOnlyPubkey);
      const tweakBigInt = BigInt('0x' + bytesToHex(tweak));
      try {
        const secp = window.secp256k1Lib;
        // Use ProjectivePoint for @noble/secp256k1 v2.0.0+
        const PointClass = secp.ProjectivePoint || secp.Point;
        if (PointClass) {
          const P = PointClass.fromHex(bytesToHex(workingPubkey));
          const tweakPoint = PointClass.BASE.multiply(tweakBigInt);
          const Q = P.add(tweakPoint);
          return Q.toRawBytes(true).slice(1);
        }
      } catch (e) {
        console.warn('Taproot tweak failed:', e);
      }
      return xOnlyPubkey;
    }

    async function privateKeyToWIF(privateKey, compressed = true, testnet = false) {
      const version = testnet ? 0xef : 0x80;
      let payload;
      if (compressed) {
        payload = new Uint8Array(34);
        payload[0] = version;
        payload.set(privateKey, 1);
        payload[33] = 0x01;
      } else {
        payload = new Uint8Array(33);
        payload[0] = version;
        payload.set(privateKey, 1);
      }
      const hash1 = await sha256(payload);
      const hash2 = await sha256(hash1);
      const checksum = hash2.slice(0, 4);
      const withChecksum = new Uint8Array(payload.length + 4);
      withChecksum.set(payload);
      withChecksum.set(checksum, payload.length);
      return base58Encode(withChecksum);
    }

    // ==================== BIP39 ====================

    let WORDLIST = null;

    function loadWordlist(text) {
      const words = text.trim().split('\\n').map(w => w.trim());
      if (words.length !== 2048) throw new Error('Invalid wordlist');
      WORDLIST = words;
      return words;
    }

    function getWordlist() {
      if (!WORDLIST) throw new Error('Wordlist not loaded');
      return WORDLIST;
    }

    function bytesToBinary(bytes) {
      return Array.from(bytes).map(byte => byte.toString(2).padStart(8, '0')).join('');
    }

    async function entropyToMnemonic(entropy) {
      const wordlist = getWordlist();
      const entropyBits = entropy.length * 8;
      const hash = await sha256(entropy);
      const checksumBits = entropyBits / 32;
      const checksumBinary = bytesToBinary(hash).slice(0, checksumBits);
      const entropyBinary = bytesToBinary(entropy);
      const fullBinary = entropyBinary + checksumBinary;
      const words = [];
      for (let i = 0; i < fullBinary.length; i += 11) {
        const index = parseInt(fullBinary.slice(i, i + 11), 2);
        words.push(wordlist[index]);
      }
      return words.join(' ');
    }

    function sanitizeMnemonic(mnemonic) {
      return mnemonic.trim().toLowerCase().replace(/\\s+/g, ' ');
    }

    async function mnemonicToEntropy(mnemonic) {
      const wordlist = getWordlist();
      const words = sanitizeMnemonic(mnemonic).split(' ');
      const indices = words.map(word => {
        const index = wordlist.indexOf(word);
        if (index === -1) throw new Error('Invalid word: ' + word);
        return index;
      });
      const binary = indices.map(i => i.toString(2).padStart(11, '0')).join('');
      const checksumBits = words.length / 3;
      const entropyBits = binary.length - checksumBits;
      const entropyBinary = binary.slice(0, entropyBits);
      const checksumBinary = binary.slice(entropyBits);
      const bytes = [];
      for (let i = 0; i < entropyBinary.length; i += 8) {
        bytes.push(parseInt(entropyBinary.slice(i, i + 8), 2));
      }
      const entropy = new Uint8Array(bytes);
      const hash = await sha256(entropy);
      const expectedChecksum = bytesToBinary(hash).slice(0, checksumBits);
      if (checksumBinary !== expectedChecksum) throw new Error('Invalid checksum');
      return entropy;
    }

    async function validateMnemonic(mnemonic) {
      try {
        await mnemonicToEntropy(mnemonic);
        return true;
      } catch { return false; }
    }

    async function generateMnemonic(wordCount = 12) {
      const bits = wordCount === 12 ? 128 : 256;
      const entropy = new Uint8Array(bits / 8);
      crypto.getRandomValues(entropy);
      const mnemonic = await entropyToMnemonic(entropy);
      return { mnemonic, entropy, entropyHex: bytesToHex(entropy) };
    }

    async function mnemonicToSeed(mnemonic, passphrase = '') {
      const mnemonicNormalized = mnemonic.normalize('NFKD');
      const passphraseNormalized = passphrase.normalize('NFKD');
      const salt = 'mnemonic' + passphraseNormalized;
      return await pbkdf2(mnemonicNormalized, salt, 2048, 64, 'SHA-512');
    }

    // ==================== BIP32 ====================

    const HARDENED_OFFSET = 0x80000000;

    class HDNode {
      constructor(privateKey, chainCode, depth = 0, index = 0, parentFingerprint = 0) {
        this.privateKey = privateKey;
        this.chainCode = chainCode;
        this.depth = depth;
        this.index = index;
        this.parentFingerprint = parentFingerprint;
        this._publicKey = null;
        this._fingerprint = null;
      }

      static async fromSeed(seed) {
        if (seed.length !== 64) throw new Error('Seed must be 64 bytes');
        const I = await hmacSHA512(utf8ToBytes('Bitcoin seed'), seed);
        const privateKey = I.slice(0, 32);
        const chainCode = I.slice(32, 64);
        const keyInt = BigInt('0x' + bytesToHex(privateKey));
        if (keyInt === BigInt(0) || keyInt >= SECP256K1_N) throw new Error('Invalid private key');
        return new HDNode(privateKey, chainCode, 0, 0, 0);
      }

      async deriveChild(index) {
        const hardened = index >= HARDENED_OFFSET;
        let data;
        if (hardened) {
          data = new Uint8Array(37);
          data[0] = 0x00;
          data.set(this.privateKey, 1);
          data.set(uint32ToBytes(index), 33);
        } else {
          const publicKey = await this.getPublicKey(true);
          data = new Uint8Array(37);
          data.set(publicKey, 0);
          data.set(uint32ToBytes(index), 33);
        }
        const I = await hmacSHA512(this.chainCode, data);
        const childPrivateKey = addPrivateKeys(I.slice(0, 32), this.privateKey);
        const fingerprint = await this.getFingerprint();
        return new HDNode(childPrivateKey, I.slice(32, 64), this.depth + 1, index, fingerprint);
      }

      async derive(path) {
        if (!path.startsWith('m') && !path.startsWith('M')) throw new Error('Path must start with m');
        const segments = path.split('/').slice(1);
        let node = this;
        for (const segment of segments) {
          if (segment === '') continue;
          const hardened = segment.endsWith("'") || segment.endsWith('h');
          const index = parseInt(segment.replace(/['h]/g, ''), 10);
          if (isNaN(index) || index < 0) throw new Error('Invalid path segment');
          node = await node.deriveChild(hardened ? index + HARDENED_OFFSET : index);
        }
        return node;
      }

      async getPublicKey(compressed = true) {
        if (!this._publicKey) {
          this._publicKey = await privateKeyToPublicKey(this.privateKey, compressed);
        }
        return this._publicKey;
      }

      async getFingerprint() {
        if (this._fingerprint === null) {
          const publicKey = await this.getPublicKey(true);
          const hash = await hash160(publicKey);
          const bytes = hash.slice(0, 4);
          this._fingerprint = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
        }
        return this._fingerprint;
      }
    }

    // ==================== SLIP-0010 Ed25519 ====================

    class Ed25519HDNode {
      constructor(privateKey, chainCode) {
        this.privateKey = privateKey;
        this.chainCode = chainCode;
      }

      static async fromSeed(seed) {
        if (seed.length !== 64) throw new Error('Seed must be 64 bytes');
        const I = await hmacSHA512(utf8ToBytes('ed25519 seed'), seed);
        return new Ed25519HDNode(I.slice(0, 32), I.slice(32, 64));
      }

      async deriveChild(index) {
        const hardenedIndex = index >= HARDENED_OFFSET ? index : index + HARDENED_OFFSET;
        const data = new Uint8Array(37);
        data[0] = 0x00;
        data.set(this.privateKey, 1);
        data.set(uint32ToBytes(hardenedIndex), 33);
        const I = await hmacSHA512(this.chainCode, data);
        return new Ed25519HDNode(I.slice(0, 32), I.slice(32, 64));
      }

      async derive(path) {
        if (!path.startsWith('m')) throw new Error('Path must start with m');
        const segments = path.split('/').slice(1);
        let node = this;
        for (const segment of segments) {
          if (segment === '') continue;
          const index = parseInt(segment.replace(/['h]/g, ''), 10);
          if (isNaN(index) || index < 0) throw new Error('Invalid path segment');
          node = await node.deriveChild(index);
        }
        return node;
      }

      async getPublicKey() {
        return await ed25519GetPublicKey(this.privateKey);
      }
    }

    // ==================== ADDRESS DERIVATION ====================

    const DERIVATION_PATHS = {
      bitcoin: {
        legacy: (account, change, index) => \`m/44'/0'/\${account}'/\${change}/\${index}\`,
        nestedSegwit: (account, change, index) => \`m/49'/0'/\${account}'/\${change}/\${index}\`,
        nativeSegwit: (account, change, index) => \`m/84'/0'/\${account}'/\${change}/\${index}\`,
        taproot: (account, change, index) => \`m/86'/0'/\${account}'/\${change}/\${index}\`,
      },
      ethereum: (account, index) => \`m/44'/60'/\${account}'/0/\${index}\`,
      solana: (account, change) => \`m/44'/501'/\${account}'/\${change}'\`,
      tron: (account, index) => \`m/44'/195'/\${account}'/0/\${index}\`,
    };

    async function generateP2PKH(publicKey) {
      const pubKeyHash = await hash160(publicKey);
      const versionedPayload = new Uint8Array(21);
      versionedPayload[0] = 0x00;
      versionedPayload.set(pubKeyHash, 1);
      const hash1 = await sha256(versionedPayload);
      const hash2 = await sha256(hash1);
      const addressBytes = new Uint8Array(25);
      addressBytes.set(versionedPayload);
      addressBytes.set(hash2.slice(0, 4), 21);
      return base58Encode(addressBytes);
    }

    async function generateP2SH_P2WPKH(publicKey) {
      const pubKeyHash = await hash160(publicKey);
      const redeemScript = new Uint8Array(22);
      redeemScript[0] = 0x00;
      redeemScript[1] = 0x14;
      redeemScript.set(pubKeyHash, 2);
      const scriptHash = await hash160(redeemScript);
      const versionedPayload = new Uint8Array(21);
      versionedPayload[0] = 0x05;
      versionedPayload.set(scriptHash, 1);
      const hash1 = await sha256(versionedPayload);
      const hash2 = await sha256(hash1);
      const addressBytes = new Uint8Array(25);
      addressBytes.set(versionedPayload);
      addressBytes.set(hash2.slice(0, 4), 21);
      return base58Encode(addressBytes);
    }

    async function generateP2WPKH(publicKey) {
      const pubKeyHash = await hash160(publicKey);
      const words = convertBits(pubKeyHash, 8, 5, true);
      const data = new Uint8Array(words.length + 1);
      data[0] = 0x00;
      data.set(words, 1);
      return bech32Encode('bc', Array.from(data), 'bech32');
    }

    async function generateP2TR(publicKey) {
      const xOnlyPubkey = await taprootTweakPublicKey(publicKey);
      const words = convertBits(xOnlyPubkey, 8, 5, true);
      const data = new Uint8Array(words.length + 1);
      data[0] = 0x01;
      data.set(words, 1);
      return bech32Encode('bc', Array.from(data), 'bech32m');
    }

    async function deriveBitcoinAddress(rootNode, type, account = 0, change = 0, index = 0) {
      const pathFn = DERIVATION_PATHS.bitcoin[type === 'nested-segwit' ? 'nestedSegwit' : type === 'native-segwit' ? 'nativeSegwit' : type];
      const path = pathFn(account, change, index);
      const node = await rootNode.derive(path);
      const publicKey = await node.getPublicKey(true);
      let address;
      switch (type) {
        case 'legacy': address = await generateP2PKH(publicKey); break;
        case 'nested-segwit': address = await generateP2SH_P2WPKH(publicKey); break;
        case 'native-segwit': address = await generateP2WPKH(publicKey); break;
        case 'taproot': address = await generateP2TR(publicKey); break;
      }
      const wif = await privateKeyToWIF(node.privateKey, true, false);
      return { address, privateKey: bytesToHex(node.privateKey), privateKeyWIF: wif, publicKey: bytesToHex(publicKey), path, type, account, change, index };
    }

    async function deriveBitcoinAddresses(rootNode, type, account = 0, change = 0, startIndex = 0, count = 5) {
      const addresses = [];
      for (let i = startIndex; i < startIndex + count; i++) {
        addresses.push(await deriveBitcoinAddress(rootNode, type, account, change, i));
      }
      return addresses;
    }

    async function deriveEthereumAddress(rootNode, account = 0, index = 0) {
      const path = DERIVATION_PATHS.ethereum(account, index);
      const node = await rootNode.derive(path);
      const publicKey = await node.getPublicKey(false);
      const pubKeyWithoutPrefix = publicKey.slice(1);
      const hash = await keccak256(pubKeyWithoutPrefix);
      const addressBytes = hash.slice(-20);
      const addr = bytesToHex(addressBytes);
      const hashForChecksum = await keccak256(utf8ToBytes(addr));
      const hashHex = bytesToHex(hashForChecksum);
      let checksummed = '0x';
      for (let i = 0; i < addr.length; i++) {
        checksummed += parseInt(hashHex[i], 16) >= 8 ? addr[i].toUpperCase() : addr[i];
      }
      return { address: checksummed, privateKey: '0x' + bytesToHex(node.privateKey), publicKey: '0x' + bytesToHex(publicKey), path, account, index };
    }

    async function deriveEthereumAddresses(rootNode, account = 0, startIndex = 0, count = 5) {
      const addresses = [];
      for (let i = startIndex; i < startIndex + count; i++) {
        addresses.push(await deriveEthereumAddress(rootNode, account, i));
      }
      return addresses;
    }

    async function deriveSolanaAddress(seed, account = 0, change = 0) {
      const path = DERIVATION_PATHS.solana(account, change);
      const masterNode = await Ed25519HDNode.fromSeed(seed);
      const node = await masterNode.derive(path);
      const publicKey = await node.getPublicKey();
      const address = base58Encode(publicKey);
      const fullPrivateKey = new Uint8Array(64);
      fullPrivateKey.set(node.privateKey, 0);
      fullPrivateKey.set(publicKey, 32);
      return { address, privateKey: base58Encode(fullPrivateKey), publicKey: base58Encode(publicKey), privateKeyHex: bytesToHex(node.privateKey), publicKeyHex: bytesToHex(publicKey), path, account, index: account };
    }

    async function deriveSolanaAddresses(seed, startAccount = 0, count = 5) {
      const addresses = [];
      for (let i = startAccount; i < startAccount + count; i++) {
        addresses.push(await deriveSolanaAddress(seed, i));
      }
      return addresses;
    }

    async function deriveTronAddress(rootNode, account = 0, index = 0) {
      const path = DERIVATION_PATHS.tron(account, index);
      const node = await rootNode.derive(path);
      const publicKey = await node.getPublicKey(false);
      const pubKeyWithoutPrefix = publicKey.slice(1);
      const hash = await keccak256(pubKeyWithoutPrefix);
      const addressBytes = hash.slice(-20);
      const addressWithPrefix = new Uint8Array(21);
      addressWithPrefix[0] = 0x41;
      addressWithPrefix.set(addressBytes, 1);
      const hash1 = await sha256(addressWithPrefix);
      const hash2 = await sha256(hash1);
      const addressWithChecksum = new Uint8Array(25);
      addressWithChecksum.set(addressWithPrefix);
      addressWithChecksum.set(hash2.slice(0, 4), 21);
      return { address: base58Encode(addressWithChecksum), privateKey: '0x' + bytesToHex(node.privateKey), publicKey: '0x' + bytesToHex(publicKey), path, account, index };
    }

    async function deriveTronAddresses(rootNode, account = 0, startIndex = 0, count = 5) {
      const addresses = [];
      for (let i = startIndex; i < startIndex + count; i++) {
        addresses.push(await deriveTronAddress(rootNode, account, i));
      }
      return addresses;
    }

    // ==================== UI ====================

    const state = {
      mnemonic: null,
      passphrase: '',
      seed: null,
      rootNode: null,
      currentChain: 'bitcoin',
      bitcoinAddressType: 'native-segwit',
      addressStart: 0,
      addressBatch: 20,
      addresses: [],
      wordCount: 12
    };

    function showToast(message, type = 'info') {
      let container = document.querySelector('.toast-container');
      if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
      }
      const toast = document.createElement('div');
      toast.className = 'toast ' + type;
      toast.textContent = message;
      container.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
      }, 3000);
    }

    async function copyToClipboard(text) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        return true;
      }
    }

    function renderApp() {
      const app = document.getElementById('app');
      app.innerHTML = \`
        <div class="header">
          <h1>🔐 Mnemonic Generator</h1>
          <p>Secure, offline, multi-chain HD wallet generator</p>
        </div>
        <div class="security-warning">
          <strong>Security Warning:</strong> This tool generates real cryptocurrency private keys.
          Always use in an offline environment. Never share your mnemonic or private keys.
        </div>
        <div class="card">
          <h2 class="card-title">Step 1: Generate or Import Mnemonic</h2>
          <div class="form-group">
            <label class="form-label">Word Count</label>
            <select id="wordCount" class="form-input">
              <option value="12">12 words (128-bit)</option>
              <option value="24">24 words (256-bit)</option>
            </select>
          </div>
          <button id="generateBtn" class="button button-primary">Generate New Mnemonic</button>
          <h3 style="margin-top: 2rem;">Or Import Existing Mnemonic</h3>
          <div class="form-group">
            <label class="form-label">Mnemonic Phrase</label>
            <textarea id="importMnemonic" class="form-input" rows="3" placeholder="Enter your 12 or 24 word mnemonic phrase..."></textarea>
          </div>
          <button id="importBtn" class="button button-secondary">Import Mnemonic</button>
        </div>
        <div id="mnemonicDisplay" style="display: none;"></div>
        <div id="passphraseSection" style="display: none;"></div>
        <div id="chainSection" style="display: none;"></div>
        <div class="footer">Created by L</div>
      \`;

      document.getElementById('generateBtn').addEventListener('click', async () => {
        const wordCount = parseInt(document.getElementById('wordCount').value);
        const result = await generateMnemonic(wordCount);
        state.mnemonic = result.mnemonic;
        state.wordCount = wordCount;
        state.passphrase = '';
        state.addressStart = 0;
        state.addresses = [];
        showToast('Mnemonic generated!', 'success');
        showMnemonicAndContinue();
      });

      document.getElementById('importBtn').addEventListener('click', async () => {
        const mnemonic = document.getElementById('importMnemonic').value.trim();
        if (!mnemonic) { showToast('Please enter a mnemonic', 'error'); return; }
        const isValid = await validateMnemonic(mnemonic);
        if (!isValid) { showToast('Invalid mnemonic phrase', 'error'); return; }
        state.mnemonic = mnemonic;
        state.passphrase = '';
        state.addressStart = 0;
        state.addresses = [];
        showToast('Mnemonic imported!', 'success');
        showMnemonicAndContinue();
      });
    }

    function showMnemonicAndContinue() {
      state.passphrase = '';
      state.addressStart = 0;
      state.addresses = [];
      const words = state.mnemonic.split(' ');
      const mnemonicDisplay = document.getElementById('mnemonicDisplay');
      mnemonicDisplay.style.display = 'block';
      mnemonicDisplay.innerHTML = \`
        <div class="card">
          <h2 class="card-title">Your Mnemonic Phrase</h2>
          <div class="mnemonic-grid">
            \${words.map((word, i) => \`<div class="mnemonic-word"><span class="mnemonic-word-index">\${i + 1}</span><span class="mnemonic-word-text">\${word}</span></div>\`).join('')}
          </div>
          <div style="display: flex; gap: 0.5rem; margin-top: 1rem; flex-wrap: wrap;">
            <button id="regenBtn" class="button button-secondary">Generate New</button>
            <button id="copyMnemonicBtn" class="button button-secondary">📋 Copy Mnemonic</button>
          </div>
        </div>
      \`;

      document.getElementById('regenBtn').addEventListener('click', async () => {
        const result = await generateMnemonic(state.wordCount);
        state.mnemonic = result.mnemonic;
        state.passphrase = '';
        state.addressStart = 0;
        state.addresses = [];
        showMnemonicAndContinue();
      });

      document.getElementById('copyMnemonicBtn').addEventListener('click', () => {
        copyToClipboard(state.mnemonic);
        showToast('Mnemonic copied.', 'success');
      });

      showPassphraseSection();
      showChainSection();
      // Reset address state before deriving
      state.addresses = [];
      state.addressStart = 0;
      deriveAddresses({ reset: true, showToast: true });
    }

    function showPassphraseSection() {
      const section = document.getElementById('passphraseSection');
      section.style.display = 'block';
      section.innerHTML = \`
        <div class="card">
          <h2 class="card-title">Step 2: Optional Passphrase</h2>
          <div class="form-group">
            <label class="form-label">Passphrase (Advanced)</label>
            <div style="display: flex; gap: 0.5rem;">
              <input type="password" id="passphrase" class="form-input" placeholder="Optional passphrase (leave empty for none)">
              <button id="togglePassphrase" class="button button-secondary button-small">Show</button>
            </div>
            <div class="form-hint">Adds extra security but makes recovery harder. Leave empty if unsure.</div>
          </div>
          <button id="applyPassphrase" class="button button-primary">Apply Passphrase</button>
        </div>
      \`;

      document.getElementById('togglePassphrase').addEventListener('click', () => {
        const input = document.getElementById('passphrase');
        const btn = document.getElementById('togglePassphrase');
        if (input.type === 'password') { input.type = 'text'; btn.textContent = 'Hide'; }
        else { input.type = 'password'; btn.textContent = 'Show'; }
      });

      document.getElementById('applyPassphrase').addEventListener('click', () => {
        state.passphrase = document.getElementById('passphrase').value;
        state.addressStart = 0;
        state.addresses = [];
        deriveAddresses({ reset: true, showToast: true });
      });
    }

    function showChainSection() {
      const section = document.getElementById('chainSection');
      section.style.display = 'block';
      section.innerHTML = \`
        <div class="card">
          <h2 class="card-title">Step 3: Derive Addresses</h2>
          <div class="tabs">
            <button class="tab" data-chain="bitcoin">Bitcoin</button>
            <button class="tab" data-chain="ethereum">Ethereum</button>
            <button class="tab" data-chain="solana">Solana</button>
            <button class="tab" data-chain="tron">Tron</button>
          </div>
          <div id="bitcoinTypeSelector" class="form-group" style="margin-top: 1rem;">
            <label class="form-label">Address Type</label>
            <select id="btcAddressType" class="form-input">
              <option value="legacy">Legacy (P2PKH)</option>
              <option value="nested-segwit">Nested SegWit (P2SH)</option>
              <option value="native-segwit" selected>Native SegWit (P2WPKH)</option>
              <option value="taproot">Taproot (P2TR)</option>
            </select>
          </div>
          <div id="addressContainer"></div>
        </div>
      \`;

      document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
          tab.classList.add('active');
          state.currentChain = tab.dataset.chain;
          state.addressStart = 0;
          state.addresses = [];
          document.getElementById('bitcoinTypeSelector').style.display = state.currentChain === 'bitcoin' ? 'block' : 'none';
          deriveAddresses({ reset: true, showToast: true });
        });
      });

      const activeChain = state.currentChain || 'bitcoin';
      const activeTab = document.querySelector(\`.tab[data-chain="\${activeChain}"]\`);
      if (activeTab) {
        activeTab.classList.add('active');
      }
      document.getElementById('bitcoinTypeSelector').style.display = activeChain === 'bitcoin' ? 'block' : 'none';

      document.getElementById('btcAddressType').addEventListener('change', (e) => {
        state.bitcoinAddressType = e.target.value;
        state.addressStart = 0;
        state.addresses = [];
        deriveAddresses({ reset: true, showToast: true });
      });
    }

    async function deriveAddresses(options = {}) {
      const opts = (options && options.type && options.target) ? {} : options;
      const { reset = false, showToast: showSuccessToast = false } = opts || {};
      if (!state.mnemonic) return;
      const container = document.getElementById('addressContainer');
      container.innerHTML = '<div class="loading"><div class="spinner"></div><div>Generating...</div></div>';

      try {
        if (reset) {
          state.addressStart = 0;
          state.addresses = [];
        }
        state.seed = await mnemonicToSeed(state.mnemonic, state.passphrase);
        state.rootNode = await HDNode.fromSeed(state.seed);

        let newAddresses;
        switch (state.currentChain) {
          case 'bitcoin':
            newAddresses = await deriveBitcoinAddresses(state.rootNode, state.bitcoinAddressType, 0, 0, state.addressStart, state.addressBatch);
            break;
          case 'ethereum':
            newAddresses = await deriveEthereumAddresses(state.rootNode, 0, state.addressStart, state.addressBatch);
            break;
          case 'solana':
            newAddresses = await deriveSolanaAddresses(state.seed, state.addressStart, state.addressBatch);
            break;
          case 'tron':
            newAddresses = await deriveTronAddresses(state.rootNode, 0, state.addressStart, state.addressBatch);
            break;
        }

        state.addresses = state.addresses.concat(newAddresses);
        state.addressStart += state.addressBatch;
        renderAddresses(container);
        if (showSuccessToast) {
          showToast('Addresses refreshed successfully.', 'success');
        }
      } catch (e) {
        container.innerHTML = '<p style="color: var(--accent-danger);">Error: ' + e.message + '</p>';
        console.error(e);
      }
    }

    function renderAddresses(container) {
      container.innerHTML = \`
        <table class="address-table">
          <thead>
            <tr><th>#</th><th>Address</th><th>Path</th><th>Private Key</th><th>Actions</th></tr>
          </thead>
          <tbody>
            \${state.addresses.map((addr, i) => \`
              <tr>
                <td data-label="#">#\${addr.index ?? addr.account ?? i}</td>
                <td data-label="Address" class="address-value-cell">
                  <div class="address-key-value" style="cursor:pointer" onclick="copyAddr('\${addr.address}')">\${addr.address}</div>
                </td>
                <td data-label="Path">\${addr.path}</td>
                <td data-label="Private Key" class="address-value-cell">
                  <div class="address-key-value masked" onclick="this.classList.toggle('masked'); copyPrivateKey('\${(addr.privateKeyWIF || addr.privateKey).replace(/'/g, "\\\\'")}');">\${addr.privateKeyWIF || addr.privateKey}</div>
                </td>
                <td data-label="Actions">
                  <button class="button button-small button-secondary" onclick="copyAddr('\${addr.address}')">Copy Addr</button>
                  <button class="button button-small button-secondary" onclick="copyPrivateKey('\${(addr.privateKeyWIF || addr.privateKey).replace(/'/g, "\\\\'")}')">Copy Key</button>
                </td>
              </tr>
            \`).join('')}
          </tbody>
        </table>
        <button id="loadMoreBtn" class="button button-secondary" style="width: 100%; margin-top: 1rem;">Load More Addresses</button>
      \`;

      document.getElementById('loadMoreBtn').addEventListener('click', deriveAddresses);
    }

    window.copyAddr = function(text) {
      copyToClipboard(text);
      showToast('Address copied!', 'success');
    };

    window.copyPrivateKey = function(text) {
      copyToClipboard(text);
      showToast('Private key copied.', 'success');
    };

    // Initialize
    loadWordlist(window.EMBEDDED_WORDLIST);
    renderApp();
  </script>
</body>
</html>`;

fs.writeFileSync(OUTPUT_FILE, html, "utf8");
console.log("Built:", OUTPUT_FILE);
console.log(
  "File size:",
  (fs.statSync(OUTPUT_FILE).size / 1024).toFixed(2),
  "KB",
);
