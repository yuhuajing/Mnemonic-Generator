/**
 * Debug script for Taproot address derivation
 * Run with: node --experimental-modules debug-taproot.js
 */

const TEST_MNEMONIC = 'now now now now now now now now now now now before';
const EXPECTED_TAPROOT = 'bc1p66849ux3rzvcxyv3hudgnmueyhr4dn4gws3vd0mqnk8qap5ryxxsexmywe';

// Dynamic import for ES modules
async function main() {
  console.log('Loading dependencies from CDN...');

  // Load noble libraries
  const secp = await import('https://esm.sh/@noble/secp256k1@2.0.0');
  const { sha256 } = await import('https://esm.sh/@noble/hashes@1.3.3/sha256');
  const { sha512 } = await import('https://esm.sh/@noble/hashes@1.3.3/sha512');
  const { pbkdf2 } = await import('https://esm.sh/@noble/hashes@1.3.3/pbkdf2');
  const { hmac } = await import('https://esm.sh/@noble/hashes@1.3.3/hmac');
  const { ripemd160 } = await import('https://esm.sh/@noble/hashes@1.3.3/ripemd160');

  console.log('secp256k1 exports:', Object.keys(secp));
  console.log('Has ProjectivePoint:', !!secp.ProjectivePoint);
  console.log('Has Point:', !!secp.Point);

  // Helper functions
  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function utf8ToBytes(str) {
    return new TextEncoder().encode(str);
  }

  // HMAC-SHA512
  function hmacSHA512(key, data) {
    return hmac(sha512, key, data);
  }

  // Mnemonic to seed
  function mnemonicToSeed(mnemonic, passphrase = '') {
    const salt = 'mnemonic' + passphrase;
    return pbkdf2(sha512, utf8ToBytes(mnemonic), utf8ToBytes(salt), { c: 2048, dkLen: 64 });
  }

  // BIP32 derivation
  const HARDENED_OFFSET = 0x80000000;

  function uint32ToBytes(num) {
    const bytes = new Uint8Array(4);
    bytes[0] = (num >> 24) & 0xff;
    bytes[1] = (num >> 16) & 0xff;
    bytes[2] = (num >> 8) & 0xff;
    bytes[3] = num & 0xff;
    return bytes;
  }

  const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

  function addPrivateKeys(key1, key2) {
    const k1 = BigInt('0x' + bytesToHex(key1));
    const k2 = BigInt('0x' + bytesToHex(key2));
    const sum = (k1 + k2) % SECP256K1_N;
    return hexToBytes(sum.toString(16).padStart(64, '0'));
  }

  class HDNode {
    constructor(privateKey, chainCode) {
      this.privateKey = privateKey;
      this.chainCode = chainCode;
    }

    static fromSeed(seed) {
      const I = hmacSHA512(utf8ToBytes('Bitcoin seed'), seed);
      return new HDNode(I.slice(0, 32), I.slice(32, 64));
    }

    getPublicKey() {
      return secp.getPublicKey(this.privateKey, true);
    }

    deriveChild(index) {
      const hardened = index >= HARDENED_OFFSET;
      let data;
      if (hardened) {
        data = new Uint8Array(37);
        data[0] = 0x00;
        data.set(this.privateKey, 1);
        data.set(uint32ToBytes(index), 33);
      } else {
        const publicKey = this.getPublicKey();
        data = new Uint8Array(37);
        data.set(publicKey, 0);
        data.set(uint32ToBytes(index), 33);
      }
      const I = hmacSHA512(this.chainCode, data);
      const childPrivateKey = addPrivateKeys(I.slice(0, 32), this.privateKey);
      return new HDNode(childPrivateKey, I.slice(32, 64));
    }

    derive(path) {
      const segments = path.split('/').slice(1);
      let node = this;
      for (const segment of segments) {
        const hardened = segment.endsWith("'") || segment.endsWith('h');
        const index = parseInt(segment.replace(/['h]/g, ''), 10);
        node = node.deriveChild(hardened ? index + HARDENED_OFFSET : index);
      }
      return node;
    }
  }

  // Tagged hash
  function taggedHash(tag, msg) {
    const tagHash = sha256(utf8ToBytes(tag));
    const combined = new Uint8Array(tagHash.length * 2 + msg.length);
    combined.set(tagHash, 0);
    combined.set(tagHash, tagHash.length);
    combined.set(msg, tagHash.length * 2);
    return sha256(combined);
  }

  // Bech32m encoding
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

  function bech32Encode(hrp, data, encoding) {
    const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    const constant = encoding === 'bech32m' ? 0x2bc830a3 : 1;
    const polymod = bech32Polymod(values) ^ constant;
    const checksum = [];
    for (let i = 0; i < 6; i++) checksum.push((polymod >> 5 * (5 - i)) & 31);
    return hrp + '1' + data.concat(checksum).map(d => BECH32_CHARSET[d]).join('');
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
    return result;
  }

  // Run test
  console.log('\n=== Taproot Derivation Debug ===\n');
  console.log('Mnemonic:', TEST_MNEMONIC);
  console.log('Expected:', EXPECTED_TAPROOT);

  // Step 1: Mnemonic to seed
  const seed = mnemonicToSeed(TEST_MNEMONIC, '');
  console.log('\n1. Seed:', bytesToHex(seed));

  // Step 2: Derive path m/86'/0'/0'/0/0
  const rootNode = HDNode.fromSeed(seed);
  console.log('2. Root private key:', bytesToHex(rootNode.privateKey));
  console.log('   Root chain code:', bytesToHex(rootNode.chainCode));

  const taprootNode = rootNode.derive("m/86'/0'/0'/0/0");
  console.log('3. Derived private key:', bytesToHex(taprootNode.privateKey));

  // Step 3: Get public key
  const publicKey = taprootNode.getPublicKey();
  console.log('4. Public key:', bytesToHex(publicKey));
  console.log('   Prefix:', publicKey[0].toString(16));
  console.log('   Has even Y:', publicKey[0] === 0x02);

  // Step 4: Get x-only pubkey
  const xOnlyPubkey = publicKey.slice(1);
  console.log('5. X-only pubkey:', bytesToHex(xOnlyPubkey));

  // Step 5: Compute tweak
  const tweak = taggedHash('TapTweak', xOnlyPubkey);
  console.log('6. Tweak:', bytesToHex(tweak));

  // Step 6: Compute tweaked public key
  const PointClass = secp.ProjectivePoint || secp.Point;
  console.log('7. Using PointClass:', PointClass ? 'available' : 'not available');

  // Use the correct point (with even y if original has odd y)
  let workingPubkey = publicKey;
  if (publicKey[0] !== 0x02) {
    workingPubkey = new Uint8Array(33);
    workingPubkey[0] = 0x02;
    workingPubkey.set(xOnlyPubkey, 1);
    console.log('   Negated to even Y');
  }

  const tweakBigInt = BigInt('0x' + bytesToHex(tweak));
  console.log('8. Tweak as BigInt:', tweakBigInt.toString(16));

  const P = PointClass.fromHex(bytesToHex(workingPubkey));
  console.log('9. Point P loaded');

  const tweakPoint = PointClass.BASE.multiply(tweakBigInt);
  console.log('10. Tweak point calculated');

  const Q = P.add(tweakPoint);
  console.log('11. Output point Q calculated');

  const tweakedPubkey = Q.toRawBytes(true);
  console.log('12. Tweaked pubkey (compressed):', bytesToHex(tweakedPubkey));

  const tweakedX = tweakedPubkey.slice(1);
  console.log('13. Tweaked X-only:', bytesToHex(tweakedX));

  // Step 7: Encode as bech32m
  const words = convertBits(Array.from(tweakedX), 8, 5, true);
  const data = [0x01].concat(words); // witness version 1
  const address = bech32Encode('bc', data, 'bech32m');
  console.log('\n14. Generated address:', address);
  console.log('    Expected address: ', EXPECTED_TAPROOT);
  console.log('    Match:', address === EXPECTED_TAPROOT);
}

main().catch(console.error);
