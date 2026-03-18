/**
 * Test Vectors for Address Derivation Verification
 *
 * Run in browser console after loading the app:
 *   import('./test-vectors.js').then(m => m.runTests())
 *
 * Or include via script tag and call runTests()
 */

import { loadWordlist, entropyToMnemonic, validateMnemonic } from './core/bip39.js';
import { mnemonicToSeed } from './core/seed.js';
import { HDNode } from './core/bip32.js';
import { deriveBitcoinAddress } from './chains/bitcoin.js';
import { deriveEthereumAddress } from './chains/ethereum.js';
import { deriveSolanaAddressFromSeed } from './chains/solana.js';
import { deriveTronAddress } from './chains/tron.js';
import { bytesToHex, hexToBytes } from './utils/encoding.js';

/**
 * BIP39 Test Vectors
 * Source: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
 */
const BIP39_VECTORS = [
  {
    entropy: '00000000000000000000000000000000',
    mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    seed: '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
    passphrase: 'TREZOR'
  },
  {
    entropy: '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f',
    mnemonic: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
    seed: '2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607',
    passphrase: 'TREZOR'
  }
];

/**
 * Bitcoin Address Test Vectors
 * Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
 * Passphrase: (empty)
 *
 * Verified with: https://iancoleman.io/bip39/
 */
const BITCOIN_VECTORS = {
  mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  passphrase: '',

  // BIP44 Legacy (m/44'/0'/0'/0/0)
  legacy: {
    path: "m/44'/0'/0'/0/0",
    address: '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA',
    privateKeyWIF: 'L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D'
  },

  // BIP49 Nested SegWit (m/49'/0'/0'/0/0)
  nestedSegwit: {
    path: "m/49'/0'/0'/0/0",
    address: '37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf',
    privateKeyWIF: 'KyvHbRLNXfXxkhPV3nqH9vrS5L7nP8bLY1PACpQKoPdSMhH4zNrq'
  },

  // BIP84 Native SegWit (m/84'/0'/0'/0/0)
  nativeSegwit: {
    path: "m/84'/0'/0'/0/0",
    address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
    privateKeyWIF: 'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d'
  },

  // BIP86 Taproot (m/86'/0'/0'/0/0)
  taproot: {
    path: "m/86'/0'/0'/0/0",
    address: 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
    privateKeyWIF: 'KysPMJTeTL3LpQ15677XQj1uuxugFBQ2JBmjLMxQFqWUWMLTBaTN'
  }
};

/**
 * Ethereum Test Vector
 * Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
 * Passphrase: (empty)
 * Path: m/44'/60'/0'/0/0
 */
const ETHEREUM_VECTOR = {
  mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  passphrase: '',
  path: "m/44'/60'/0'/0/0",
  address: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94',
  privateKey: '0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727'
};

/**
 * Solana Test Vector
 * Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
 * Passphrase: (empty)
 * Path: m/44'/501'/0'/0' (SLIP-0010 Ed25519)
 *
 * Note: This should match Phantom wallet derivation
 */
const SOLANA_VECTOR = {
  mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  passphrase: '',
  path: "m/44'/501'/0'/0'",
  // Phantom/Solflare compatible address
  address: 'XXXXXXXXXXXXXXXX' // Will be verified against actual Phantom output
};

/**
 * Tron Test Vector
 * Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
 * Passphrase: (empty)
 * Path: m/44'/195'/0'/0/0
 */
const TRON_VECTOR = {
  mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  passphrase: '',
  path: "m/44'/195'/0'/0/0",
  address: 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH'
};

let testResults = [];

function log(message, isError = false) {
  const prefix = isError ? '❌' : '✅';
  console.log(`${prefix} ${message}`);
  testResults.push({ message, isError });
}

function assertEqual(actual, expected, description) {
  if (actual === expected) {
    log(`${description}: PASS`);
    return true;
  } else {
    log(`${description}: FAIL\n   Expected: ${expected}\n   Actual:   ${actual}`, true);
    return false;
  }
}

/**
 * Run all test vectors
 */
export async function runTests() {
  testResults = [];
  console.log('\n========================================');
  console.log('Address Derivation Test Vectors');
  console.log('========================================\n');

  try {
    // Load wordlist first
    const response = await fetch('./wordlist_english.txt');
    const wordlistText = await response.text();
    loadWordlist(wordlistText);
    log('Wordlist loaded');

    // Test BIP39
    console.log('\n--- BIP39 Tests ---');
    await testBIP39();

    // Test Bitcoin addresses
    console.log('\n--- Bitcoin Tests ---');
    await testBitcoin();

    // Test Ethereum
    console.log('\n--- Ethereum Tests ---');
    await testEthereum();

    // Test Solana
    console.log('\n--- Solana Tests ---');
    await testSolana();

    // Test Tron
    console.log('\n--- Tron Tests ---');
    await testTron();

    // Summary
    console.log('\n========================================');
    const passed = testResults.filter(r => !r.isError).length;
    const failed = testResults.filter(r => r.isError).length;
    console.log(`Summary: ${passed} passed, ${failed} failed`);
    console.log('========================================\n');

    return { passed, failed, results: testResults };
  } catch (e) {
    console.error('Test execution failed:', e);
    throw e;
  }
}

async function testBIP39() {
  for (const vector of BIP39_VECTORS) {
    // Test entropy to mnemonic
    const entropy = hexToBytes(vector.entropy);
    const mnemonic = await entropyToMnemonic(entropy);
    assertEqual(mnemonic, vector.mnemonic, 'Entropy to mnemonic');

    // Test mnemonic validation
    const isValid = await validateMnemonic(vector.mnemonic);
    assertEqual(isValid, true, 'Mnemonic validation');

    // Test seed generation with passphrase
    const seed = await mnemonicToSeed(vector.mnemonic, vector.passphrase);
    const seedHex = bytesToHex(seed);
    assertEqual(seedHex, vector.seed, `Seed with passphrase "${vector.passphrase}"`);
  }
}

async function testBitcoin() {
  const { mnemonic, passphrase } = BITCOIN_VECTORS;

  // Generate seed and root node
  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const rootNode = await HDNode.fromSeed(seed);

  // Test Legacy (P2PKH)
  const legacy = await deriveBitcoinAddress(rootNode, 'legacy', 0, 0, 0);
  assertEqual(legacy.address, BITCOIN_VECTORS.legacy.address, 'Bitcoin Legacy address');
  assertEqual(legacy.path, BITCOIN_VECTORS.legacy.path, 'Bitcoin Legacy path');

  // Test Nested SegWit (P2SH-P2WPKH)
  const nestedSegwit = await deriveBitcoinAddress(rootNode, 'nested-segwit', 0, 0, 0);
  assertEqual(nestedSegwit.address, BITCOIN_VECTORS.nestedSegwit.address, 'Bitcoin Nested SegWit address');

  // Test Native SegWit (P2WPKH)
  const nativeSegwit = await deriveBitcoinAddress(rootNode, 'native-segwit', 0, 0, 0);
  assertEqual(nativeSegwit.address, BITCOIN_VECTORS.nativeSegwit.address, 'Bitcoin Native SegWit address');

  // Test Taproot (P2TR)
  const taproot = await deriveBitcoinAddress(rootNode, 'taproot', 0, 0, 0);
  assertEqual(taproot.address, BITCOIN_VECTORS.taproot.address, 'Bitcoin Taproot address');

  // Log actual values for debugging
  console.log('  Actual addresses:');
  console.log('    Legacy:', legacy.address);
  console.log('    Nested SegWit:', nestedSegwit.address);
  console.log('    Native SegWit:', nativeSegwit.address);
  console.log('    Taproot:', taproot.address);
}

async function testEthereum() {
  const { mnemonic, passphrase, address, privateKey } = ETHEREUM_VECTOR;

  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const rootNode = await HDNode.fromSeed(seed);

  const eth = await deriveEthereumAddress(rootNode, 0, 0);
  assertEqual(eth.address.toLowerCase(), address.toLowerCase(), 'Ethereum address');

  console.log('  Actual Ethereum address:', eth.address);
}

async function testSolana() {
  const { mnemonic, passphrase } = SOLANA_VECTOR;

  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const sol = await deriveSolanaAddressFromSeed(seed, 0, 0);

  // Log for manual verification with Phantom
  console.log('  Solana address (verify with Phantom):');
  console.log('    Address:', sol.address);
  console.log('    Path:', sol.path);

  // Basic validation
  if (sol.address && sol.address.length >= 32 && sol.address.length <= 44) {
    log('Solana address format valid');
  } else {
    log('Solana address format invalid', true);
  }
}

async function testTron() {
  const { mnemonic, passphrase, address } = TRON_VECTOR;

  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const rootNode = await HDNode.fromSeed(seed);

  const tron = await deriveTronAddress(rootNode, 0, 0);
  assertEqual(tron.address, address, 'Tron address');

  console.log('  Actual Tron address:', tron.address);
}

// Auto-run if loaded directly
if (typeof window !== 'undefined') {
  window.runAddressTests = runTests;
  console.log('Test vectors loaded. Run window.runAddressTests() to execute tests.');
}
