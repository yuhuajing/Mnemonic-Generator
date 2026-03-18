# Vendor Dependencies

This directory contains wrapper modules for cryptographic dependencies.

## Security Notice

For maximum security in production/offline use, you should replace these wrapper files with the actual bundled libraries.

## How to Bundle Dependencies Locally

### Option 1: Using npm and a bundler

```bash
# Install dependencies
npm install @noble/secp256k1@2.0.0 @noble/ed25519@2.0.0 @noble/hashes@1.3.3

# Bundle each module (using esbuild as example)
npx esbuild node_modules/@noble/secp256k1/index.js --bundle --format=esm --outfile=src/vendor/secp256k1.js
npx esbuild node_modules/@noble/ed25519/index.js --bundle --format=esm --outfile=src/vendor/ed25519.js
npx esbuild node_modules/@noble/hashes/sha512.js --bundle --format=esm --outfile=src/vendor/sha512.js
npx esbuild node_modules/@noble/hashes/sha3.js --bundle --format=esm --outfile=src/vendor/sha3.js
npx esbuild node_modules/@noble/hashes/ripemd160.js --bundle --format=esm --outfile=src/vendor/ripemd160.js
```

### Option 2: Using esm.sh pre-built bundles

Download pre-built bundles directly:

```bash
curl -o src/vendor/secp256k1.js "https://esm.sh/@noble/secp256k1@2.0.0?bundle"
curl -o src/vendor/ed25519.js "https://esm.sh/@noble/ed25519@2.0.0?bundle"
curl -o src/vendor/sha512.js "https://esm.sh/@noble/hashes@1.3.3/sha512?bundle"
curl -o src/vendor/sha3.js "https://esm.sh/@noble/hashes@1.3.3/sha3?bundle"
curl -o src/vendor/ripemd160.js "https://esm.sh/@noble/hashes@1.3.3/ripemd160?bundle"
```

## Verifying Integrity

After downloading, verify the integrity of each package:

```bash
# Get official integrity hashes from npm
npm view @noble/secp256k1@2.0.0 dist.integrity
npm view @noble/ed25519@2.0.0 dist.integrity
npm view @noble/hashes@1.3.3 dist.integrity
```

## Current Wrapper Behavior

The current wrapper files will:
1. First check for globally pre-loaded libraries (`window.secp256k1Lib`, etc.)
2. Fall back to loading from CDN (esm.sh) with version lock
3. Throw an error if both fail

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| @noble/secp256k1 | 2.0.0 | Bitcoin/Ethereum elliptic curve operations |
| @noble/ed25519 | 2.0.0 | Solana Ed25519 signatures |
| @noble/hashes | 1.3.3 | SHA-512, Keccak-256, RIPEMD-160 |
