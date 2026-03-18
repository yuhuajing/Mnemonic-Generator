# Mnemonic Generator

A secure, offline, multi-chain HD wallet mnemonic generator with a vault-style UI.

## Quick Start

**Option 1: Single-file version (recommended)**
```bash
# Open the pre-built standalone file
open mnemonic-generator.html
```

**Option 2: Development mode**
```bash
# Open the modular source version
open src/index.html
```

Both versions work completely offline with no network requests.

## Features

- **Multi-Chain Support**: Bitcoin (4 types), Ethereum, Solana, Tron
- **BIP39/32/44/84/86 Compliant**: Industry-standard HD wallet derivation
- **Secure**: Web Crypto API, no network requests, fully offline
- **Unique UI**: Vault-style design with gold accents and terminal aesthetics
- **Batch Generation**: Default 50 addresses per chain, load more as needed
- **Mobile Friendly**: Responsive design, works on all devices

## Supported Chains & Address Types

| Chain | Address Types | Derivation Path |
|-------|--------------|-----------------|
| **Bitcoin** | Taproot (P2TR) | m/86'/0'/0'/0/n |
| | Native SegWit (P2WPKH) | m/84'/0'/0'/0/n |
| | Nested SegWit (P2SH-P2WPKH) | m/49'/0'/0'/0/n |
| | Legacy (P2PKH) | m/44'/0'/0'/0/n |
| **Ethereum** | EIP-55 Checksum | m/44'/60'/0'/0/n |
| **Solana** | Ed25519 | m/44'/501'/n'/0' |
| **Tron** | Base58Check | m/44'/195'/0'/0/n |

## Mnemonic Options

- 12-word or 24-word phrases
- Optional BIP39 passphrase (25th word)
- Cryptographically secure random generation

## Usage

1. **Generate/Import Mnemonic**
   - Click "Generate New Mnemonic" or import existing
   - Write down your mnemonic securely (paper, not digital!)

2. **Optional Passphrase**
   - Add extra security layer (optional)
   - Leave empty if unsure

3. **View Addresses**
   - Automatically shows Bitcoin Taproot addresses (50 by default)
   - Switch chains via tabs
   - Click "Load More" for additional addresses

4. **Copy & Use**
   - Click addresses to copy
   - Click private keys to reveal/copy
   - Import into your preferred wallet

## Security

### Randomness Security

This project uses **`crypto.getRandomValues()`** - the browser's native Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).

**Key Security Features:**
- OS-level entropy: Windows BCryptGenRandom, macOS/Linux /dev/random
- Industry standard: Same as MetaMask, MyEtherWallet, Trust Wallet
- Sufficient entropy: 128-bit (12 words) = 2^128 possibilities
- NIST compliant: Follows NIST SP 800-90A standards
- Audited implementations: BoringSSL (Chrome), NSS (Firefox), CommonCrypto (Safari)

**Security Level:**
- Brute-forcing 128-bit entropy requires: 10^38 years
- Brute-forcing 256-bit entropy requires: 10^77 years

See [SECURITY_RANDOMNESS.md](SECURITY_RANDOMNESS.md) for detailed analysis.

### Best Practices

- Use offline/air-gapped computer
- Write mnemonic on paper, never digitally
- Verify addresses with external tools
- Test with small amounts first
- Never share mnemonic or private keys
- Never use on public/shared computers

### Verification

Compare results with:
- [Ian Coleman's BIP39 Tool](https://iancoleman.io/bip39/)
- Python `mnemonic` library
- Hardware wallets (Ledger, Trezor)

**Test Vector (for verification):**
```
Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
Bitcoin (Native SegWit): bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
Ethereum: 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

## Project Structure

```
mnemonicgenerator/
├── mnemonic-generator.html     # Standalone single-file version (built)
├── build.js                    # Build script for single-file output
├── SECURITY_RANDOMNESS.md      # Detailed security analysis
├── CLAUDE.md                   # Development guidance
└── src/
    ├── index.html              # Entry point (dev mode)
    ├── wordlist_english.txt    # BIP39 English wordlist (2048 words)
    ├── test-vectors.js         # Test vectors for verification
    ├── core/                   # Cryptographic core
    │   ├── entropy.js          # Random number generation
    │   ├── bip39.js            # Mnemonic generation & validation
    │   ├── seed.js             # PBKDF2 seed derivation
    │   └── bip32.js            # HD key derivation (HDNode class)
    ├── chains/                 # Chain implementations
    │   ├── bitcoin.js          # Bitcoin (4 address types)
    │   ├── ethereum.js         # Ethereum (EIP-55)
    │   ├── solana.js           # Solana (Ed25519)
    │   └── tron.js             # Tron (Base58Check)
    ├── utils/                  # Utility functions
    │   ├── crypto.js           # Crypto primitives (SHA256, PBKDF2)
    │   ├── encoding.js         # Format conversions (Hex, Base58, Bech32)
    │   ├── validation.js       # Input validation
    │   └── secure.js           # Secure memory handling
    ├── ui/                     # User interface
    │   ├── app.js              # Main application (state, entry point)
    │   ├── components.js       # UI components
    │   └── styles.css          # Vault theme styles
    └── vendor/                 # Local cryptographic libraries
        ├── secp256k1.js        # Bitcoin/Ethereum elliptic curves
        ├── ed25519.js          # Solana Ed25519
        ├── sha512.js           # SHA-512 hash
        ├── sha3.js             # Keccak-256 (Ethereum)
        ├── ripemd160.js        # RIPEMD-160 (Bitcoin)
        └── README.md           # Vendor bundling instructions
```

## Building

The single-file version bundles all code into one HTML file:

```bash
node build.js
# Output: mnemonic-generator.html
```

This creates a completely standalone file with:
- All JavaScript inlined
- All CSS inlined
- Wordlist embedded
- No external dependencies

## Technical Details

### Dependencies

Uses audited cryptographic libraries (bundled locally in `src/vendor/`):
- `@noble/secp256k1` v2.0.0 - Bitcoin/Ethereum signatures
- `@noble/ed25519` v2.0.0 - Solana signatures
- `@noble/hashes` v1.3.3 - SHA-512, RIPEMD-160, Keccak-256

### Browser Requirements

- Chrome 60+
- Firefox 60+
- Safari 11+
- Edge 79+

Requires Web Crypto API support.

### Core Flow

1. Entropy generation -> `crypto.getRandomValues()`
2. BIP39 encoding -> Map to word list (12 or 24 words)
3. Seed derivation -> PBKDF2-HMAC-SHA512 (2048 iterations)
4. HD key derivation -> BIP32 from seed
5. Chain-specific derivation -> BIP44 paths per chain
6. Address encoding -> Chain-specific formats

## Verification Example

### Using Python

```python
from mnemonic import Mnemonic

mnemo = Mnemonic("english")
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Validate
print("Valid:", mnemo.check(mnemonic))

# Generate seed
seed = mnemo.to_seed(mnemonic, "")
print("Seed:", seed.hex())

# Expected: c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
```

## UI Design

**Vault Theme Features:**
- Gold (#d4af37) + Pure Black (#0a0a0a) color scheme
- Monospace fonts for technical content
- Animated grid background
- Scanline effects (CRT screen aesthetic)
- Glow effects on hover
- Professional crypto tool appearance

## Disclaimer

This software is provided "as is" without warranty. Users are responsible for:
- Verifying correctness of generated keys
- Securing their mnemonic phrases
- Understanding cryptocurrency security
- Any financial losses

**Always test with small amounts first!**

## License

MIT License - Use at your own risk.

---

Created by L
# Mnemonic-Generator
