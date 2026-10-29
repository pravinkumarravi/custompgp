# CustomPGP: Pure TypeScript & Browser-Compatible OpenPGP Cryptography

CustomPGP is a **100% pure TypeScript** OpenPGP implementation built from first cryptographic principles.

### Key Highlights
* **Zero 3rd-party packages** (no external npm dependencies).
* **Zero Node.js core modules** in [`custompgp.ts`](file:///d:/js/openpgp/custompgp.ts) (no `node:crypto`, `node:fs`, `node:path`).
* **Universal Browser & Server Runtime**: Fully runs in modern **Web Browsers**, Node.js, Deno, Bun, Cloudflare Workers, and Web Workers.
* **Standard-Compliant**: Complies with **RFC 4880**, **RFC 6637**, and **RFC 9580**.

---

## 1. Built-in Pure Cryptographic Primitives

[`custompgp.ts`](file:///d:/js/openpgp/custompgp.ts) includes hand-crafted, standards-compliant implementations using standard JavaScript `Uint8Array`, `BigInt`, and `DataView`:

1. **SHA-1 Engine (FIPS PUB 180-1 / RFC 3174)**:
   * Pure bitwise 160-bit SHA-1 hash function (`Crypto.sha1`).
   * Computes OpenPGP v4 Key Fingerprints and verifies S2K Usage 254 integrity checksums.
2. **SHA-256 Engine (FIPS PUB 180-4)**:
   * Pure bitwise 256-bit SHA-256 hash function (`Crypto.sha256`).
   * Used for RFC 6637 KDF and String-to-Key (S2K) iterated stretching.
3. **AES-128 & AES-256 Block Cipher (FIPS PUB 197 / Rijndael)**:
   * Full round key schedule (`Crypto.aesKeyExpansion`) and state matrix transformations (`Crypto.aesEncryptBlock`) and inverse transformations.
4. **Curve25519 / X25519 Montgomery Ladder (RFC 7748)**:
   * Elliptic curve scalar multiplication (`Crypto.x25519ScalarMult`) over finite field $2^{255} - 19$.
   * Derives ECDH shared secrets between sender and recipient without WebCrypto subtle key limits.
5. **NIST SP 800-38F / RFC 3394 AES Key Wrap**:
   * Pure 6-round key wrapping and unwrapping algorithm for symmetric session key protection (`CryptoEngine.aesKeyWrap`).
6. **OpenPGP CFB Mode (RFC 4880 §13.9)**:
   * Full 2-octet resynchronization feedback register cipher (`CryptoEngine.openpgpCfbEncrypt`).
7. **Cross-Platform Randomness**:
   * Uses `Crypto.getRandomBytes` backed by standard `globalThis.crypto.getRandomValues`.

---

## 2. Using CustomPGP in Web Browsers or Frontend Frameworks

In your frontend application (React, Vue, Angular, Svelte, or vanilla JS/TS):

```typescript
import { CustomPGP } from './custompgp';

// 1. Encrypt a message in the browser
const armoredPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----...-----END PGP PUBLIC KEY BLOCK-----`;
const encryptedMessage = CustomPGP.encrypt(armoredPublicKey, 'Hello from the Web Browser!');

// 2. Decrypt a message in the browser
const armoredPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----...-----END PGP PRIVATE KEY BLOCK-----`;
const decryptedText = CustomPGP.decrypt(encryptedMessage, armoredPrivateKey, 'Test@123');
console.log(decryptedText); // => "Hello from the Web Browser!"

// 3. Generate a fresh key pair directly in the browser
const keyPair = CustomPGP.generateKeyPair('User <user@example.com>', 'BrowserPass@2026');
console.log(keyPair.publicKeyArmored);
console.log(keyPair.privateKeyArmored);
```

---

## 3. Running the Verification Suite

Run the full end-to-end test suite via:

```powershell
npm run example
```

### Verified Test Output
* **PART 1**: Reads and parses `example_key/public_key.pub` and `example_key/private_key.key`.
* **PART 2 & 3**: Encrypts with public key and decrypts with private key using passphrase **`Test@123`** (`PASSED 100% Match ✅`).
* **PART 4 & 5**: Generates a brand-new OpenPGP key pair (`Ed25519` + `X25519`) from scratch and performs end-to-end encryption/decryption (`PASSED 100% Match ✅`).
