# CustomPGP: How PGP Works

A modern, browser-compatible TypeScript implementation of OpenPGP (RFC 4880, RFC 6637, RFC 9580) built with **zero external dependencies** and **zero Node.js core modules**.

> Inspired by Phil Zimmermann's foundational treatise on cryptography (*"How PGP Works"*, Network Associates / CMU course reference [Adrian Perrig, 18-630](https://users.ece.cmu.edu/~adrian/630-f04/PGP-intro.html)).

---

## 1. Introduction: How PGP Works

Pretty Good Privacy (PGP) combines the best features of **conventional (symmetric) cryptography** and **public-key (asymmetric) cryptography**. PGP is a **hybrid cryptosystem**.

```
+───────────────────────────────────────────────────────────────────────────────────────────────+
|                                  HOW PGP ENCRYPTION WORKS                                     |
+───────────────────────────────────────────────────────────────────────────────────────────────+
|                                                                                               |
|  Plaintext Message                                                                            |
|        │                                                                                      |
|        ├───────────────────────────────────────────────────────┐                              |
|        ▼                                                       │                              |
|   1. Data Compression / Formatting (Tag 11)                    │                              |
|        │                                                       │                              |
|        │                                                       ▼                              |
|        │                                            2. Generate Random Session Key            |
|        │                                               (One-time symmetric key, e.g. AES-128) |
|        │                                                       │                              |
|        ▼                                                       ▼                              |
|   3. Fast Symmetric Encryption                        4. Asymmetric Public-Key Encryption     |
|      (AES-128 in OpenPGP-CFB mode)                       (Recipient's Public Key, e.g. X25519)|
|        │                                                       │                              |
|        ▼                                                       ▼                              |
|      Ciphertext Payload (Tag 9 / SED)                    Encrypted Session Key (Tag 1 / PKESK)|
|        │                                                       │                              |
|        └───────────────────────────────┬───────────────────────┘                              |
|                                        ▼                                                      |
|                          5. Combine Packets into Stream                                       |
|                                        │                                                      |
|                                        ▼                                                      |
|                          6. Radix-64 / ASCII Armor with CRC-24                                |
|                                        │                                                      |
|                                        ▼                                                      |
|                             -----BEGIN PGP MESSAGE-----                                       |
|                             ... encrypted message ...                                         |
|                             =CRC24                                                            |
|                             -----END PGP MESSAGE-----                                         |
+───────────────────────────────────────────────────────────────────────────────────────────────+
```

```
+───────────────────────────────────────────────────────────────────────────────────────────────+
|                                  HOW PGP DECRYPTION WORKS                                     |
+───────────────────────────────────────────────────────────────────────────────────────────────+
|                                                                                               |
|  Armored PGP Message                                                                          |
|        │                                                                                      |
|        ▼                                                                                      |
|   1. Strip ASCII Armor & Verify CRC-24 Checksum                                               |
|        │                                                                                      |
|        ▼                                                                                      |
|   2. Parse Packet Stream: [PKESK (Tag 1)] + [Ciphertext (Tag 9)]                              |
|        │                                                                                      |
|        ├───────────────────────────────────────────────────────┐                              |
|        ▼                                                       │                              |
|   3. Decrypt Private Key with Passphrase                       │                              |
|      (S2K Iterated & Salted + AES-256-CFB)                     │                              |
|        │                                                       │                              |
|        ▼                                                       │                              |
|   4. Asymmetric Decryption of Session Key                      │                              |
|      (Recipient's Private Key + Sender's Ephemeral Key)        │                              |
|        │                                                       │                              |
|        ▼                                                       ▼                              |
|      Recovered Session Key                            5. Symmetric Decryption of Ciphertext   |
|        │                                                 (AES-128 in OpenPGP-CFB mode)        |
|        └───────────────────────────────────────────────────────┘                              |
|                                        │                                                      |
|                                        ▼                                                      |
|                               6. Original Plaintext Message                                   |
+───────────────────────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Comparing Cryptographic Approaches

As explained in Zimmermann's guide:

| Feature | Conventional (Symmetric) Cryptography | Public-Key (Asymmetric) Cryptography | PGP Hybrid Approach |
| :--- | :--- | :--- | :--- |
| **Examples** | AES, DES, IDEA, Camellia | RSA, Diffie-Hellman, ECDH (Curve25519) | ECDH / RSA + AES (CFB) |
| **Speed** | Extremely fast (megabytes/sec) | Computationally expensive | Fast (bulk data encrypted with symmetric cipher) |
| **Key Distribution** | Difficult (both parties must share a pre-shared secret securely) | Easy (public keys can be published anywhere) | Easy (only one-time session key is encrypted with public key) |
| **Security** | High (provided key is kept secret) | High (mathematically intractable trapdoor functions) | Best of both worlds |

---

## 3. Cryptographic Steps in CustomPGP

### 1. Keys & Certificates
* **Primary Key (Tag 6)**: Used to identify the user and certify subkeys (Ed25519 / EdDSA).
* **Encryption Subkey (Tag 14)**: Dedicated solely to encrypting messages (Curve25519 / X25519).
* **Key Passphrase Protection**: Private keys are not stored in plaintext. They are hashed using **S2K Iterated and Salted** (RFC 4880 §3.7.1.3) across 1,048,576 rounds and encrypted with AES-256-CFB.

### 2. Session Key Generation & RFC 3394 Wrapping
1. For every message, CustomPGP generates a fresh random 128-bit symmetric session key.
2. An ephemeral Curve25519 key pair is created to perform scalar Diffie-Hellman multiplication with the recipient's public key.
3. The derived shared secret is fed into the **RFC 6637 KDF** to produce a Key Encryption Key (KEK).
4. The session key is packaged with a 2-byte checksum and wrapped using the **NIST RFC 3394 AES Key Wrap Algorithm**.

### 3. OpenPGP Cipher Feedback (CFB) Mode
Unlike standard CFB:
* OpenPGP CFB prepends 16 random octets and repeats the 15th and 16th octets as a synchronization check.
* The feedback register is resynchronized before encrypting actual message payload.

### 4. Radix-64 ASCII Armor & CRC-24
Binary OpenPGP packet streams are converted into printable ASCII using Radix-64 (Base64) line-wrapped at 64 characters, suffixed with an OpenPGP 24-bit Cyclic Redundancy Check (CRC-24, generator polynomial `0x1864CFB`, initial value `0xB704CE`).

---

## 4. Architecture & Browser Compatibility

CustomPGP is designed to run everywhere — directly in modern **Web Browsers**, Node.js, Deno, Bun, and Web Workers.

```
d:\js\openpgp\
├── crypto.ts       <-- Pure cryptographic engine (SHA-1, SHA-256, AES-128/256, X25519)
├── custompgp.ts    <-- OpenPGP classes: CustomPGP, PacketCodec, ArmorCodec, CryptoEngine
├── example.ts      <-- Comprehensive test & verification script
├── example_key/    <-- Sample OpenPGP key pair (Ed25519 + X25519)
```

---

## 5. Quick Start

### 1. Encrypt and Decrypt a Message

```typescript
import { CustomPGP } from './custompgp';

// Read or receive public/private keys
const publicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----...-----END PGP PUBLIC KEY BLOCK-----`;
const privateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----...-----END PGP PRIVATE KEY BLOCK-----`;

// Encrypt
const ciphertext = CustomPGP.encrypt(publicKey, 'Hello World!');
console.log(ciphertext);

// Decrypt with passphrase
const plaintext = CustomPGP.decrypt(ciphertext, privateKey, 'Test@123');
console.log(plaintext); // => "Hello World!"
```

### 2. Generate a Key Pair

```typescript
import { CustomPGP } from './custompgp';

const keyPair = CustomPGP.generateKeyPair(
  'Alice Developer <alice@example.com>',
  'SecretPassword@2026'
);

console.log(keyPair.publicKeyArmored);
console.log(keyPair.privateKeyArmored);
console.log('Key ID:', keyPair.keyId);
```

---

## 6. Running the Tests

```powershell
npm run example
```

**Verification Results:**
* Successfully reads existing sample keys from `example_key/`.
* Decrypts message with sample private key using passphrase **`Test@123`** (`PASSED 100% ✅`).
* Generates brand-new key pairs and completes end-to-end encryption/decryption (`PASSED 100% ✅`).
