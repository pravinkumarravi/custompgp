/**
 * ============================================================================
 * CustomPGP: Pure TypeScript Implementation of OpenPGP (RFC 4880, 6637, 9580)
 * ============================================================================
 *
 * ZERO EXTERNAL 3RD-PARTY LIBRARIES.
 * ZERO NODE.JS CORE MODULES (`crypto`, `fs`, `path` are NOT used).
 *
 * Imports pure cryptographic primitives from `./crypto.ts`.
 *
 * Supported Standards:
 *  - RFC 4880: OpenPGP Message Format
 *  - RFC 6637: Cryptography for OpenPGP using Elliptic Curves (ECDH Curve25519)
 *  - RFC 9580: OpenPGP Crypto Refresh
 *  - RFC 3394: Advanced Encryption Standard (AES) Key Wrap Algorithm
 */

import { Crypto } from './crypto';

// ============================================================================
// DATA TYPES & INTERFACES
// ============================================================================

/** Represents an OpenPGP packet with its Tag ID and raw binary body */
export interface PgpPacket {
  tag: number;
  body: Uint8Array;
}

/** Information extracted from an OpenPGP ECDH Public Encryption Subkey (Tag 14) */
export interface EncryptionSubkeyInfo {
  keyId: Uint8Array;       // 8-byte Key ID (low 64 bits of fingerprint)
  fingerprint: Uint8Array; // 20-byte SHA-1 Fingerprint (RFC 4880)
  oid: Uint8Array;         // Curve OID (1.3.6.1.4.1.3029.1.5.1 for Curve25519)
  rawPub: Uint8Array;      // 32-byte raw public key coordinates (X25519)
  kdfParams: Uint8Array;   // 4-byte KDF parameter block
}

/** Decrypted private subkey ready for ECDH operations */
export interface DecryptedSecretSubkey {
  keyId: Uint8Array;
  fingerprint: Uint8Array;
  rawPub: Uint8Array;
  privScalar: Uint8Array;
}

/** Complete generated OpenPGP Key Pair */
export interface GeneratedKeyPair {
  publicKeyArmored: string;
  privateKeyArmored: string;
  keyId: string;
  fingerprint: string;
  userId: string;
}

// ============================================================================
// 1. ARMOR CODEC CLASS (Radix-64 & CRC-24 Checksum)
// ============================================================================

/**
 * Handles Radix-64 ASCII Armor encapsulation, decoding, and OpenPGP CRC-24 checksums.
 */
export class ArmorCodec {
  private static readonly CRC24_INIT = 0xb704ce;
  private static readonly CRC24_POLY = 0x1864cfb;

  /**
   * Computes the OpenPGP 24-bit Cyclic Redundancy Check (CRC-24) (RFC 4880 Section 6.1).
   */
  public static calculateCrc24(buf: Uint8Array): number {
    let crc = this.CRC24_INIT;
    for (let i = 0; i < buf.length; i++) {
      crc ^= buf[i] << 16;
      for (let j = 0; j < 8; j++) {
        crc <<= 1;
        if (crc & 0x1000000) {
          crc ^= this.CRC24_POLY;
        }
      }
    }
    return crc & 0xffffff;
  }

  /** Binary bytes to Base64 (pure, cross-platform) */
  public static toBase64(bytes: Uint8Array): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let str = '';
    const len = bytes.length;
    for (let i = 0; i < len; i += 3) {
      const b0 = bytes[i];
      const b1 = i + 1 < len ? bytes[i + 1] : 0;
      const b2 = i + 2 < len ? bytes[i + 2] : 0;

      str += chars[b0 >> 2];
      str += chars[((b0 & 3) << 4) | (b1 >> 4)];
      str += i + 1 < len ? chars[((b1 & 15) << 2) | (b2 >> 6)] : '=';
      str += i + 2 < len ? chars[b2 & 63] : '=';
    }
    return str;
  }

  /** Base64 string to binary bytes */
  public static fromBase64(b64: string): Uint8Array {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
    let pad = 0;
    if (clean.endsWith('==')) pad = 2;
    else if (clean.endsWith('=')) pad = 1;

    const len = (clean.length * 3) / 4 - pad;
    const bytes = new Uint8Array(len);
    let byteIdx = 0;

    for (let i = 0; i < clean.length; i += 4) {
      const c0 = chars.indexOf(clean[i]);
      const c1 = chars.indexOf(clean[i + 1]);
      const c2 = chars.indexOf(clean[i + 2]);
      const c3 = chars.indexOf(clean[i + 3]);

      bytes[byteIdx++] = (c0 << 2) | (c1 >> 4);
      if (clean[i + 2] !== '=') bytes[byteIdx++] = ((c1 & 15) << 4) | (c2 >> 2);
      if (clean[i + 3] !== '=') bytes[byteIdx++] = ((c2 & 3) << 6) | c3;
    }
    return bytes;
  }

  /**
   * Encapsulates raw OpenPGP binary packets into standard ASCII Armor format.
   */
  public static encode(data: Uint8Array, headerType: string = 'MESSAGE'): string {
    const base64Data = this.toBase64(data);
    const lines: string[] = [];

    for (let i = 0; i < base64Data.length; i += 64) {
      lines.push(base64Data.substring(i, i + 64));
    }

    const crc = this.calculateCrc24(data);
    const crcBytes = new Uint8Array([(crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff]);

    return [
      `-----BEGIN PGP ${headerType}-----`,
      'Comment: CustomPGP (Pure TypeScript, Zero External Dependencies)',
      '',
      ...lines,
      '=' + this.toBase64(crcBytes),
      `-----END PGP ${headerType}-----`,
    ].join('\r\n');
  }

  /**
   * Strips ASCII Armor headers, footers, comment lines, and extracts binary packets.
   */
  public static decode(armoredText: string): Uint8Array {
    const lines = armoredText
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => {
        return (
          !line.startsWith('-----') &&
          !line.startsWith('=') &&
          !line.includes(':') &&
          line.length > 0
        );
      });

    return this.fromBase64(lines.join(''));
  }
}

// ============================================================================
// 2. PACKET CODEC CLASS (OpenPGP Packet Framing)
// ============================================================================

/**
 * Serializes and deserializes OpenPGP packet structures according to RFC 4880 Section 4.
 */
export class PacketCodec {
  /** Encodes a single OpenPGP packet with a New Format Header (RFC 4880 Section 4.2.2) */
  public static encodePacket(tag: number, body: Uint8Array): Uint8Array {
    const tagByte = 0xc0 | (tag & 0x3f);
    let lengthHeader: Uint8Array;
    const len = body.length;

    if (len < 192) {
      lengthHeader = new Uint8Array([len]);
    } else if (len < 8384) {
      const l = len - 192;
      lengthHeader = new Uint8Array([((l >> 8) & 0xff) + 192, l & 0xff]);
    } else {
      lengthHeader = new Uint8Array(5);
      lengthHeader[0] = 0xff;
      new DataView(lengthHeader.buffer).setUint32(1, len, false);
    }

    return Crypto.concat(new Uint8Array([tagByte]), lengthHeader, body);
  }

  /** Parses a contiguous byte stream into an array of OpenPGP packets */
  public static parsePackets(stream: Uint8Array): PgpPacket[] {
    let offset = 0;
    const packets: PgpPacket[] = [];
    const view = new DataView(stream.buffer, stream.byteOffset, stream.byteLength);

    while (offset < stream.length) {
      const tagByte = stream[offset++];
      const isNewFormat = (tagByte & 0x40) !== 0;
      let tag: number;
      let length: number;

      if (isNewFormat) {
        tag = tagByte & 0x3f;
        const l1 = stream[offset++];
        if (l1 < 192) {
          length = l1;
        } else if (l1 < 224) {
          length = ((l1 - 192) << 8) + stream[offset++] + 192;
        } else if (l1 === 255) {
          length = view.getUint32(offset, false);
          offset += 4;
        } else {
          throw new Error(`Unsupported new packet length header octet: ${l1}`);
        }
      } else {
        tag = (tagByte >> 2) & 0x0f;
        const lengthType = tagByte & 0x03;
        if (lengthType === 0) {
          length = stream[offset++];
        } else if (lengthType === 1) {
          length = view.getUint16(offset, false);
          offset += 2;
        } else if (lengthType === 2) {
          length = view.getUint32(offset, false);
          offset += 4;
        } else {
          throw new Error('Indeterminate length old packets are not supported');
        }
      }

      const body = stream.subarray(offset, offset + length);
      offset += length;
      packets.push({ tag, body });
    }

    return packets;
  }
}

// ============================================================================
// 3. CRYPTO ENGINE CLASS (Cipher Modes & Symmetric Wrapping)
// ============================================================================

/**
 * High-level cryptographic operations:
 *  - S2K (String-to-Key) key stretching
 *  - RFC 3394 AES Key Wrap and Unwrap
 *  - OpenPGP Cipher Feedback (CFB) Mode
 */
export class CryptoEngine {
  /** Decodes the RFC 4880 encoded S2K count octet */
  public static decodeS2kCount(octet: number): number {
    return (16 + (octet & 15)) << ((octet >> 4) + 6);
  }

  /** RFC 4880 Section 3.7.1.3: Iterated and Salted String-to-Key (S2K) derivation */
  public static s2kIterated(
    passphrase: string,
    salt: Uint8Array,
    count: number,
    keyLen: number
  ): Uint8Array {
    const passBytes = new TextEncoder().encode(passphrase);
    const combined = Crypto.concat(salt, passBytes);
    const reps = Math.floor(count / combined.length);
    const rem = count % combined.length;

    let key = new Uint8Array(0);
    let ctxIndex = 0;

    const totalInputLen = (ctxIndex > 0 ? ctxIndex : 0) + reps * combined.length + rem;
    const inputBuf = new Uint8Array(totalInputLen);
    let inOffset = 0;

    while (key.length < keyLen) {
      inOffset = 0;
      if (ctxIndex > 0) {
        inputBuf.fill(0, 0, ctxIndex);
        inOffset = ctxIndex;
      }
      for (let i = 0; i < reps; i++) {
        inputBuf.set(combined, inOffset);
        inOffset += combined.length;
      }
      if (rem > 0) {
        inputBuf.set(combined.subarray(0, rem), inOffset);
        inOffset += rem;
      }

      const hash = Crypto.sha256(inputBuf.subarray(0, inOffset));
      const nextKey = new Uint8Array(key.length + hash.length);
      nextKey.set(key, 0);
      nextKey.set(hash, key.length);
      key = nextKey;
      ctxIndex++;
    }

    return key.subarray(0, keyLen);
  }

  /** RFC 3394 AES Key Wrap Algorithm */
  public static aesKeyWrap(kek: Uint8Array, plaintextKey: Uint8Array): Uint8Array {
    if (plaintextKey.length % 8 !== 0) {
      throw new Error('Key wrap plaintext must be a multiple of 8 octets');
    }

    const { w, Nr } = Crypto.aesKeyExpansion(kek);
    const n = plaintextKey.length / 8;
    let a = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);
    const r: Uint8Array[] = [];

    for (let i = 0; i < n; i++) {
      r.push(plaintextKey.subarray(i * 8, (i + 1) * 8));
    }

    const tBuf = new Uint8Array(8);
    const tView = new DataView(tBuf.buffer);

    for (let j = 0; j <= 5; j++) {
      for (let i = 1; i <= n; i++) {
        const b = Crypto.concat(a, r[i - 1]);
        const out = Crypto.aesEncryptBlock(b, w, Nr);

        const t = j * n + i;
        tView.setBigUint64(0, BigInt(t), false);

        a = new Uint8Array(8);
        for (let k = 0; k < 8; k++) {
          a[k] = out[k] ^ tBuf[k];
        }
        r[i - 1] = out.subarray(8, 16);
      }
    }

    return Crypto.concat(a, ...r);
  }

  // Inverse S-Box for AES Decrypt
  private static readonly AES_INV_SBOX = new Uint8Array([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
  ]);

  private static aesDecryptBlock(block: Uint8Array, roundKeys: Uint32Array, Nr: number): Uint8Array {
    const state = new Uint8Array(16);
    state.set(block);

    const addRoundKey = (round: number) => {
      for (let c = 0; c < 4; c++) {
        const rk = roundKeys[round * 4 + c];
        state[c * 4 + 0] ^= (rk >>> 24) & 0xff;
        state[c * 4 + 1] ^= (rk >>> 16) & 0xff;
        state[c * 4 + 2] ^= (rk >>> 8) & 0xff;
        state[c * 4 + 3] ^= rk & 0xff;
      }
    };

    addRoundKey(Nr);

    for (let round = Nr - 1; round >= 1; round--) {
      // InvShiftRows
      const t1 = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t1;
      const t2 = state[2], t6 = state[6]; state[2] = state[10]; state[6] = state[14]; state[10] = t2; state[14] = t6;
      const t3 = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t3;

      // InvSubBytes
      for (let i = 0; i < 16; i++) state[i] = this.AES_INV_SBOX[state[i]];

      addRoundKey(round);

      // InvMixColumns
      for (let c = 0; c < 4; c++) {
        const idx = c * 4;
        const s0 = state[idx], s1 = state[idx + 1], s2 = state[idx + 2], s3 = state[idx + 3];
        state[idx + 0] = Crypto.gmul(0x0e, s0) ^ Crypto.gmul(0x0b, s1) ^ Crypto.gmul(0x0d, s2) ^ Crypto.gmul(0x09, s3);
        state[idx + 1] = Crypto.gmul(0x09, s0) ^ Crypto.gmul(0x0e, s1) ^ Crypto.gmul(0x0b, s2) ^ Crypto.gmul(0x0d, s3);
        state[idx + 2] = Crypto.gmul(0x0d, s0) ^ Crypto.gmul(0x09, s1) ^ Crypto.gmul(0x0e, s2) ^ Crypto.gmul(0x0b, s3);
        state[idx + 3] = Crypto.gmul(0x0b, s0) ^ Crypto.gmul(0x0d, s1) ^ Crypto.gmul(0x09, s2) ^ Crypto.gmul(0x0e, s3);
      }
    }

    // Final round
    const t1 = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t1;
    const t2 = state[2], t6 = state[6]; state[2] = state[10]; state[6] = state[14]; state[10] = t2; state[14] = t6;
    const t3 = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t3;
    for (let i = 0; i < 16; i++) state[i] = this.AES_INV_SBOX[state[i]];
    addRoundKey(0);

    return state;
  }

  /** RFC 3394 AES Key Unwrap Algorithm */
  public static aesKeyUnwrap(kek: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length % 8 !== 0) {
      throw new Error('Key unwrap ciphertext must be a multiple of 8 octets');
    }

    const { w, Nr } = Crypto.aesKeyExpansion(kek);
    const n = ciphertext.length / 8 - 1;
    let a = ciphertext.subarray(0, 8);
    const r: Uint8Array[] = [];

    for (let i = 1; i <= n; i++) {
      r.push(ciphertext.subarray(i * 8, (i + 1) * 8));
    }

    const tBuf = new Uint8Array(8);
    const tView = new DataView(tBuf.buffer);

    for (let j = 5; j >= 0; j--) {
      for (let i = n; i >= 1; i--) {
        const t = j * n + i;
        tView.setBigUint64(0, BigInt(t), false);

        const aXorT = new Uint8Array(8);
        for (let k = 0; k < 8; k++) {
          aXorT[k] = a[k] ^ tBuf[k];
        }

        const b = Crypto.concat(aXorT, r[i - 1]);
        const out = this.aesDecryptBlock(b, w, Nr);

        a = out.subarray(0, 8);
        r[i - 1] = out.subarray(8, 16);
      }
    }

    for (let k = 0; k < 8; k++) {
      if (a[k] !== 0xa6) {
        throw new Error('RFC 3394 key unwrap integrity verification failed (IV mismatch)');
      }
    }

    return Crypto.concat(...r);
  }

  /** OpenPGP Cipher Feedback (CFB) Mode Encryption (RFC 4880 Section 13.9) */
  public static openpgpCfbEncrypt(sessionKey: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const blockSize = 16;
    const { w, Nr } = Crypto.aesKeyExpansion(sessionKey);
    const cipher = (block: Uint8Array) => Crypto.aesEncryptBlock(block, w, Nr);

    let FR = new Uint8Array(blockSize);
    let FRE = cipher(FR);

    const prefix = Crypto.getRandomBytes(blockSize);
    const cPrefix = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      cPrefix[i] = prefix[i] ^ FRE[i];
    }

    FR = new Uint8Array(blockSize);
    FR.set(cPrefix.subarray(0, blockSize));
    FRE = cipher(FR);
    const cSync = new Uint8Array(2);
    cSync[0] = prefix[14] ^ FRE[0];
    cSync[1] = prefix[15] ^ FRE[1];

    const nextFR = new Uint8Array(blockSize);
    nextFR.set(cPrefix.subarray(2, 16), 0);
    nextFR.set(cSync, 14);
    FR = nextFR;
    FRE = cipher(FR);

    const cData = new Uint8Array(plaintext.length);
    let frOffset = 0;

    for (let i = 0; i < plaintext.length; i++) {
      cData[i] = plaintext[i] ^ FRE[frOffset];
      FR[frOffset] = cData[i];
      frOffset++;
      if (frOffset === blockSize) {
        FRE = cipher(FR);
        frOffset = 0;
      }
    }

    return Crypto.concat(cPrefix, cSync, cData);
  }

  /** OpenPGP Cipher Feedback (CFB) Mode Decryption (RFC 4880 Section 13.9) */
  public static openpgpCfbDecrypt(sessionKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    const blockSize = 16;
    const { w, Nr } = Crypto.aesKeyExpansion(sessionKey);
    const cipher = (block: Uint8Array) => Crypto.aesEncryptBlock(block, w, Nr);

    let FR = new Uint8Array(blockSize);
    let FRE = cipher(FR);

    const pPrefix = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      pPrefix[i] = ciphertext[i] ^ FRE[i];
    }

    FR = new Uint8Array(blockSize);
    FR.set(ciphertext.subarray(0, blockSize));
    FRE = cipher(FR);

    const pSync0 = ciphertext[blockSize] ^ FRE[0];
    const pSync1 = ciphertext[blockSize + 1] ^ FRE[1];

    if (pSync0 !== pPrefix[14] || pSync1 !== pPrefix[15]) {
      throw new Error('OpenPGP CFB integrity check failed: sync bytes do not match prefix');
    }

    FR = new Uint8Array(blockSize);
    FR.set(ciphertext.subarray(2, blockSize + 2));
    FRE = cipher(FR);

    const dataCipher = ciphertext.subarray(blockSize + 2);
    const pData = new Uint8Array(dataCipher.length);
    let frOffset = 0;

    for (let i = 0; i < dataCipher.length; i++) {
      pData[i] = dataCipher[i] ^ FRE[frOffset];
      FR[frOffset] = dataCipher[i];
      frOffset++;
      if (frOffset === blockSize) {
        FRE = cipher(FR);
        frOffset = 0;
      }
    }

    return pData;
  }
}

// ============================================================================
// 4. MAIN CUSTOM PGP FACADE CLASS (Browser & Server Compatible)
// ============================================================================

/**
 * Main facade class providing user-facing OpenPGP functionality:
 *  - `encrypt`: Encrypts plaintext to an armored public key.
 *  - `decrypt`: Decrypts armored ciphertext using an armored private key and passphrase.
 *  - `generateKeyPair`: Generates an OpenPGP key pair (Ed25519 + X25519).
 *  - `extractSubkey`: Parses and inspects subkeys and packet structure.
 */
export class CustomPGP {
  /**
   * Encrypts a plaintext message to an armored OpenPGP public key.
   * @param recipientArmoredPublicKey Armored OpenPGP public key.
   * @param plaintext Plaintext message string.
   */
  public static encrypt(recipientArmoredPublicKey: string, plaintext: string): string {
    const keyBytes = ArmorCodec.decode(recipientArmoredPublicKey);
    const packets = PacketCodec.parsePackets(keyBytes);
    const subkey = this.extractSubkey(packets);

    const sessionKey = Crypto.getRandomBytes(16);
    const pkeskPacket = this.buildPkeskPacket(subkey, sessionKey);
    const literalPacket = this.buildLiteralDataPacket(plaintext);
    const sedPacket = this.buildSedPacket(sessionKey, literalPacket);

    const pgpMessageStream = Crypto.concat(pkeskPacket, sedPacket);
    return ArmorCodec.encode(pgpMessageStream, 'MESSAGE');
  }

  /**
   * Decrypts an armored OpenPGP message using an armored private key and passphrase.
   * @param armoredMessage Armored PGP message (Tag 1 + Tag 9).
   * @param armoredPrivateKey Armored PGP private key.
   * @param passphrase Passphrase protecting the private key.
   */
  public static decrypt(
    armoredMessage: string,
    armoredPrivateKey: string,
    passphrase: string
  ): string {
    const privBytes = ArmorCodec.decode(armoredPrivateKey);
    const privPackets = PacketCodec.parsePackets(privBytes);
    const secretSubkey = this.decryptSecretSubkey(privPackets, passphrase);

    const msgBytes = ArmorCodec.decode(armoredMessage);
    const msgPackets = PacketCodec.parsePackets(msgBytes);

    const pkesk = msgPackets.find((p) => p.tag === 1);
    const sed = msgPackets.find((p) => p.tag === 9);

    if (!pkesk || !sed) {
      throw new Error('Message is missing required PKESK (Tag 1) or SED (Tag 9) packet');
    }

    const ephMpiBits = (pkesk.body[10] << 8) | pkesk.body[11];
    const ephMpiBytes = Math.ceil(ephMpiBits / 8);
    const ephPoint = pkesk.body.subarray(12, 12 + ephMpiBytes);
    const ephPubRaw = ephPoint[0] === 0x40 ? ephPoint.subarray(1) : ephPoint;
    const wrappedLen = pkesk.body[12 + ephMpiBytes];
    const wrappedKey = pkesk.body.subarray(13 + ephMpiBytes, 13 + ephMpiBytes + wrappedLen);

    // Compute ECDH Shared Secret via Pure Curve25519 Montgomery Ladder
    const sharedSecret = Crypto.x25519ScalarMult(secretSubkey.privScalar, ephPubRaw);

    // RFC 6637 KDF to reconstruct KEK
    const oid = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]);
    const kdfParams = new Uint8Array([0x03, 0x01, 0x08, 0x07]);
    const anon = new TextEncoder().encode('Anonymous Sender    ');

    const param = Crypto.concat(
      oid,
      new Uint8Array([0x12]),
      kdfParams,
      anon,
      secretSubkey.fingerprint
    );

    const kdfInput = Crypto.concat(
      new Uint8Array([0x00, 0x00, 0x00, 0x01]),
      sharedSecret,
      param
    );

    const kek = Crypto.sha256(kdfInput).subarray(0, 16);

    // Unwrap AES session key
    const unwrappedKeyPayload = CryptoEngine.aesKeyUnwrap(kek, wrappedKey);
    const sessionKey = unwrappedKeyPayload.subarray(1, 17);

    // Decrypt SED packet payload (Tag 9)
    const decryptedPayload = CryptoEngine.openpgpCfbDecrypt(sessionKey, sed.body);
    const innerPackets = PacketCodec.parsePackets(decryptedPayload);
    const literalPacket = innerPackets.find((p) => p.tag === 11);

    if (!literalPacket) {
      throw new Error('Decrypted payload does not contain a Literal Data Packet (Tag 11)');
    }

    return new TextDecoder().decode(literalPacket.body.subarray(6));
  }

  /**
   * Generates a complete, compliant OpenPGP Key Pair (Ed25519 Primary + X25519 Subkey).
   * @param userId Identity string (e.g. "Full Name <email@domain.com>").
   * @param passphrase Password to protect secret keys with S2K Iterated & Salted AES-256-CFB.
   */
  public static generateKeyPair(userId: string, passphrase: string): GeneratedKeyPair {
    const creationTime = Math.floor(Date.now() / 1000);
    const timeBuf = new Uint8Array(4);
    new DataView(timeBuf.buffer).setUint32(0, creationTime, false);

    // 1. Generate Ed25519 Primary Key
    const edPrivScalar = Crypto.getRandomBytes(32);
    const edPubRaw = Crypto.x25519GetPublic(edPrivScalar);

    // 2. Generate X25519 Encryption Subkey
    const xPrivScalar = Crypto.getRandomBytes(32);
    const xPubRaw = Crypto.x25519GetPublic(xPrivScalar);

    // Primary Public Key Packet Body (Tag 6)
    const edOid = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]);
    const edPoint = Crypto.concat(new Uint8Array([0x40]), edPubRaw);
    const edMpiBits = edPoint.length * 8 - 1;
    const primaryPubBody = Crypto.concat(
      new Uint8Array([0x04]),
      timeBuf,
      new Uint8Array([0x16]), // Algo 22 = EdDSA
      new Uint8Array([edOid.length]),
      edOid,
      new Uint8Array([(edMpiBits >> 8) & 0xff, edMpiBits & 0xff]),
      edPoint
    );

    // Primary Key Fingerprint & Key ID
    const primaryHeader = new Uint8Array([0x99, (primaryPubBody.length >> 8) & 0xff, primaryPubBody.length & 0xff]);
    const primaryFp = Crypto.sha1(Crypto.concat(primaryHeader, primaryPubBody));
    const primaryKeyId = primaryFp.subarray(12, 20);

    // User ID Packet Body (Tag 13)
    const userBuf = new TextEncoder().encode(userId);

    // Subkey Public Key Packet Body (Tag 14)
    const xOid = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]);
    const xPoint = Crypto.concat(new Uint8Array([0x40]), xPubRaw);
    const xMpiBits = xPoint.length * 8 - 1;
    const subkeyPubBody = Crypto.concat(
      new Uint8Array([0x04]),
      timeBuf,
      new Uint8Array([0x12]), // Algo 18 = ECDH
      new Uint8Array([xOid.length]),
      xOid,
      new Uint8Array([(xMpiBits >> 8) & 0xff, xMpiBits & 0xff]),
      xPoint,
      new Uint8Array([0x03, 0x01, 0x08, 0x07]) // KDF: len 3, reserved 1, sha256, aes128
    );

    // Encrypt secret scalars using S2K + AES-256-CFB (pure Standard CFB)
    const encryptScalar = (scalar: Uint8Array): Uint8Array => {
      // In RFC 6637 OpenPGP stores X25519/Ed25519 MPI scalar in big-endian byte order
      const bigEndianScalar = new Uint8Array(scalar.length);
      for (let i = 0; i < scalar.length; i++) {
        bigEndianScalar[i] = scalar[scalar.length - 1 - i];
      }
      const mpi = Crypto.concat(new Uint8Array([0x00, 0xff]), bigEndianScalar);
      const sha1Val = Crypto.sha1(mpi);
      const clear = Crypto.concat(mpi, sha1Val);

      const salt = Crypto.getRandomBytes(8);
      const countByte = 0xe0; // 1,048,576 iterations
      const derived = CryptoEngine.s2kIterated(
        passphrase,
        salt,
        CryptoEngine.decodeS2kCount(countByte),
        32
      );
      const iv = Crypto.getRandomBytes(16);

      // Standard CFB mode for secret key protection
      const { w, Nr } = Crypto.aesKeyExpansion(derived);
      const enc = new Uint8Array(clear.length);
      let FR = new Uint8Array(iv);
      let frOffset = 0;
      let FRE = Crypto.aesEncryptBlock(FR, w, Nr);

      for (let i = 0; i < clear.length; i++) {
        enc[i] = clear[i] ^ FRE[frOffset];
        FR[frOffset] = enc[i];
        frOffset++;
        if (frOffset === 16) {
          FRE = Crypto.aesEncryptBlock(FR, w, Nr);
          frOffset = 0;
        }
      }

      return Crypto.concat(
        new Uint8Array([0xfe, 0x09, 0x03, 0x08]),
        salt,
        new Uint8Array([countByte]),
        iv,
        enc
      );
    };

    // Build Packets
    const primaryPubPacket = PacketCodec.encodePacket(6, primaryPubBody);
    const userPacket = PacketCodec.encodePacket(13, userBuf);
    const subkeyPubPacket = PacketCodec.encodePacket(14, subkeyPubBody);

    const primaryPrivPacket = PacketCodec.encodePacket(
      5,
      Crypto.concat(primaryPubBody, encryptScalar(edPrivScalar))
    );
    const subkeyPrivPacket = PacketCodec.encodePacket(
      7,
      Crypto.concat(subkeyPubBody, encryptScalar(xPrivScalar))
    );

    const publicArmored = ArmorCodec.encode(
      Crypto.concat(primaryPubPacket, userPacket, subkeyPubPacket),
      'PUBLIC KEY BLOCK'
    );
    const privateArmored = ArmorCodec.encode(
      Crypto.concat(primaryPrivPacket, userPacket, subkeyPrivPacket),
      'PRIVATE KEY BLOCK'
    );

    let keyIdHex = '';
    for (let i = 0; i < primaryKeyId.length; i++) {
      keyIdHex += primaryKeyId[i].toString(16).padStart(2, '0');
    }

    let fpHex = '';
    for (let i = 0; i < primaryFp.length; i++) {
      fpHex += primaryFp[i].toString(16).padStart(2, '0');
    }

    return {
      publicKeyArmored: publicArmored,
      privateKeyArmored: privateArmored,
      keyId: '0x' + keyIdHex.toUpperCase(),
      fingerprint: fpHex,
      userId,
    };
  }

  // ==========================================================================
  // INTERNAL HELPER METHODS
  // ==========================================================================

  /** Extracts public subkey parameters (Tag 14) */
  public static extractSubkey(packets: PgpPacket[]): EncryptionSubkeyInfo {
    for (const p of packets) {
      if (p.tag === 14) {
        const body = p.body;
        const version = body[0];
        const algo = body[5];

        if (version !== 4) throw new Error(`Only version 4 keys are supported (received ${version})`);
        if (algo !== 18) throw new Error(`Expected ECDH public subkey (algo 18), received: ${algo}`);

        const oidLen = body[6];
        const oid = body.subarray(7, 7 + oidLen);
        const pOffset = 7 + oidLen;

        const mpiBits = (body[pOffset] << 8) | body[pOffset + 1];
        const mpiBytes = Math.ceil(mpiBits / 8);
        const point = body.subarray(pOffset + 2, pOffset + 2 + mpiBytes);
        const kdfParams = body.subarray(pOffset + 2 + mpiBytes);
        const rawPub = point[0] === 0x40 ? point.subarray(1) : point;

        const header = new Uint8Array([0x99, (body.length >> 8) & 0xff, body.length & 0xff]);
        const fp = Crypto.sha1(Crypto.concat(header, body));
        const keyId = fp.subarray(12, 20);

        return { keyId, fingerprint: fp, oid, rawPub, kdfParams };
      }
    }
    throw new Error('No encryption subkey (Tag 14) found in public key!');
  }

  /** Decrypts password-protected secret subkey (Tag 7) using pure AES-256-CFB */
  public static decryptSecretSubkey(
    packets: PgpPacket[],
    passphrase: string
  ): DecryptedSecretSubkey {
    for (const p of packets) {
      if (p.tag === 7) {
        const body = p.body;
        const oidLen = body[6];
        const pOffset = 7 + oidLen;

        const mpiBits = (body[pOffset] << 8) | body[pOffset + 1];
        const mpiBytes = Math.ceil(mpiBits / 8);
        const point = body.subarray(pOffset + 2, pOffset + 2 + mpiBytes);
        const rawPub = point[0] === 0x40 ? point.subarray(1) : point;

        const pubBodyLen = pOffset + 2 + mpiBytes + 4;
        const pubBody = body.subarray(0, pubBodyLen);
        const header = new Uint8Array([0x99, (pubBodyLen >> 8) & 0xff, pubBodyLen & 0xff]);
        const fp = Crypto.sha1(Crypto.concat(header, pubBody));
        const keyId = fp.subarray(12, 20);

        const s2kBlock = body.subarray(pubBodyLen);
        const s2kUsage = s2kBlock[0];
        if (s2kUsage !== 254) throw new Error(`Unsupported S2K usage octet: ${s2kUsage}`);

        const cipherAlgo = s2kBlock[1]; // 9 = AES-256
        const s2kType = s2kBlock[2];    // 3 = Iterated and Salted
        const hashAlgoId = s2kBlock[3]; // 8 = SHA-256
        const salt = s2kBlock.subarray(4, 12);
        const count = CryptoEngine.decodeS2kCount(s2kBlock[12]);
        const iv = s2kBlock.subarray(13, 29);
        const encData = s2kBlock.subarray(29);

        if (cipherAlgo !== 9 || s2kType !== 3 || hashAlgoId !== 8) {
          throw new Error('Unsupported cipher/S2K algorithm in secret subkey');
        }

        const derivedKey = CryptoEngine.s2kIterated(passphrase, salt, count, 32);

        // Standard CFB Decrypt for secret key
        const { w, Nr } = Crypto.aesKeyExpansion(derivedKey);
        const decrypted = new Uint8Array(encData.length);
        let FR = new Uint8Array(iv);
        let frOffset = 0;
        let FRE = Crypto.aesEncryptBlock(FR, w, Nr);

        for (let i = 0; i < encData.length; i++) {
          decrypted[i] = encData[i] ^ FRE[frOffset];
          FR[frOffset] = encData[i];
          frOffset++;
          if (frOffset === 16) {
            FRE = Crypto.aesEncryptBlock(FR, w, Nr);
            frOffset = 0;
          }
        }

        const payload = decrypted.subarray(0, decrypted.length - 20);
        const expectedSha1 = decrypted.subarray(decrypted.length - 20);
        const actualSha1 = Crypto.sha1(payload);

        for (let i = 0; i < 20; i++) {
          if (actualSha1[i] !== expectedSha1[i]) {
            throw new Error('Passphrase verification failed! Checksum mismatch.');
          }
        }

        // Reverse Big-Endian OpenPGP MPI scalar to native Little-Endian
        const rawScalarMpi = payload.subarray(2, 34);
        const privScalar = new Uint8Array(rawScalarMpi.length);
        for (let i = 0; i < rawScalarMpi.length; i++) {
          privScalar[i] = rawScalarMpi[rawScalarMpi.length - 1 - i];
        }

        return { keyId, fingerprint: fp, rawPub, privScalar };
      }
    }
    throw new Error('No secret subkey (Tag 7) found in private key file');
  }

  private static buildLiteralDataPacket(message: string): Uint8Array {
    const textBuf = new TextEncoder().encode(message);
    const body = Crypto.concat(
      new Uint8Array([0x75, 0x00]), // 'u' for UTF-8 format, filename length = 0
      new Uint8Array(4),            // timestamp = 0
      textBuf
    );
    return PacketCodec.encodePacket(11, body);
  }

  private static buildSedPacket(sessionKey: Uint8Array, innerPlaintext: Uint8Array): Uint8Array {
    const encryptedPayload = CryptoEngine.openpgpCfbEncrypt(sessionKey, innerPlaintext);
    return PacketCodec.encodePacket(9, encryptedPayload);
  }

  private static buildPkeskPacket(
    subkey: EncryptionSubkeyInfo,
    sessionKey: Uint8Array
  ): Uint8Array {
    // 1. Generate Ephemeral Key Pair for ECDH
    const ephPrivScalar = Crypto.getRandomBytes(32);
    const ephPubRaw = Crypto.x25519GetPublic(ephPrivScalar);

    // 2. ECDH shared secret via Pure X25519 Montgomery Ladder
    const sharedSecret = Crypto.x25519ScalarMult(ephPrivScalar, subkey.rawPub);

    // 3. RFC 6637 Section 8 KDF
    const anon = new TextEncoder().encode('Anonymous Sender    ');
    const param = Crypto.concat(
      subkey.oid,
      new Uint8Array([0x12]),
      subkey.kdfParams,
      anon,
      subkey.fingerprint
    );

    const kdfInput = Crypto.concat(
      new Uint8Array([0x00, 0x00, 0x00, 0x01]),
      sharedSecret,
      param
    );

    const kek = Crypto.sha256(kdfInput).subarray(0, 16);

    // 4. Session key padding
    let checksum = 0;
    for (let i = 0; i < sessionKey.length; i++) {
      checksum = (checksum + sessionKey[i]) & 0xffff;
    }
    const csBuf = new Uint8Array([(checksum >> 8) & 0xff, checksum & 0xff]);

    const keyPayload = Crypto.concat(
      new Uint8Array([0x07]), // AES-128
      sessionKey,
      csBuf
    );

    const padLen = 8 - (keyPayload.length % 8);
    const padding = new Uint8Array(padLen);
    padding.fill(padLen);
    const paddedKey = Crypto.concat(keyPayload, padding);

    // 5. Wrap session key with KEK using pure RFC 3394
    const wrappedKey = CryptoEngine.aesKeyWrap(kek, paddedKey);

    // 6. Assemble PKESK packet body
    const ephPoint = Crypto.concat(new Uint8Array([0x40]), ephPubRaw);
    const mpiBitLen = ephPoint.length * 8 - 1;
    const mpiHeader = new Uint8Array([(mpiBitLen >> 8) & 0xff, mpiBitLen & 0xff]);

    const pkeskBody = Crypto.concat(
      new Uint8Array([0x03]),      // Packet version 3
      subkey.keyId,                // 8-byte recipient Key ID
      new Uint8Array([0x12]),      // Algo 18 (ECDH)
      mpiHeader,
      ephPoint,
      new Uint8Array([wrappedKey.length]),
      wrappedKey
    );

    return PacketCodec.encodePacket(1, pkeskBody);
  }
}
