/**
 * ============================================================================
 * Crypto: Pure TypeScript / JavaScript Cryptographic Engine
 * ============================================================================
 *
 * ZERO EXTERNAL 3RD-PARTY LIBRARIES.
 * ZERO NODE.JS CORE MODULES (`crypto`, `fs`, `path` are NOT used).
 *
 * Fully compatible with:
 *  - Modern Web Browsers (Chrome, Firefox, Safari, Edge)
 *  - Node.js, Deno, Bun, Cloudflare Workers, Electron
 *
 * Features:
 *  1. Pure SHA-1 Hash Engine (FIPS PUB 180-1 / RFC 3174)
 *  2. Pure SHA-256 Hash Engine (FIPS PUB 180-4)
 *  3. Pure AES-128 & AES-256 Block Cipher (FIPS PUB 197 / Rijndael)
 *  4. Pure Curve25519 / X25519 Elliptic Curve Montgomery Ladder (RFC 7748)
 *  5. Secure Cross-Platform Random Bytes Generator (globalThis.crypto)
 */

export class Crypto {
  /**
   * Secure Random Byte Generator.
   * Uses standard Web Crypto API (window.crypto in browser, globalThis.crypto in modern runtimes).
   */
  public static getRandomBytes(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    if (
      typeof globalThis !== 'undefined' &&
      globalThis.crypto &&
      typeof globalThis.crypto.getRandomValues === 'function'
    ) {
      globalThis.crypto.getRandomValues(bytes);
    } else {
      // Fallback pseudo-random for edge environments without Web Crypto API
      for (let i = 0; i < length; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    return bytes;
  }

  // --------------------------------------------------------------------------
  // SHA-1 (FIPS PUB 180-1 / RFC 3174)
  // --------------------------------------------------------------------------

  /**
   * Computes standard 160-bit SHA-1 hash.
   * @param bytes Input byte array.
   * @returns 20-byte SHA-1 digest.
   */
  public static sha1(bytes: Uint8Array): Uint8Array {
    let h0 = 0x67452301;
    let h1 = 0xefcdab89;
    let h2 = 0x98badcfe;
    let h3 = 0x10325476;
    let h4 = 0xc3d2e1f0;

    const len = bytes.length;
    const bitLen = BigInt(len) * 8n;
    const padLen = len % 64 < 56 ? 56 - (len % 64) : 120 - (len % 64);
    const total = len + padLen + 8;
    const buf = new Uint8Array(total);
    buf.set(bytes, 0);
    buf[len] = 0x80;
    const view = new DataView(buf.buffer);
    view.setBigUint64(total - 8, bitLen, false);

    const w = new Uint32Array(80);
    for (let i = 0; i < total; i += 64) {
      for (let t = 0; t < 16; t++) {
        w[t] = view.getUint32(i + t * 4, false);
      }
      for (let t = 16; t < 80; t++) {
        const x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
        w[t] = (x << 1) | (x >>> 31);
      }

      let a = h0, b = h1, c = h2, d = h3, e = h4;
      for (let t = 0; t < 80; t++) {
        let f: number, k: number;
        if (t < 20) {
          f = (b & c) | (~b & d);
          k = 0x5a827999;
        } else if (t < 40) {
          f = b ^ c ^ d;
          k = 0x6ed9eba1;
        } else if (t < 60) {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8f1bbcdc;
        } else {
          f = b ^ c ^ d;
          k = 0xca62c1d6;
        }

        const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[t]) >>> 0;
        e = d;
        d = c;
        c = ((b << 30) | (b >>> 2)) >>> 0;
        b = a;
        a = temp;
      }

      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
    }

    const out = new Uint8Array(20);
    const outView = new DataView(out.buffer);
    outView.setUint32(0, h0, false);
    outView.setUint32(4, h1, false);
    outView.setUint32(8, h2, false);
    outView.setUint32(12, h3, false);
    outView.setUint32(16, h4, false);
    return out;
  }

  // --------------------------------------------------------------------------
  // SHA-256 (FIPS PUB 180-4)
  // --------------------------------------------------------------------------

  private static readonly SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  /**
   * Computes standard 256-bit SHA-256 hash.
   * @param bytes Input byte array.
   * @returns 32-byte SHA-256 digest.
   */
  public static sha256(bytes: Uint8Array): Uint8Array {
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    const len = bytes.length;
    const bitLen = BigInt(len) * 8n;
    const padLen = len % 64 < 56 ? 56 - (len % 64) : 120 - (len % 64);
    const total = len + padLen + 8;
    const buf = new Uint8Array(total);
    buf.set(bytes, 0);
    buf[len] = 0x80;
    const view = new DataView(buf.buffer);
    view.setBigUint64(total - 8, bitLen, false);

    const w = new Uint32Array(64);
    for (let i = 0; i < total; i += 64) {
      for (let t = 0; t < 16; t++) {
        w[t] = view.getUint32(i + t * 4, false);
      }
      for (let t = 16; t < 64; t++) {
        const s0 =
          ((w[t - 15] >>> 7) | (w[t - 15] << 25)) ^
          ((w[t - 15] >>> 18) | (w[t - 15] << 14)) ^
          (w[t - 15] >>> 3);
        const s1 =
          ((w[t - 2] >>> 17) | (w[t - 2] << 15)) ^
          ((w[t - 2] >>> 19) | (w[t - 2] << 13)) ^
          (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
      }

      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let t = 0; t < 64; t++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + this.SHA256_K[t] + w[t]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }

      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
      h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0;
      h7 = (h7 + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    outView.setUint32(0, h0, false);
    outView.setUint32(4, h1, false);
    outView.setUint32(8, h2, false);
    outView.setUint32(12, h3, false);
    outView.setUint32(16, h4, false);
    outView.setUint32(20, h5, false);
    outView.setUint32(24, h6, false);
    outView.setUint32(28, h7, false);
    return out;
  }

  // --------------------------------------------------------------------------
  // AES-128 & AES-256 (FIPS PUB 197 / Rijndael Block Cipher)
  // --------------------------------------------------------------------------

  private static readonly AES_SBOX = new Uint8Array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
  ]);

  private static readonly AES_RCON = new Uint32Array([
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
  ]);

  private static subWord(w: number): number {
    return (
      ((this.AES_SBOX[(w >>> 24) & 0xff] << 24) |
        (this.AES_SBOX[(w >>> 16) & 0xff] << 16) |
        (this.AES_SBOX[(w >>> 8) & 0xff] << 8) |
        this.AES_SBOX[w & 0xff]) >>>
      0
    );
  }

  private static rotWord(w: number): number {
    return ((w << 8) | (w >>> 24)) >>> 0;
  }

  public static gmul(a: number, b: number): number {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      const hi = a & 0x80;
      a = (a << 1) & 0xff;
      if (hi) a ^= 0x1b;
      b >>>= 1;
    }
    return p;
  }

  /** Expands AES cipher key into round keys */
  public static aesKeyExpansion(keyBytes: Uint8Array): { w: Uint32Array; Nr: number } {
    const keyLen = keyBytes.length;
    const Nk = keyLen / 4;
    const Nr = Nk + 6;
    const w = new Uint32Array(4 * (Nr + 1));
    const view = new DataView(keyBytes.buffer, keyBytes.byteOffset, keyBytes.byteLength);

    for (let i = 0; i < Nk; i++) {
      w[i] = view.getUint32(i * 4, false);
    }

    for (let i = Nk; i < 4 * (Nr + 1); i++) {
      let temp = w[i - 1];
      if (i % Nk === 0) {
        temp = this.subWord(this.rotWord(temp)) ^ (this.AES_RCON[i / Nk] << 24);
      } else if (Nk > 6 && i % Nk === 4) {
        temp = this.subWord(temp);
      }
      w[i] = (w[i - Nk] ^ temp) >>> 0;
    }
    return { w, Nr };
  }

  /** Encrypts a single 16-byte block with AES */
  public static aesEncryptBlock(block: Uint8Array, roundKeys: Uint32Array, Nr: number): Uint8Array {
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

    addRoundKey(0);

    for (let round = 1; round < Nr; round++) {
      for (let i = 0; i < 16; i++) state[i] = this.AES_SBOX[state[i]];

      const t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
      const t2 = state[2], t6 = state[6]; state[2] = state[10]; state[6] = state[14]; state[10] = t2; state[14] = t6;
      const t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;

      for (let c = 0; c < 4; c++) {
        const idx = c * 4;
        const s0 = state[idx], s1 = state[idx + 1], s2 = state[idx + 2], s3 = state[idx + 3];
        state[idx + 0] = this.gmul(0x02, s0) ^ this.gmul(0x03, s1) ^ s2 ^ s3;
        state[idx + 1] = s0 ^ this.gmul(0x02, s1) ^ this.gmul(0x03, s2) ^ s3;
        state[idx + 2] = s0 ^ s1 ^ this.gmul(0x02, s2) ^ this.gmul(0x03, s3);
        state[idx + 3] = this.gmul(0x03, s0) ^ s1 ^ s2 ^ this.gmul(0x02, s3);
      }

      addRoundKey(round);
    }

    for (let i = 0; i < 16; i++) state[i] = this.AES_SBOX[state[i]];
    const t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
    const t2 = state[2], t6 = state[6]; state[2] = state[10]; state[6] = state[14]; state[10] = t2; state[14] = t6;
    const t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;
    addRoundKey(Nr);

    return state;
  }

  // --------------------------------------------------------------------------
  // Curve25519 / X25519 (RFC 7748 Montgomery Ladder)
  // --------------------------------------------------------------------------

  private static readonly CURVE25519_P = (1n << 255n) - 19n;
  private static readonly CURVE25519_A24 = 121665n;

  private static curveMod(a: bigint): bigint {
    const r = a % this.CURVE25519_P;
    return r < 0n ? r + this.CURVE25519_P : r;
  }

  private static curveInv(a: bigint): bigint {
    let res = 1n;
    let base = this.curveMod(a);
    let exp = this.CURVE25519_P - 2n;
    while (exp > 0n) {
      if (exp & 1n) res = this.curveMod(res * base);
      base = this.curveMod(base * base);
      exp >>= 1n;
    }
    return res;
  }

  private static decodeLE(bytes: Uint8Array): bigint {
    let res = 0n;
    for (let i = 0; i < bytes.length; i++) {
      res |= BigInt(bytes[i]) << BigInt(8 * i);
    }
    return res;
  }

  private static encodeLE(n: bigint, len: number = 32): Uint8Array {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      out[i] = Number((n >> BigInt(8 * i)) & 0xffn);
    }
    return out;
  }

  /**
   * RFC 7748 Section 5: X25519 Scalar Multiplication (Montgomery Ladder).
   * @param scalarBytes 32-byte private key scalar.
   * @param pointBytes 32-byte public key coordinate.
   */
  public static x25519ScalarMult(scalarBytes: Uint8Array, pointBytes: Uint8Array): Uint8Array {
    const s = new Uint8Array(scalarBytes);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;

    const k = this.decodeLE(s);
    const u = this.decodeLE(pointBytes) & ((1n << 255n) - 1n);

    const x_1 = u;
    let x_2 = 1n;
    let z_2 = 0n;
    let x_3 = u;
    let z_3 = 1n;
    let swap = 0n;

    for (let t = 254; t >= 0; t--) {
      const k_t = (k >> BigInt(t)) & 1n;
      swap ^= k_t;
      if (swap) {
        let tmp = x_2; x_2 = x_3; x_3 = tmp;
        tmp = z_2; z_2 = z_3; z_3 = tmp;
      }
      swap = k_t;

      const A = this.curveMod(x_2 + z_2);
      const AA = this.curveMod(A * A);
      const B = this.curveMod(x_2 - z_2);
      const BB = this.curveMod(B * B);
      const E = this.curveMod(AA - BB);
      const C = this.curveMod(x_3 + z_3);
      const D = this.curveMod(x_3 - z_3);
      const DA = this.curveMod(D * A);
      const CB = this.curveMod(C * B);
      x_3 = this.curveMod((DA + CB) * (DA + CB));
      z_3 = this.curveMod(x_1 * this.curveMod((DA - CB) * (DA - CB)));
      x_2 = this.curveMod(AA * BB);
      z_2 = this.curveMod(E * this.curveMod(AA + this.curveMod(this.CURVE25519_A24 * E)));
    }

    if (swap) {
      let tmp = x_2; x_2 = x_3; x_3 = tmp;
      tmp = z_2; z_2 = z_3; z_3 = tmp;
    }

    const result = this.curveMod(x_2 * this.curveInv(z_2));
    return this.encodeLE(result, 32);
  }

  /** Derives public key from X25519 private scalar */
  public static x25519GetPublic(scalarBytes: Uint8Array): Uint8Array {
    const basePoint = new Uint8Array(32);
    basePoint[0] = 9; // Generator u = 9
    return this.x25519ScalarMult(scalarBytes, basePoint);
  }

  /** Utility to concatenate byte arrays */
  public static concat(...arrays: Uint8Array[]): Uint8Array {
    let totalLen = 0;
    for (const a of arrays) totalLen += a.length;
    const res = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
      res.set(a, offset);
      offset += a.length;
    }
    return res;
  }
}
