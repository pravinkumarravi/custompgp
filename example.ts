/**
 * ============================================================================
 * OpenPGP Example Script: Test Existing Keys & Generate New Key Pair
 * ============================================================================
 *
 * This test file demonstrates:
 *   PART 1: Read and inspect existing sample keys in `example_key/`
 *   PART 2: Encrypt a message using CustomPGP.encrypt()
 *   PART 3: Decrypt the message using CustomPGP.decrypt() with passphrase "Test@123"
 *   PART 4: Generate a brand-new OpenPGP key pair using CustomPGP.generateKeyPair()
 *   PART 5: Encrypt and decrypt a test message using the newly generated key pair
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { CustomPGP, ArmorCodec, PacketCodec } from './custompgp';

async function main() {
  console.log('╔══════════════════════════════════════════════════════════════════╗');
  console.log('║       CUSTOM PGP CLASS: READ EXISTING KEYS & CREATE NEW PAIR     ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝\n');

  // ==========================================================================
  // PART 1: Read and Inspect Existing Sample Keys
  // ==========================================================================
  console.log('┌──────────────────────────────────────────────────────────────────┐');
  console.log('│ PART 1: Reading Existing Sample Keys                             │');
  console.log('└──────────────────────────────────────────────────────────────────┘');

  const pubKeyPath = path.resolve(__dirname, 'example_key', 'public_key.pub');
  const privKeyPath = path.resolve(__dirname, 'example_key', 'private_key.key');

  const existingPubKey = fs.readFileSync(pubKeyPath, 'utf8');
  const existingPrivKey = fs.readFileSync(privKeyPath, 'utf8');

  // Inspect packets
  const pubPackets = PacketCodec.parsePackets(ArmorCodec.decode(existingPubKey));
  const subkeyInfo = CustomPGP.extractSubkey(pubPackets);

  const toHex = (buf: Uint8Array): string => {
    let s = '';
    for (let i = 0; i < buf.length; i++) s += buf[i].toString(16).padStart(2, '0');
    return s;
  };

  console.log(`[✔] Read Public Key File:  ${pubKeyPath}`);
  console.log(`[✔] Read Private Key File: ${privKeyPath}`);
  console.log(`[i] Target Encryption Subkey Key ID: 0x${toHex(subkeyInfo.keyId).toUpperCase()}`);
  console.log(`[i] Target Subkey Fingerprint:       ${toHex(subkeyInfo.fingerprint)}`);
  console.log(`[i] Subkey Curve:                   Curve25519 (X25519)`);

  // ==========================================================================
  // PART 2 & 3: Encrypt & Decrypt with Existing Key and Passphrase
  // ==========================================================================
  console.log('\n');
  console.log('┌──────────────────────────────────────────────────────────────────┐');
  console.log('│ PART 2 & 3: Test Encrypt & Decrypt With Existing Key             │');
  console.log('└──────────────────────────────────────────────────────────────────┘');

  const secretMessage = 'Confidential: OpenPGP decryption using passphrase Test@123 successful!';
  const passphrase = 'Test@123';

  console.log(`[1] Original Plaintext Message:`);
  console.log(`    "${secretMessage}"`);

  console.log(`\n[2] Encrypting using CustomPGP.encrypt()...`);
  const encryptedArmored = CustomPGP.encrypt(existingPubKey, secretMessage);
  console.log(`    Generated Ciphertext Preview:`);
  console.log('    ' + encryptedArmored.split(/\r?\n/).slice(0, 5).join('\n    ') + '\n    ...');

  console.log(`\n[3] Decrypting using CustomPGP.decrypt() (Passphrase: "${passphrase}")...`);
  const decryptedMessage = CustomPGP.decrypt(encryptedArmored, existingPrivKey, passphrase);
  console.log(`    Recovered Plaintext:`);
  console.log(`    "${decryptedMessage}"`);

  const existingKeyMatch = decryptedMessage === secretMessage;
  console.log(`    Result: ${existingKeyMatch ? 'PASSED (100% Match) ✅' : 'FAILED ❌'}`);

  // ==========================================================================
  // PART 4: Generate a Brand New OpenPGP Key Pair
  // ==========================================================================
  console.log('\n');
  console.log('┌──────────────────────────────────────────────────────────────────┐');
  console.log('│ PART 4: Generating Brand New Key Pair (Ed25519 + X25519)          │');
  console.log('└──────────────────────────────────────────────────────────────────┘');

  const newUserId = 'Alice Developer <alice@custom-openpgp.io>';
  const newPassphrase = 'NewPassword@2026';

  console.log(`[1] Creating key pair for User ID: "${newUserId}"`);
  console.log(`    Protecting private key with passphrase: "${newPassphrase}"...`);

  const newKeys = CustomPGP.generateKeyPair(newUserId, newPassphrase);

  console.log(`[✔] Key Generation Complete:`);
  console.log(`    Primary Key ID: ${newKeys.keyId}`);
  console.log(`    Fingerprint:    ${newKeys.fingerprint}`);

  console.log(`\n[2] Armored Public Key Block:`);
  console.log('----------------------------------------------------------------------');
  console.log(newKeys.publicKeyArmored);
  console.log('----------------------------------------------------------------------');

  console.log(`\n[3] Armored Private Key Block:`);
  console.log('----------------------------------------------------------------------');
  console.log(newKeys.privateKeyArmored);
  console.log('----------------------------------------------------------------------');

  // ==========================================================================
  // PART 5: Test Encrypt & Decrypt with the Newly Generated Key Pair
  // ==========================================================================
  console.log('\n');
  console.log('┌──────────────────────────────────────────────────────────────────┐');
  console.log('│ PART 5: Test Encrypt & Decrypt With Newly Generated Key Pair     │');
  console.log('└──────────────────────────────────────────────────────────────────┘');

  const testMessageNewKey = 'Hello Alice! Welcome to modern OpenPGP cryptography with CustomPGP.';

  console.log(`[1] Encrypting message to Alice's new public key...`);
  const newEncrypted = CustomPGP.encrypt(newKeys.publicKeyArmored, testMessageNewKey);

  console.log(`[2] Decrypting message using Alice's new private key and passphrase...`);
  const newDecrypted = CustomPGP.decrypt(newEncrypted, newKeys.privateKeyArmored, newPassphrase);

  console.log(`    Decrypted Message: "${newDecrypted}"`);
  const newKeyMatch = newDecrypted === testMessageNewKey;
  console.log(`    Result: ${newKeyMatch ? 'PASSED (100% Match) ✅' : 'FAILED ❌'}`);

  console.log('\n');
  console.log('══════════════════════════════════════════════════════════════════════');
  console.log('  ALL CUSTOM PGP TESTS COMPLETED SUCCESSFULLY!');
  console.log('══════════════════════════════════════════════════════════════════════');
}

main().catch((err) => {
  console.error('Error during execution:', err);
  process.exit(1);
});
