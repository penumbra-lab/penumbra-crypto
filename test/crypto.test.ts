/**
 * Test suite for penumbra-crypto
 *
 * These tests serve as both validation and documentation of the expected behavior.
 * Test vectors can be used to verify compatibility with other implementations.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  deriveKey,
  encrypt,
  decrypt,
  base64ToBytes,
  bytesToBase64,
  generateECDHKeyPair,
  encryptPrivateKey,
  decryptPrivateKey,
  deriveConversationKey,
  encryptForConversation,
  decryptFromConversation,
  generateGroupKey,
  exportGroupKey,
  importGroupKey,
  encryptGroupKeyForMember,
  decryptGroupKey,
  KeyManager,
  PBKDF2_ITERATIONS,
  KEY_LENGTH,
  IV_LENGTH,
  ECDH_CURVE,
} from '../src/index';

// ============================================================================
// Test Vectors
// ============================================================================

/**
 * Known test vectors for verifying implementation correctness.
 * These can be used by other implementations to verify compatibility.
 */
const TEST_VECTORS = {
  // Base64 encoding
  base64: {
    input: 'Hello, World!',
    encoded: 'SGVsbG8sIFdvcmxkIQ==',
  },

  // PBKDF2 (for reference - actual test uses Web Crypto)
  pbkdf2: {
    passphrase: 'test-passphrase-123',
    saltBase64: 'dGVzdC1zYWx0LXZhbHVl', // "test-salt-value"
    iterations: PBKDF2_ITERATIONS,
    keyLength: KEY_LENGTH,
  },
};

// ============================================================================
// Utility Function Tests
// ============================================================================

describe('Base64 Utilities', () => {
  it('should encode bytes to base64', () => {
    const input = new TextEncoder().encode(TEST_VECTORS.base64.input);
    const result = bytesToBase64(input);
    expect(result).toBe(TEST_VECTORS.base64.encoded);
  });

  it('should decode base64 to bytes', () => {
    const result = base64ToBytes(TEST_VECTORS.base64.encoded);
    const decoded = new TextDecoder().decode(result);
    expect(decoded).toBe(TEST_VECTORS.base64.input);
  });

  it('should handle base64url encoding', () => {
    // base64url uses - and _ instead of + and /
    const base64url = 'SGVsbG8tV29ybGRf'; // Contains - and _
    const result = base64ToBytes(base64url);
    expect(result).toBeInstanceOf(Uint8Array);
  });

  it('should handle large arrays without stack overflow', () => {
    // Create a large array (100KB) - fill manually since getRandomValues has 64KB limit
    const largeArray = new Uint8Array(100 * 1024);
    for (let i = 0; i < largeArray.length; i++) {
      largeArray[i] = i % 256;
    }

    const encoded = bytesToBase64(largeArray);
    const decoded = base64ToBytes(encoded);

    expect(decoded).toEqual(largeArray);
  });
});

// ============================================================================
// Key Derivation Tests
// ============================================================================

describe('Key Derivation (PBKDF2)', () => {
  it('should derive a key from passphrase and salt', async () => {
    const salt = base64ToBytes(TEST_VECTORS.pbkdf2.saltBase64);
    const key = await deriveKey(TEST_VECTORS.pbkdf2.passphrase, salt);

    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.type).toBe('secret');
    expect(key.algorithm.name).toBe('AES-GCM');
    expect(key.extractable).toBe(false);
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');
  });

  it('should derive the same key for same passphrase and salt', async () => {
    const salt = base64ToBytes(TEST_VECTORS.pbkdf2.saltBase64);
    const key1 = await deriveKey(TEST_VECTORS.pbkdf2.passphrase, salt);
    const key2 = await deriveKey(TEST_VECTORS.pbkdf2.passphrase, salt);

    // Encrypt with key1, decrypt with key2
    const testData = { test: 'deterministic derivation' };
    const encrypted = await encrypt(testData, key1);
    const decrypted = await decrypt(encrypted, key2);

    expect(decrypted).toEqual(testData);
  });

  it('should derive different keys for different passphrases', async () => {
    const salt = base64ToBytes(TEST_VECTORS.pbkdf2.saltBase64);
    const key1 = await deriveKey('passphrase-1', salt);
    const key2 = await deriveKey('passphrase-2', salt);

    const testData = { test: 'different keys' };
    const encrypted = await encrypt(testData, key1);

    await expect(decrypt(encrypted, key2)).rejects.toThrow();
  });

  it('should derive different keys for different salts', async () => {
    const salt1 = new TextEncoder().encode('salt-1');
    const salt2 = new TextEncoder().encode('salt-2');
    const key1 = await deriveKey(TEST_VECTORS.pbkdf2.passphrase, salt1);
    const key2 = await deriveKey(TEST_VECTORS.pbkdf2.passphrase, salt2);

    const testData = { test: 'different salts' };
    const encrypted = await encrypt(testData, key1);

    await expect(decrypt(encrypted, key2)).rejects.toThrow();
  });
});

// ============================================================================
// AES-GCM Encryption Tests
// ============================================================================

describe('AES-GCM Encryption', () => {
  let key: CryptoKey;

  beforeEach(async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    key = await deriveKey('test-passphrase', salt);
  });

  it('should encrypt and decrypt data', async () => {
    const testData = { message: 'Hello, World!', number: 42 };
    const encrypted = await encrypt(testData, key);
    const decrypted = await decrypt(encrypted, key);

    expect(decrypted).toEqual(testData);
  });

  it('should produce different ciphertext each time (random IV)', async () => {
    const testData = { message: 'same data' };
    const encrypted1 = await encrypt(testData, key);
    const encrypted2 = await encrypt(testData, key);

    // IVs should be different
    expect(encrypted1.iv).not.toEqual(encrypted2.iv);
    // Ciphertext should be different
    expect(encrypted1.data).not.toEqual(encrypted2.data);
  });

  it('should use correct IV length', async () => {
    const encrypted = await encrypt({ test: true }, key);
    expect(encrypted.iv.length).toBe(IV_LENGTH);
  });

  it('should detect tampered data', async () => {
    const encrypted = await encrypt({ secret: 'data' }, key);

    // Tamper with the ciphertext
    encrypted.data[0] ^= 0xff;

    await expect(decrypt(encrypted, key)).rejects.toThrow();
  });

  it('should handle empty objects', async () => {
    const encrypted = await encrypt({}, key);
    const decrypted = await decrypt(encrypted, key);
    expect(decrypted).toEqual({});
  });

  it('should handle arrays', async () => {
    const testData = [1, 2, 3, 'four', { five: 5 }];
    const encrypted = await encrypt(testData, key);
    const decrypted = await decrypt(encrypted, key);
    expect(decrypted).toEqual(testData);
  });

  it('should handle nested objects', async () => {
    const testData = {
      level1: {
        level2: {
          level3: {
            value: 'deep nesting',
          },
        },
      },
    };
    const encrypted = await encrypt(testData, key);
    const decrypted = await decrypt(encrypted, key);
    expect(decrypted).toEqual(testData);
  });
});

// ============================================================================
// ECDH Key Exchange Tests
// ============================================================================

describe('ECDH Key Exchange', () => {
  it('should generate a valid key pair', async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateECDHKeyPair();

    expect(publicKeyJwk.kty).toBe('EC');
    expect(publicKeyJwk.crv).toBe(ECDH_CURVE);
    expect(publicKeyJwk.x).toBeDefined();
    expect(publicKeyJwk.y).toBeDefined();
    expect(publicKeyJwk.d).toBeUndefined(); // Public key has no 'd'

    expect(privateKeyJwk.kty).toBe('EC');
    expect(privateKeyJwk.crv).toBe(ECDH_CURVE);
    expect(privateKeyJwk.d).toBeDefined(); // Private key has 'd'
  });

  it('should encrypt and decrypt private key', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passphraseKey = await deriveKey('test-passphrase', salt);
    const { privateKeyJwk } = await generateECDHKeyPair();

    const encrypted = await encryptPrivateKey(privateKeyJwk, passphraseKey);
    expect(typeof encrypted).toBe('string');

    const decrypted = await decryptPrivateKey(encrypted, passphraseKey);
    expect(decrypted).toBeInstanceOf(CryptoKey);
    expect(decrypted.type).toBe('private');
    expect(decrypted.algorithm.name).toBe('ECDH');
  });

  it('should derive the same conversation key for both parties', async () => {
    const alice = await generateECDHKeyPair();
    const bob = await generateECDHKeyPair();

    // Import private keys
    const alicePrivate = await crypto.subtle.importKey(
      'jwk',
      alice.privateKeyJwk,
      { name: 'ECDH', namedCurve: ECDH_CURVE },
      false,
      ['deriveBits']
    );
    const bobPrivate = await crypto.subtle.importKey(
      'jwk',
      bob.privateKeyJwk,
      { name: 'ECDH', namedCurve: ECDH_CURVE },
      false,
      ['deriveBits']
    );

    // Alice derives key using Bob's public key
    const aliceKey = await deriveConversationKey(alicePrivate, bob.publicKeyJwk);
    // Bob derives key using Alice's public key
    const bobKey = await deriveConversationKey(bobPrivate, alice.publicKeyJwk);

    // Both should be able to decrypt each other's messages
    const testData = { secret: 'shared secret' };
    const encrypted = await encryptForConversation(testData, aliceKey);
    const decrypted = await decryptFromConversation(encrypted, bobKey);

    expect(decrypted).toEqual(testData);
  });
});

// ============================================================================
// Group Key Tests
// ============================================================================

describe('Group Key Management', () => {
  it('should generate a group key', async () => {
    const groupKey = await generateGroupKey();

    expect(groupKey).toBeInstanceOf(CryptoKey);
    expect(groupKey.type).toBe('secret');
    expect(groupKey.algorithm.name).toBe('AES-GCM');
    expect(groupKey.extractable).toBe(true); // Needed for sharing
  });

  it('should export and import group key', async () => {
    const originalKey = await generateGroupKey();
    const exported = await exportGroupKey(originalKey);

    expect(exported).toBeInstanceOf(Uint8Array);
    expect(exported.length).toBe(32); // 256 bits

    const imported = await importGroupKey(exported);
    expect(imported).toBeInstanceOf(CryptoKey);
    expect(imported.extractable).toBe(false); // Non-extractable after import

    // Verify keys work the same
    const testData = { group: 'message' };
    const encrypted = await encryptForConversation(testData, originalKey);
    const decrypted = await decryptFromConversation(encrypted, imported);

    expect(decrypted).toEqual(testData);
  });

  it('should encrypt group key for member using ECDH', async () => {
    const owner = await generateECDHKeyPair();
    const member = await generateECDHKeyPair();

    const ownerPrivate = await crypto.subtle.importKey(
      'jwk',
      owner.privateKeyJwk,
      { name: 'ECDH', namedCurve: ECDH_CURVE },
      false,
      ['deriveBits']
    );
    const memberPrivate = await crypto.subtle.importKey(
      'jwk',
      member.privateKeyJwk,
      { name: 'ECDH', namedCurve: ECDH_CURVE },
      false,
      ['deriveBits']
    );

    // Owner creates group key and encrypts for member
    const groupKey = await generateGroupKey();
    const encryptedForMember = await encryptGroupKeyForMember(
      groupKey,
      ownerPrivate,
      member.publicKeyJwk
    );

    // Member decrypts group key
    const decryptedKey = await decryptGroupKey(
      encryptedForMember,
      memberPrivate,
      owner.publicKeyJwk
    );

    // Verify both keys work the same
    const testData = { group: 'secret message' };
    const encrypted = await encryptForConversation(testData, groupKey);
    const decrypted = await decryptFromConversation(encrypted, decryptedKey);

    expect(decrypted).toEqual(testData);
  });
});

// ============================================================================
// KeyManager Tests
// ============================================================================

describe('KeyManager', () => {
  let keyManager: KeyManager;
  const testSalt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
  const testPassphrase = 'test-passphrase-123';

  beforeEach(() => {
    keyManager = new KeyManager();
  });

  it('should initialize with passphrase', async () => {
    expect(keyManager.isUnlocked()).toBe(false);
    await keyManager.init(testSalt, testPassphrase);
    expect(keyManager.isUnlocked()).toBe(true);
  });

  it('should encrypt and decrypt data', async () => {
    await keyManager.init(testSalt, testPassphrase);

    const testData = { secret: 'manager test' };
    const encrypted = await keyManager.encrypt(testData);
    const decrypted = await keyManager.decrypt(encrypted);

    expect(decrypted).toEqual(testData);
  });

  it('should throw when not initialized', async () => {
    await expect(keyManager.encrypt({ test: true })).rejects.toThrow(
      'Key not initialized'
    );
  });

  it('should lock and clear keys', async () => {
    await keyManager.init(testSalt, testPassphrase);
    expect(keyManager.isUnlocked()).toBe(true);

    keyManager.lock();
    expect(keyManager.isUnlocked()).toBe(false);
  });

  it('should initialize ECDH', async () => {
    await keyManager.init(testSalt, testPassphrase);
    expect(keyManager.hasECDH()).toBe(false);

    // Generate and encrypt a key pair
    const { privateKeyJwk } = await generateECDHKeyPair();
    const salt = base64ToBytes(testSalt);
    const passphraseKey = await deriveKey(testPassphrase, salt);
    const encryptedPrivKey = await encryptPrivateKey(privateKeyJwk, passphraseKey);

    await keyManager.initECDH(encryptedPrivKey);
    expect(keyManager.hasECDH()).toBe(true);
  });

  it('should cache and retrieve group keys', async () => {
    await keyManager.init(testSalt, testPassphrase);

    const groupKey = await generateGroupKey();
    const groupId = 'test-group-123';

    expect(keyManager.getGroupKey(groupId)).toBeNull();
    keyManager.cacheGroupKey(groupId, groupKey);
    expect(keyManager.getGroupKey(groupId)).toBe(groupKey);
  });

  it('should encrypt/decrypt group key for self', async () => {
    await keyManager.init(testSalt, testPassphrase);

    const groupKey = await generateGroupKey();
    const encrypted = await keyManager.encryptGroupKeyForSelf(groupKey);
    const decrypted = await keyManager.decryptGroupKeyForSelf(encrypted);

    // Verify both keys work
    const testData = { group: 'self-encrypted' };
    const encryptedData = await encryptForConversation(testData, groupKey);
    const decryptedData = await decryptFromConversation(encryptedData, decrypted);

    expect(decryptedData).toEqual(testData);
  });
});

// ============================================================================
// Security Tests
// ============================================================================

describe('Security Properties', () => {
  it('should use minimum recommended PBKDF2 iterations', () => {
    // OWASP recommends minimum 600,000 for SHA-256
    // We use 100,000 as a balance between security and UX
    expect(PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(100_000);
  });

  it('should use AES-256', () => {
    expect(KEY_LENGTH).toBe(256);
  });

  it('should use recommended IV length for AES-GCM', () => {
    // NIST recommends 96 bits (12 bytes) for AES-GCM
    expect(IV_LENGTH).toBe(12);
  });

  it('should use approved ECDH curve', () => {
    // P-256 is NIST approved and widely supported
    expect(ECDH_CURVE).toBe('P-256');
  });
});
