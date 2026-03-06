/**
 * penumbra-crypto - Client-side E2E encryption using Web Crypto API
 *
 * This library provides:
 * - PBKDF2 key derivation from passphrases
 * - AES-256-GCM authenticated encryption
 * - ECDH P-256 key exchange for conversation encryption
 * - Group key management with per-member encryption
 *
 * All cryptographic operations use the Web Crypto API (SubtleCrypto).
 * No external dependencies. Works in browsers and Node.js 18+.
 *
 * @packageDocumentation
 */

// ============================================================================
// Constants
// ============================================================================

/** PBKDF2 iteration count - OWASP recommended minimum is 600,000 for SHA-256 */
export const PBKDF2_ITERATIONS = 100_000;

/** AES key length in bits */
export const KEY_LENGTH = 256;

/** AES-GCM IV/nonce length in bytes (96 bits as recommended by NIST) */
export const IV_LENGTH = 12;

/** ECDH curve identifier */
export const ECDH_CURVE = 'P-256';

/** HKDF info string for conversation key derivation */
export const HKDF_INFO = 'penumbra-conversation-v1';

// ============================================================================
// Types
// ============================================================================

/** Encrypted payload structure */
export interface EncryptedPayload {
  /** Initialization vector (12 bytes as number array) */
  iv: number[];
  /** Ciphertext (as number array) */
  data: number[];
}

/** ECDH key pair as JWK */
export interface ECDHKeyPair {
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert base64/base64url string to Uint8Array.
 * Handles both standard base64 and base64url encoding.
 *
 * @param base64url - Base64 or base64url encoded string
 * @returns Decoded bytes
 *
 * @example
 * ```ts
 * const bytes = base64ToBytes('SGVsbG8gV29ybGQ=');
 * // Uint8Array containing "Hello World"
 * ```
 */
export function base64ToBytes(base64url: string): Uint8Array {
  // Convert base64url to standard base64
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const pad = base64.length % 4;
  if (pad) {
    base64 += '='.repeat(4 - pad);
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert Uint8Array to base64 string.
 * Uses chunked processing to avoid "too many function arguments" error.
 *
 * @param bytes - Bytes to encode
 * @returns Base64 encoded string
 *
 * @example
 * ```ts
 * const encoded = bytesToBase64(new TextEncoder().encode('Hello'));
 * // "SGVsbG8="
 * ```
 */
export function bytesToBase64(bytes: Uint8Array): string {
  // Process in chunks to avoid stack overflow on large arrays
  const chunkSize = 8192;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, Array.from(chunk));
  }
  return btoa(binary);
}

// ============================================================================
// Key Derivation
// ============================================================================

/**
 * Derive an AES-256-GCM key from a passphrase using PBKDF2.
 *
 * Security properties:
 * - Uses SHA-256 as the hash function
 * - 100,000 iterations (adjustable via PBKDF2_ITERATIONS)
 * - Salt should be unique per user (16+ bytes recommended)
 * - Resulting key is non-extractable
 *
 * @param passphrase - User's encryption passphrase
 * @param salt - Salt bytes (should be unique per user, stored server-side)
 * @returns Derived AES-GCM CryptoKey
 *
 * @example
 * ```ts
 * const salt = crypto.getRandomValues(new Uint8Array(16));
 * const key = await deriveKey('my-secure-passphrase', salt);
 * ```
 */
export async function deriveKey(
  passphrase: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const encoder = new TextEncoder();

  // Import passphrase as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  // Derive AES-GCM key
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false, // Not extractable
    ['encrypt', 'decrypt']
  );
}

// ============================================================================
// AES-GCM Encryption
// ============================================================================

/**
 * Encrypt data with AES-256-GCM.
 *
 * Security properties:
 * - Random 96-bit IV generated per encryption
 * - Authenticated encryption (integrity + confidentiality)
 * - Data is JSON stringified before encryption
 *
 * @param data - Data to encrypt (will be JSON stringified)
 * @param key - AES-GCM key from deriveKey()
 * @returns Encrypted payload containing IV and ciphertext
 *
 * @example
 * ```ts
 * const encrypted = await encrypt({ secret: 'data' }, key);
 * // { iv: [...], data: [...] }
 * ```
 */
export async function encrypt(
  data: unknown,
  key: CryptoKey
): Promise<EncryptedPayload> {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(JSON.stringify(data))
  );

  return {
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(encrypted)),
  };
}

/**
 * Decrypt data with AES-256-GCM.
 *
 * @param encryptedObj - Encrypted payload from encrypt()
 * @param key - AES-GCM key from deriveKey()
 * @returns Decrypted data (JSON parsed)
 * @throws If decryption fails (wrong key or tampered data)
 *
 * @example
 * ```ts
 * const decrypted = await decrypt(encrypted, key);
 * // { secret: 'data' }
 * ```
 */
export async function decrypt(
  encryptedObj: EncryptedPayload,
  key: CryptoKey
): Promise<unknown> {
  const iv = new Uint8Array(encryptedObj.iv);
  const data = new Uint8Array(encryptedObj.data);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    data
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(decrypted));
}

// ============================================================================
// ECDH Key Exchange
// ============================================================================

/**
 * Generate an ECDH P-256 key pair for conversation encryption.
 *
 * The public key is shared with other users.
 * The private key should be encrypted and stored securely.
 *
 * @returns Key pair as JWK objects
 *
 * @example
 * ```ts
 * const { publicKeyJwk, privateKeyJwk } = await generateECDHKeyPair();
 * // Share publicKeyJwk with server
 * // Encrypt and store privateKeyJwk
 * ```
 */
export async function generateECDHKeyPair(): Promise<ECDHKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: ECDH_CURVE },
    true, // extractable - we need JWK export
    ['deriveBits']
  );

  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  return { publicKeyJwk, privateKeyJwk };
}

/**
 * Encrypt an ECDH private key JWK with a passphrase-derived key.
 *
 * Use this to securely store the ECDH private key.
 *
 * @param privateKeyJwk - ECDH private key as JWK
 * @param passphraseKey - AES-GCM key from PBKDF2
 * @returns Base64 encoded encrypted blob
 *
 * @example
 * ```ts
 * const encrypted = await encryptPrivateKey(privateKeyJwk, passphraseKey);
 * // Store encrypted on server
 * ```
 */
export async function encryptPrivateKey(
  privateKeyJwk: JsonWebKey,
  passphraseKey: CryptoKey
): Promise<string> {
  const encoded = new TextEncoder().encode(JSON.stringify(privateKeyJwk));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    passphraseKey,
    encoded
  );

  const payload: EncryptedPayload = {
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(ciphertext)),
  };
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(payload)));
}

/**
 * Decrypt an ECDH private key from encrypted blob.
 *
 * @param encryptedBase64 - Base64 encoded encrypted blob
 * @param passphraseKey - AES-GCM key from PBKDF2
 * @returns ECDH private key (non-extractable)
 *
 * @example
 * ```ts
 * const privateKey = await decryptPrivateKey(encryptedBlob, passphraseKey);
 * // Use for conversation key derivation
 * ```
 */
export async function decryptPrivateKey(
  encryptedBase64: string,
  passphraseKey: CryptoKey
): Promise<CryptoKey> {
  const encryptedJson = new TextDecoder().decode(base64ToBytes(encryptedBase64));
  const { iv, data } = JSON.parse(encryptedJson) as EncryptedPayload;

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv) },
    passphraseKey,
    new Uint8Array(data)
  );

  const jwk = JSON.parse(new TextDecoder().decode(decrypted)) as JsonWebKey;
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDH', namedCurve: ECDH_CURVE },
    false, // non-extractable once imported
    ['deriveBits']
  );
}

/**
 * Derive a conversation AES-GCM key from ECDH shared secret.
 *
 * Both parties derive the same key:
 * - ECDH(Alice_priv, Bob_pub) === ECDH(Bob_priv, Alice_pub)
 *
 * Uses HKDF to stretch the ECDH output into a proper AES key.
 *
 * @param myPrivateKey - My ECDH private key
 * @param theirPublicKeyJwk - Other user's ECDH public key as JWK
 * @returns AES-GCM conversation key
 *
 * @example
 * ```ts
 * const conversationKey = await deriveConversationKey(myPrivKey, theirPubKey);
 * // Both parties derive the same key
 * ```
 */
export async function deriveConversationKey(
  myPrivateKey: CryptoKey,
  theirPublicKeyJwk: JsonWebKey
): Promise<CryptoKey> {
  const theirPublicKey = await crypto.subtle.importKey(
    'jwk',
    theirPublicKeyJwk,
    { name: 'ECDH', namedCurve: ECDH_CURVE },
    false,
    []
  );

  // ECDH -> 256 bits of shared secret
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: theirPublicKey },
    myPrivateKey,
    256
  );

  // HKDF to stretch into a proper AES-GCM key
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    sharedBits,
    'HKDF',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(HKDF_INFO),
    },
    hkdfKey,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data for a conversation (AES-GCM with random IV).
 *
 * @param data - Data to encrypt (will be JSON stringified)
 * @param conversationKey - AES-GCM key from deriveConversationKey()
 * @returns Base64 encoded encrypted payload
 */
export async function encryptForConversation(
  data: unknown,
  conversationKey: CryptoKey
): Promise<string> {
  const encrypted = await encrypt(data, conversationKey);
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(encrypted)));
}

/**
 * Decrypt conversation data.
 *
 * @param encryptedBase64 - Base64 encoded encrypted payload
 * @param conversationKey - AES-GCM key
 * @returns Decrypted data (JSON parsed)
 */
export async function decryptFromConversation(
  encryptedBase64: string,
  conversationKey: CryptoKey
): Promise<unknown> {
  const encryptedJson = new TextDecoder().decode(base64ToBytes(encryptedBase64));
  const encryptedObj = JSON.parse(encryptedJson) as EncryptedPayload;
  return decrypt(encryptedObj, conversationKey);
}

// ============================================================================
// Group Key Management
// ============================================================================

/**
 * Generate a random AES-256-GCM key for a new group.
 *
 * The group key is shared with all members by encrypting it
 * individually for each member using ECDH.
 *
 * @returns Random AES-GCM key (extractable for sharing)
 */
export async function generateGroupKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: KEY_LENGTH },
    true, // Extractable (needed to encrypt for members)
    ['encrypt', 'decrypt']
  );
}

/**
 * Export a group key to raw bytes for encryption.
 *
 * @param groupKey - The group key
 * @returns Raw key bytes (32 bytes for AES-256)
 */
export async function exportGroupKey(groupKey: CryptoKey): Promise<Uint8Array> {
  const rawKey = await crypto.subtle.exportKey('raw', groupKey);
  return new Uint8Array(rawKey);
}

/**
 * Import a group key from raw bytes.
 *
 * @param keyBytes - Raw key bytes
 * @returns Imported AES-GCM key (non-extractable)
 */
export async function importGroupKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false, // Not extractable after import
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a group key for a member using ECDH.
 *
 * @param groupKey - The group key to encrypt
 * @param myPrivateKey - Sender's ECDH private key
 * @param memberPublicKeyJwk - Member's ECDH public key JWK
 * @returns Base64 encrypted group key
 */
export async function encryptGroupKeyForMember(
  groupKey: CryptoKey,
  myPrivateKey: CryptoKey,
  memberPublicKeyJwk: JsonWebKey
): Promise<string> {
  // Export the group key as raw bytes
  const groupKeyBytes = await exportGroupKey(groupKey);

  // Derive shared secret with member
  const sharedKey = await deriveConversationKey(myPrivateKey, memberPublicKeyJwk);

  // Encrypt group key with shared secret
  return encryptForConversation(Array.from(groupKeyBytes), sharedKey);
}

/**
 * Decrypt a group key using ECDH.
 *
 * @param encryptedKeyBase64 - Base64 encrypted group key
 * @param myPrivateKey - Recipient's ECDH private key
 * @param senderPublicKeyJwk - Sender's ECDH public key JWK
 * @returns Decrypted group key
 */
export async function decryptGroupKey(
  encryptedKeyBase64: string,
  myPrivateKey: CryptoKey,
  senderPublicKeyJwk: JsonWebKey
): Promise<CryptoKey> {
  // Derive shared secret with sender
  const sharedKey = await deriveConversationKey(myPrivateKey, senderPublicKeyJwk);

  // Decrypt group key bytes
  const keyBytesArray = (await decryptFromConversation(
    encryptedKeyBase64,
    sharedKey
  )) as number[];
  const keyBytes = new Uint8Array(keyBytesArray);

  // Import as CryptoKey
  return importGroupKey(keyBytes);
}

// ============================================================================
// Key Manager Class
// ============================================================================

/**
 * Session key manager for managing encryption keys.
 *
 * Stores derived keys in memory. Provides high-level methods
 * for encryption/decryption operations.
 *
 * @example
 * ```ts
 * const keyManager = new KeyManager();
 *
 * // Initialize with passphrase
 * await keyManager.init(saltBase64, 'my-passphrase');
 *
 * // Encrypt/decrypt data
 * const encrypted = await keyManager.encrypt({ secret: 'data' });
 * const decrypted = await keyManager.decrypt(encrypted);
 *
 * // Initialize ECDH for conversations
 * await keyManager.initECDH(encryptedPrivateKeyBlob);
 *
 * // Encrypt for another user
 * const msg = await keyManager.encryptForConnection(data, connId, theirPubKey);
 * ```
 */
export class KeyManager {
  private _key: CryptoKey | null = null;
  private _salt: Uint8Array | null = null;
  private _ecdhPrivateKey: CryptoKey | null = null;
  private _conversationKeys = new Map<string, CryptoKey>();
  private _groupKeys = new Map<string, CryptoKey>();

  /**
   * Initialize with user's salt and passphrase.
   *
   * @param saltBase64 - Base64 encoded salt from server
   * @param passphrase - User's encryption passphrase
   */
  async init(saltBase64: string, passphrase: string): Promise<void> {
    this._salt = base64ToBytes(saltBase64);
    this._key = await deriveKey(passphrase, this._salt);
  }

  /**
   * Check if key is loaded.
   */
  isUnlocked(): boolean {
    return this._key !== null;
  }

  /**
   * Encrypt data using stored key.
   *
   * @param data - Data to encrypt
   * @returns Base64 encoded encrypted payload
   */
  async encrypt(data: unknown): Promise<string> {
    if (!this._key) throw new Error('Key not initialized');
    const encrypted = await encrypt(data, this._key);
    return bytesToBase64(new TextEncoder().encode(JSON.stringify(encrypted)));
  }

  /**
   * Decrypt data using stored key.
   *
   * @param encryptedBase64 - Base64 encoded encrypted payload
   * @returns Decrypted data
   */
  async decrypt(encryptedBase64: string): Promise<unknown> {
    if (!this._key) throw new Error('Key not initialized');
    const encryptedJson = new TextDecoder().decode(base64ToBytes(encryptedBase64));
    const encryptedObj = JSON.parse(encryptedJson) as EncryptedPayload;
    return decrypt(encryptedObj, this._key);
  }

  /**
   * Initialize ECDH private key from encrypted blob.
   *
   * @param encryptedPrivateKeyBlob - Base64 encrypted ECDH private key
   */
  async initECDH(encryptedPrivateKeyBlob: string): Promise<void> {
    if (!this._key) throw new Error('Passphrase key not initialized');
    this._ecdhPrivateKey = await decryptPrivateKey(encryptedPrivateKeyBlob, this._key);
    this._conversationKeys.clear();
  }

  /**
   * Check if ECDH is ready for conversation encryption.
   */
  hasECDH(): boolean {
    return this._ecdhPrivateKey !== null;
  }

  /**
   * Get (or derive and cache) conversation key for a connection.
   *
   * @param connectionId - Connection ID for cache key
   * @param theirPublicKeyJwk - Other user's ECDH public key JWK
   * @returns AES-GCM conversation key
   */
  async getConversationKey(
    connectionId: string,
    theirPublicKeyJwk: JsonWebKey
  ): Promise<CryptoKey> {
    if (!this._ecdhPrivateKey) throw new Error('ECDH not initialized');

    if (!this._conversationKeys.has(connectionId)) {
      const key = await deriveConversationKey(this._ecdhPrivateKey, theirPublicKeyJwk);
      this._conversationKeys.set(connectionId, key);
    }
    return this._conversationKeys.get(connectionId)!;
  }

  /**
   * Encrypt data for a conversation.
   */
  async encryptForConnection(
    data: unknown,
    connectionId: string,
    theirPublicKeyJwk: JsonWebKey
  ): Promise<string> {
    const key = await this.getConversationKey(connectionId, theirPublicKeyJwk);
    return encryptForConversation(data, key);
  }

  /**
   * Decrypt data from a conversation.
   */
  async decryptForConnection(
    encryptedBase64: string,
    connectionId: string,
    theirPublicKeyJwk: JsonWebKey
  ): Promise<unknown> {
    const key = await this.getConversationKey(connectionId, theirPublicKeyJwk);
    return decryptFromConversation(encryptedBase64, key);
  }

  /**
   * Clear all keys from memory.
   */
  lock(): void {
    this._key = null;
    this._salt = null;
    this._ecdhPrivateKey = null;
    this._conversationKeys.clear();
    this._groupKeys.clear();
  }

  // Group key methods

  /**
   * Cache a group key.
   */
  cacheGroupKey(groupId: string, groupKey: CryptoKey): void {
    this._groupKeys.set(groupId, groupKey);
  }

  /**
   * Get cached group key.
   */
  getGroupKey(groupId: string): CryptoKey | null {
    return this._groupKeys.get(groupId) ?? null;
  }

  /**
   * Encrypt group key for self (for storage).
   */
  async encryptGroupKeyForSelf(groupKey: CryptoKey): Promise<string> {
    if (!this._key) throw new Error('Key not initialized');
    const keyBytes = await exportGroupKey(groupKey);
    const encrypted = await encrypt(Array.from(keyBytes), this._key);
    return bytesToBase64(new TextEncoder().encode(JSON.stringify(encrypted)));
  }

  /**
   * Decrypt group key encrypted for self.
   */
  async decryptGroupKeyForSelf(encryptedBase64: string): Promise<CryptoKey> {
    if (!this._key) throw new Error('Key not initialized');
    const encryptedJson = new TextDecoder().decode(base64ToBytes(encryptedBase64));
    const encryptedObj = JSON.parse(encryptedJson) as EncryptedPayload;
    const keyBytesArray = (await decrypt(encryptedObj, this._key)) as number[];
    return importGroupKey(new Uint8Array(keyBytesArray));
  }

  /**
   * Encrypt data for a group.
   */
  async encryptForGroup(data: unknown, groupId: string): Promise<string> {
    const key = this._groupKeys.get(groupId);
    if (!key) throw new Error(`Group key not loaded for ${groupId}`);
    return encryptForConversation(data, key);
  }

  /**
   * Decrypt data from a group.
   */
  async decryptFromGroup(encryptedBase64: string, groupId: string): Promise<unknown> {
    const key = this._groupKeys.get(groupId);
    if (!key) throw new Error(`Group key not loaded for ${groupId}`);
    return decryptFromConversation(encryptedBase64, key);
  }
}
