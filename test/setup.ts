import { webcrypto } from 'node:crypto';

// Polyfill global crypto for Node.js test environment
if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = webcrypto as unknown as Crypto;
}

// Expose CryptoKey globally for instanceof checks
if (typeof globalThis.CryptoKey === 'undefined') {
  globalThis.CryptoKey = webcrypto.CryptoKey as unknown as typeof CryptoKey;
}
