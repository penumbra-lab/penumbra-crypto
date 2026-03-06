# penumbra-crypto

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Client-side end-to-end encryption library using the Web Crypto API.

## Features

- **PBKDF2 key derivation** - Derive encryption keys from passphrases
- **AES-256-GCM encryption** - Authenticated encryption for data
- **ECDH key exchange** - Establish shared secrets between users
- **Group key management** - Encrypt content for multiple recipients
- **Zero dependencies** - Uses only the Web Crypto API
- **TypeScript** - Full type definitions included

## Installation

```bash
npm install penumbra-crypto
```

## Quick Start

```typescript
import { KeyManager, generateECDHKeyPair } from 'penumbra-crypto';

// Initialize with user's passphrase
const keyManager = new KeyManager();
await keyManager.init(saltBase64, 'user-passphrase');

// Encrypt data
const encrypted = await keyManager.encrypt({ secret: 'data' });

// Decrypt data
const decrypted = await keyManager.decrypt(encrypted);
```

## API Overview

### Key Derivation

```typescript
import { deriveKey } from 'penumbra-crypto';

// Derive AES-256 key from passphrase
const salt = crypto.getRandomValues(new Uint8Array(16));
const key = await deriveKey('my-passphrase', salt);
```

### Symmetric Encryption

```typescript
import { encrypt, decrypt } from 'penumbra-crypto';

// Encrypt any JSON-serializable data
const encrypted = await encrypt({ message: 'Hello' }, key);

// Decrypt
const decrypted = await decrypt(encrypted, key);
```

### ECDH Key Exchange

```typescript
import {
  generateECDHKeyPair,
  deriveConversationKey,
  encryptForConversation,
  decryptFromConversation
} from 'penumbra-crypto';

// Generate key pair
const { publicKeyJwk, privateKeyJwk } = await generateECDHKeyPair();

// Share publicKeyJwk with other user
// Store privateKeyJwk (encrypted) for yourself

// Derive shared conversation key
const conversationKey = await deriveConversationKey(
  myPrivateKey,
  theirPublicKeyJwk
);

// Encrypt message
const encrypted = await encryptForConversation(data, conversationKey);

// Decrypt message
const decrypted = await decryptFromConversation(encrypted, conversationKey);
```

### Group Encryption

```typescript
import {
  generateGroupKey,
  encryptGroupKeyForMember,
  decryptGroupKey
} from 'penumbra-crypto';

// Owner creates group key
const groupKey = await generateGroupKey();

// Encrypt for each member
const encryptedForMember = await encryptGroupKeyForMember(
  groupKey,
  ownerPrivateKey,
  memberPublicKeyJwk
);

// Member decrypts group key
const memberGroupKey = await decryptGroupKey(
  encryptedForMember,
  memberPrivateKey,
  ownerPublicKeyJwk
);
```

### KeyManager Class

High-level key management:

```typescript
import { KeyManager } from 'penumbra-crypto';

const km = new KeyManager();

// Initialize
await km.init(saltBase64, 'passphrase');

// Check state
km.isUnlocked();  // true
km.hasECDH();     // false (until initECDH called)

// Encrypt/decrypt
const enc = await km.encrypt(data);
const dec = await km.decrypt(enc);

// ECDH
await km.initECDH(encryptedPrivateKeyBlob);
const msg = await km.encryptForConnection(data, connId, theirPubKey);

// Groups
km.cacheGroupKey(groupId, groupKey);
const groupEnc = await km.encryptForGroup(data, groupId);

// Lock (clear all keys)
km.lock();
```

## Security

See [SECURITY.md](./SECURITY.md) for:
- Cryptographic design details
- Threat model
- Security properties
- Compliance information

### Summary

| Component | Algorithm |
|-----------|-----------|
| Key Derivation | PBKDF2-SHA256 (100k iterations) |
| Encryption | AES-256-GCM |
| Key Exchange | ECDH P-256 + HKDF |

## Browser Support

Requires Web Crypto API support:
- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 12+
- Node.js 18+

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build
```

## License

MIT
