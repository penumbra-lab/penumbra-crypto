# Security Architecture

This document describes the cryptographic design of `penumbra-crypto`.

## Overview

`penumbra-crypto` provides client-side end-to-end encryption using the Web Crypto API. All cryptographic operations occur in the browser - the server never sees plaintext data or encryption keys.

## Cryptographic Primitives

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Derivation | PBKDF2 | SHA-256, 100,000 iterations |
| Symmetric Encryption | AES-GCM | 256-bit key, 96-bit IV |
| Key Exchange | ECDH | P-256 (secp256r1) |
| Key Stretching | HKDF | SHA-256 |

## Key Derivation

User passphrases are converted to encryption keys using PBKDF2:

```
passphrase + salt → PBKDF2(SHA-256, 100k iterations) → AES-256 key
```

**Security properties:**
- Salt is unique per user (16+ bytes, stored server-side)
- 100,000 iterations provides resistance to brute-force attacks
- Resulting key is non-extractable (cannot be read by JavaScript)

**Recommendations:**
- Use strong passphrases (12+ characters with mixed case/numbers)
- Consider increasing iterations for high-security applications
- OWASP recommends 600,000+ iterations for SHA-256

## Symmetric Encryption (AES-GCM)

All data encryption uses AES-256-GCM:

```
plaintext + key → AES-GCM(random 96-bit IV) → ciphertext + auth tag
```

**Security properties:**
- Authenticated encryption (confidentiality + integrity)
- Random IV per encryption prevents IV reuse
- 96-bit IV as recommended by NIST SP 800-38D
- Authentication tag detects any tampering

**Payload format:**
```json
{
  "iv": [12 bytes as number array],
  "data": [ciphertext + auth tag as number array]
}
```

## Key Exchange (ECDH)

User-to-user encryption uses ECDH key agreement:

```
Alice_private + Bob_public → ECDH → shared_secret
shared_secret → HKDF(SHA-256, info="penumbra-conversation-v1") → AES-256 key
```

**Security properties:**
- P-256 curve provides ~128 bits of security
- Same shared secret derived by both parties
- HKDF stretches ECDH output into a proper key
- Forward secrecy possible with key rotation (not implemented)

**Key storage:**
- Public key: Stored as JWK on server (can be shared)
- Private key: Encrypted with user's passphrase-derived key

## Group Encryption

Groups use a shared symmetric key distributed via ECDH:

```
1. Owner generates random AES-256 group key
2. For each member:
   - Derive shared secret via ECDH(owner_priv, member_pub)
   - Encrypt group key with shared secret
   - Store encrypted key for member
3. Members decrypt group key using ECDH(member_priv, owner_pub)
```

**Security properties:**
- Group key is random (not derived from any user input)
- Each member receives individually encrypted copy
- Adding members requires owner to encrypt key for new member
- Removing members requires generating new group key

## Data Flow

### User Data Encryption
```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Plaintext  │────▶│   AES-GCM    │────▶│  Encrypted  │
│    Data     │     │ (user's key) │     │    Blob     │
└─────────────┘     └──────────────┘     └─────────────┘
                           ▲
                           │
                    ┌──────┴──────┐
                    │ PBKDF2 Key  │
                    │ (in memory) │
                    └─────────────┘
```

### Conversation Encryption
```
┌─────────┐  ECDH   ┌─────────┐
│ Alice   │◀───────▶│   Bob   │
│ Keypair │         │ Keypair │
└────┬────┘         └────┬────┘
     │                   │
     └───────┬───────────┘
             ▼
     ┌───────────────┐
     │ Shared Secret │
     └───────┬───────┘
             │ HKDF
             ▼
     ┌───────────────┐
     │ Conversation  │
     │     Key       │
     └───────┬───────┘
             │ AES-GCM
             ▼
     ┌───────────────┐
     │   Encrypted   │
     │   Messages    │
     └───────────────┘
```

## Threat Model

### What We Protect Against

| Threat | Mitigation |
|--------|------------|
| Server compromise | Server never sees plaintext or keys |
| Database theft | All user data is encrypted |
| Man-in-the-middle | ECDH provides key agreement |
| Brute-force attacks | PBKDF2 with high iterations |
| Data tampering | AES-GCM authentication |
| IV reuse | Random IV per encryption |

### What We Don't Protect Against

| Threat | Reason |
|--------|--------|
| Compromised browser | JavaScript can be modified |
| Malicious server JS | Server could serve malicious code |
| Weak passphrases | User responsibility |
| Endpoint compromise | OS/browser security issue |
| Side-channel attacks | Not implemented in Web Crypto |

### Trust Assumptions

1. **Browser's Web Crypto API is correctly implemented**
2. **TLS protects code delivery** (server must use HTTPS)
3. **User chooses a strong passphrase**
4. **User's device is not compromised**

## Implementation Notes

### Non-Extractable Keys

Where possible, keys are imported as non-extractable:
```typescript
crypto.subtle.importKey(..., false, ['encrypt', 'decrypt'])
//                         ↑ non-extractable
```

This prevents JavaScript (including XSS attacks) from reading raw key bytes.

### Memory Management

- Keys are stored in memory only while needed
- `KeyManager.lock()` clears all keys
- No keys are stored in localStorage/sessionStorage

### Error Handling

- Decryption failures throw exceptions (don't reveal why)
- Invalid data is rejected before decryption attempts
- No timing-based information leakage (Web Crypto is constant-time)

## Design Rationale

### Why Web Crypto API Only?

This library deliberately uses only the browser's native Web Crypto API with no external dependencies:

- **Auditability**: Less code to review; the cryptographic primitives are browser-implemented
- **No supply chain risk**: No npm dependencies that could be compromised
- **Performance**: Native implementations are optimized and constant-time
- **Broad support**: Works in all modern browsers and Node.js 18+

### Why PBKDF2 instead of Argon2id?

Argon2id is the current best practice for password hashing because it's memory-hard (resistant to GPU/ASIC attacks). However, **the Web Crypto API does not support Argon2id**.

Using PBKDF2 is a deliberate tradeoff:
- **Pro**: Zero dependencies, native browser support, well-audited
- **Con**: More vulnerable to GPU-based brute-force attacks

**Mitigations**:
- Use strong passphrases (12+ characters, mixed case/numbers/symbols)
- Increase iteration count for high-security applications
- The 100k iteration default is a balance; consider 600k+ per OWASP

### Why P-256 instead of X25519/Ed25519?

Curve25519 is preferred by many in the privacy community for its simpler implementation and resistance to certain implementation errors. However, **the Web Crypto API does not support Curve25519**.

P-256 (secp256r1) tradeoffs:
- **Pro**: NIST-standardized, widely audited, universal browser support
- **Con**: More complex implementation (though we use the browser's, not our own)
- **Con**: Some distrust NIST curves due to parameter selection process

Both curves provide ~128 bits of security. The practical difference is minimal for most threat models.

## Compliance

This implementation aligns with:

- **NIST SP 800-38D**: AES-GCM recommendations
- **NIST SP 800-132**: PBKDF recommendations
- **NIST SP 800-56A**: ECDH key agreement
- **OWASP**: Password storage guidelines

## Future Considerations

1. **Increase PBKDF2 iterations**: Consider 600,000+ for new accounts
2. **Forward secrecy**: Implement key rotation for conversations
3. **Key backup**: Secure recovery mechanism
4. **Audit logging**: Cryptographic operation logging
5. **Hardware keys**: WebAuthn integration for key protection

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly by opening a private issue on [Codeberg](https://codeberg.org/penumbra/penumbra-crypto/issues). Please do not open public issues for security vulnerabilities.
