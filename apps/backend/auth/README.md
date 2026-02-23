# Auth Module

This module provides RBAC authentication primitives for backend services.

## Scope

- Password hashing and verification (`passwords.py`)
- Session and API key token generation (`tokens.py`)
- One-way token hashing helpers for database persistence

## Design Notes

- Password hashes use PBKDF2-HMAC-SHA256 with a per-password random salt.
- API keys and session tokens are never intended to be stored in plaintext.
- Hashes are compared using deterministic SHA-256 digests.
- Callers should persist only token hashes and return raw tokens exactly once
  at creation time.

## Example Usage

```python
from apps.backend.auth.passwords import hash_password, verify_password
from apps.backend.auth.tokens import (
    generate_api_key,
    generate_session_token,
    hash_api_key,
    hash_session_token,
)

password_hash = hash_password("S3cure-Password!")
assert verify_password("S3cure-Password!", password_hash)

raw_api_key = generate_api_key(prefix="mck")
api_key_hash = hash_api_key(raw_api_key)

raw_session_token = generate_session_token()
session_token_hash = hash_session_token(raw_session_token)
```

## Security Considerations

- Do not log raw passwords, API keys, or session tokens.
- Do not return hashed secrets to clients as credentials.
- Rotate API keys by issuing new keys and revoking old hashes.
- Enforce TTL/expiry checks for session tokens and API keys at validation time.
