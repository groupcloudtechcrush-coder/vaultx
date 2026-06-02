"""
crypto.py — Encryption / Decryption helpers
============================================
We use the `cryptography` library's Fernet symmetric encryption scheme.

Fernet guarantees:
  • AES-128 in CBC mode with PKCS7 padding  (confidentiality)
  • HMAC-SHA256 over the ciphertext         (authenticity / tamper-detection)
  • A timestamp embedded in the token       (allows max-age enforcement)
  • URL-safe base64 encoding of the token   (safe to store as text)

Key derivation strategy
-----------------------
A single application-wide FERNET_SECRET_KEY is stored in Django settings
(loaded from an environment variable — never hard-coded).

We then derive a *per-user* key by running PBKDF2-HMAC-SHA256 over a
combination of the master secret and the user's immutable primary key.
This means:
  • Even if one user's data leaks, other users' vaults are unaffected.
  • We never store the per-user key — it is always derived on-the-fly.
"""

import hashlib
import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


def _derive_user_key(user_id: int) -> bytes:
    """
    Derive a 32-byte key unique to `user_id` using PBKDF2-HMAC-SHA256.

    Steps:
      1. Retrieve the master secret from settings (set via env var).
      2. Use the user's integer PK as the "salt" input — it is immutable and
         unique per user, so derived keys never collide.
      3. Run 390_000 PBKDF2 iterations (NIST recommendation for SHA-256).
      4. Encode the 32-byte output as URL-safe base64 so Fernet can accept it.

    Returns:
        bytes: A 44-byte URL-safe base64-encoded Fernet key.
    """
    # Master secret must be set as an env var; fail loudly if missing
    master_secret: str = settings.FERNET_SECRET_KEY
    if not master_secret:
        raise EnvironmentError(
            "FERNET_SECRET_KEY is not set in Django settings / environment."
        )

    # PBKDF2: password=master_secret, salt=str(user_id), iterations=390_000
    raw_key: bytes = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=master_secret.encode('utf-8'),   # master application secret
        salt=str(user_id).encode('utf-8'),         # user-specific salt
        iterations=390_000,                        # NIST-recommended count
        dklen=32                                   # 32 bytes = 256 bits
    )

    # Fernet requires a 32-byte key encoded as URL-safe base64 (44 chars)
    return base64.urlsafe_b64encode(raw_key)


def encrypt_password(plain_text: str, user_id: int) -> str:
    """
    Encrypt `plain_text` with a key derived for `user_id`.

    Flow:
      derive_user_key(user_id) → Fernet(key) → .encrypt(bytes) → token string

    The Fernet token is itself base64-encoded and safe to store in a TextField.

    Args:
        plain_text: The raw password to protect.
        user_id:    The PK of the owning User record.

    Returns:
        str: The Fernet ciphertext token (URL-safe, base64-encoded string).
    """
    key: bytes = _derive_user_key(user_id)
    fernet = Fernet(key)

    # Fernet.encrypt() returns bytes; decode to str for DB storage
    token: bytes = fernet.encrypt(plain_text.encode('utf-8'))
    return token.decode('utf-8')


def decrypt_password(cipher_text: str, user_id: int) -> str:
    """
    Decrypt a Fernet token back to its plain-text password.

    Flow:
      derive_user_key(user_id) → Fernet(key) → .decrypt(token) → plain string

    Fernet.decrypt() raises `cryptography.fernet.InvalidToken` if:
      • The ciphertext has been tampered with (HMAC mismatch).
      • The token was encrypted with a different key (wrong user).
      • The token is malformed / truncated.

    We propagate the exception to the caller so the view can handle it
    gracefully (e.g., return an HTTP 400 instead of crashing).

    Args:
        cipher_text: The Fernet token string retrieved from the DB.
        user_id:     The PK of the requesting User (must match the encryptor).

    Returns:
        str: The original plain-text password.

    Raises:
        cryptography.fernet.InvalidToken: If decryption fails for any reason.
    """
    key: bytes = _derive_user_key(user_id)
    fernet = Fernet(key)

    # Fernet.decrypt() verifies the HMAC *before* decrypting — tamper-evident
    plain_bytes: bytes = fernet.decrypt(cipher_text.encode('utf-8'))
    return plain_bytes.decode('utf-8')
