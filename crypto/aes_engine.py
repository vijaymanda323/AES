"""
aes_engine.py — AES-128 CBC Encryption / Decryption Engine
------------------------------------------------------------
Provides two public functions:

    encrypt_data(plaintext, raw_key)  →  (ciphertext_hex, iv_hex)
    decrypt_data(ciphertext_hex, iv_hex, raw_key)  →  plaintext

Both functions internally call :func:`evolve_key` so that the actual
encryption / decryption key is always the LFSR-evolved version of the
caller-supplied raw key — never the raw key itself.

Cipher settings
~~~~~~~~~~~~~~~
* Algorithm : AES-128
* Mode      : CBC  (Cipher Block Chaining)
* Padding   : PKCS#7  (via ``Crypto.Util.Padding``)
* IV        : 16 random bytes generated fresh on every encrypt call
              and returned to the caller for inclusion in the response.
"""

from __future__ import annotations

import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from .key_evolution import evolve_key


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _prepare_key(raw_key_hex: str) -> bytes:
    """Decode a hex-encoded raw key and evolve it.

    Args:
        raw_key_hex: The secret key as a 32-character hex string (16 bytes).

    Returns:
        The 16-byte *evolved* key ready for use in AES operations.

    Raises:
        ValueError: If the hex string does not decode to exactly 16 bytes.
    """
    try:
        raw_key_bytes: bytes = bytes.fromhex(raw_key_hex)
    except ValueError as exc:
        raise ValueError(
            "secret_key must be a valid hex string (e.g. 32 hex chars = 16 bytes)."
        ) from exc

    if len(raw_key_bytes) != 16:
        raise ValueError(
            f"Decoded key must be 16 bytes (128 bits); got {len(raw_key_bytes)} byte(s). "
            "Provide exactly 32 hexadecimal characters."
        )

    return evolve_key(raw_key_bytes)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt_data(plaintext: str, raw_key_hex: str) -> dict[str, str]:
    """Encrypt *plaintext* with AES-128-CBC using the LFSR-evolved key.

    Args:
        plaintext:   The UTF-8 string to encrypt.
        raw_key_hex: 32-character hex string representing the 16-byte raw AES key.

    Returns:
        A dict with keys:
            ``"ciphertext"`` — hex-encoded ciphertext (includes padding),
            ``"iv"``         — hex-encoded 16-byte Initialisation Vector.

    Raises:
        ValueError: On invalid key format or length.
    """
    evolved_key: bytes = _prepare_key(raw_key_hex)

    iv: bytes = os.urandom(16)
    cipher = AES.new(evolved_key, AES.MODE_CBC, iv)

    padded_plaintext: bytes = pad(plaintext.encode("utf-8"), AES.block_size)
    ciphertext: bytes = cipher.encrypt(padded_plaintext)

    return {
        "ciphertext": ciphertext.hex(),
        "iv": iv.hex(),
    }


def decrypt_data(ciphertext_hex: str, iv_hex: str, raw_key_hex: str) -> str:
    """Decrypt *ciphertext_hex* with AES-128-CBC using the LFSR-evolved key.

    Args:
        ciphertext_hex: Hex-encoded ciphertext produced by :func:`encrypt_data`.
        iv_hex:         Hex-encoded 16-byte IV produced by :func:`encrypt_data`.
        raw_key_hex:    Same 32-character hex key used during encryption.

    Returns:
        The original UTF-8 plaintext string.

    Raises:
        ValueError: On invalid inputs, bad padding, or key mismatch.
    """
    evolved_key: bytes = _prepare_key(raw_key_hex)

    try:
        ciphertext: bytes = bytes.fromhex(ciphertext_hex)
        iv: bytes = bytes.fromhex(iv_hex)
    except ValueError as exc:
        raise ValueError(
            "ciphertext and iv must be valid hex-encoded strings."
        ) from exc

    if len(iv) != 16:
        raise ValueError("IV must decode to exactly 16 bytes.")

    cipher = AES.new(evolved_key, AES.MODE_CBC, iv)
    padded_plaintext: bytes = cipher.decrypt(ciphertext)

    try:
        plaintext: bytes = unpad(padded_plaintext, AES.block_size)
    except ValueError as exc:
        raise ValueError(
            "Decryption failed: incorrect padding. "
            "Ensure the key and IV match those used during encryption."
        ) from exc

    return plaintext.decode("utf-8")
