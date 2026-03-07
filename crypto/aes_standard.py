"""
aes_standard.py — Standard AES-128 CBC (no LFSR key evolution)
----------------------------------------------------------------
Provides the *unmodified* AES-128-CBC encrypt/decrypt path.  The raw key
supplied by the caller is used **directly** — no LFSR evolution is applied.

This module intentionally mirrors the public interface of `aes_engine.py`
so that both variants can be called identically by the analysis layer.

Functions
~~~~~~~~~
    encrypt_standard(plaintext, key_hex)            → {ciphertext, iv}
    decrypt_standard(ciphertext_hex, iv_hex, key_hex) → plaintext
"""

from __future__ import annotations

import os
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _decode_key(key_hex: str) -> bytes:
    """Validate and decode the hex key into raw bytes.

    Args:
        key_hex: 32-character hexadecimal string (16 bytes / 128 bits).

    Returns:
        16-byte key.

    Raises:
        ValueError: If the key is not a valid 32-hex-char string.
    """
    if not _HEX_RE.match(key_hex):
        raise ValueError(
            "secret_key must be exactly 32 hexadecimal characters "
            "(representing a 16-byte / 128-bit AES key)."
        )
    return bytes.fromhex(key_hex)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt_standard(plaintext: str, key_hex: str) -> dict[str, str]:
    """Encrypt *plaintext* with standard AES-128-CBC (no LFSR evolution).

    Args:
        plaintext: UTF-8 string to encrypt.
        key_hex:   32-character hex key (16 bytes).

    Returns:
        ``{"ciphertext": "<hex>", "iv": "<hex>"}``
    """
    key: bytes = _decode_key(key_hex)
    iv: bytes = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded: bytes = pad(plaintext.encode("utf-8"), AES.block_size)
    ciphertext: bytes = cipher.encrypt(padded)
    return {
        "ciphertext": ciphertext.hex(),
        "iv": iv.hex(),
    }


def decrypt_standard(ciphertext_hex: str, iv_hex: str, key_hex: str) -> str:
    """Decrypt *ciphertext_hex* with standard AES-128-CBC (no LFSR evolution).

    Args:
        ciphertext_hex: Hex-encoded ciphertext.
        iv_hex:         Hex-encoded 16-byte IV.
        key_hex:        32-character hex key used during encryption.

    Returns:
        Recovered UTF-8 plaintext.

    Raises:
        ValueError: On bad inputs or padding errors.
    """
    key: bytes = _decode_key(key_hex)

    try:
        ciphertext: bytes = bytes.fromhex(ciphertext_hex)
        iv: bytes = bytes.fromhex(iv_hex)
    except ValueError as exc:
        raise ValueError("ciphertext and iv must be valid hex strings.") from exc

    if len(iv) != 16:
        raise ValueError("IV must decode to exactly 16 bytes.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext: bytes = cipher.decrypt(ciphertext)

    try:
        return unpad(padded_plaintext, AES.block_size).decode("utf-8")
    except ValueError as exc:
        raise ValueError(
            "Standard decryption failed: incorrect padding or key mismatch."
        ) from exc
