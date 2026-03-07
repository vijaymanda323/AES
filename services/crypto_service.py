"""
crypto_service.py — Unified Cryptography Service Facade
---------------------------------------------------------
Exposes a consistent interface that the analysis modules use to call
both the **standard** AES path (no LFSR) and the **dynamic** AES path
(LFSR-evolved key), plus the AES-128 round-key expansion.

The function names here intentionally match the spec:
    encrypt_standard(plaintext, key)
    encrypt_dynamic(plaintext, key)
    decrypt_standard(ciphertext, key, iv)   ← note: iv is 3rd arg for decrypt
    decrypt_dynamic(ciphertext, key, iv)
    get_round_keys(key)

All functions accept and return the same types used by the route layer.
"""

from __future__ import annotations

# Standard AES (no LFSR)
from crypto.aes_standard import (
    decrypt_standard as _std_decrypt,
    encrypt_standard as _std_encrypt,
)

# Dynamic AES (LFSR-evolved key)
from crypto.aes_engine import (
    decrypt_data as _dyn_decrypt,
    encrypt_data as _dyn_encrypt,
)

# AES-128 key schedule
from crypto.round_keys import get_round_keys as _get_round_keys


# ---------------------------------------------------------------------------
# Standard AES — no LFSR mutation
# ---------------------------------------------------------------------------

def encrypt_standard(plaintext: str, key: str) -> dict[str, str]:
    """Encrypt with plain AES-128-CBC (raw key, no LFSR).

    Returns:
        ``{"ciphertext": "<hex>", "iv": "<hex>"}``
    """
    return _std_encrypt(plaintext, key)


def decrypt_standard(ciphertext: str, key: str, iv: str) -> str:
    """Decrypt with plain AES-128-CBC (raw key, no LFSR).

    Returns:
        Recovered UTF-8 plaintext string.
    """
    return _std_decrypt(ciphertext, iv, key)


# ---------------------------------------------------------------------------
# Dynamic AES — LFSR-evolved key
# ---------------------------------------------------------------------------

def encrypt_dynamic(plaintext: str, key: str) -> dict[str, str]:
    """Encrypt with AES-128-CBC using the LFSR-evolved key.

    Returns:
        ``{"ciphertext": "<hex>", "iv": "<hex>"}``
    """
    return _dyn_encrypt(plaintext, key)


def decrypt_dynamic(ciphertext: str, key: str, iv: str) -> str:
    """Decrypt with AES-128-CBC using the LFSR-evolved key.

    Returns:
        Recovered UTF-8 plaintext string.
    """
    return _dyn_decrypt(ciphertext, iv, key)


# ---------------------------------------------------------------------------
# Round keys
# ---------------------------------------------------------------------------

def get_round_keys(key: str) -> list[str]:
    """Expand a 128-bit key into 11 AES round keys.

    Args:
        key: 32-character hex string.

    Returns:
        List of 11 hex strings (each 32 chars = 16 bytes).
    """
    return _get_round_keys(key)
