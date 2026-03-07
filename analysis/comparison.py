"""
comparison.py — Standard vs Dynamic AES Ciphertext Comparison
--------------------------------------------------------------
Runs both encryption variants on the same plaintext so the caller can
see two different ciphertexts produced from the same input — demonstrating
how LFSR key evolution changes the encrypted output.

Public API
~~~~~~~~~~
    compute_comparison(plaintext, key) → dict
"""

from __future__ import annotations

from services.crypto_service import encrypt_dynamic, encrypt_standard


def compute_comparison(plaintext: str, key: str) -> dict:
    """Encrypt *plaintext* with both Standard and Dynamic AES.

    Args:
        plaintext: UTF-8 string to encrypt.
        key:       32-character hex key.

    Returns:
        A dict with four keys:
            ``standard_ciphertext``, ``standard_iv``,
            ``dynamic_ciphertext``,  ``dynamic_iv``
    """
    std_result = encrypt_standard(plaintext, key)
    dyn_result = encrypt_dynamic(plaintext, key)

    return {
        "standard_ciphertext": std_result["ciphertext"],
        "standard_iv":         std_result["iv"],
        "dynamic_ciphertext":  dyn_result["ciphertext"],
        "dynamic_iv":          dyn_result["iv"],
    }
