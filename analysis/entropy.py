"""
entropy.py — Shannon Entropy Analysis
--------------------------------------
Computes the Shannon entropy of AES ciphertext bytes.

A perfectly random ciphertext has entropy close to 8.0 bits/byte.
Higher entropy indicates better key diffusion and less pattern leakage.

Formula
~~~~~~~
    H = -Σ p(x) · log₂ p(x)       for every distinct byte value x

Computed independently for Standard AES and Dynamic AES ciphertexts.

Public API
~~~~~~~~~~
    compute_entropy(plaintext, key) → dict
"""

from __future__ import annotations

import math
from collections import Counter

from analysis.visualization import build_entropy_histogram
from services.crypto_service import encrypt_dynamic, encrypt_standard


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of *data* in bits per byte.

    Args:
        data: Byte sequence to analyse.

    Returns:
        Entropy value in [0.0, 8.0].  Returns 0.0 for empty input.
    """
    if not data:
        return 0.0

    total = len(data)
    freq = Counter(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_entropy(plaintext: str, key: str) -> dict:
    """Compute Shannon entropy for Standard and Dynamic AES ciphertexts.

    Args:
        plaintext: UTF-8 plaintext string.
        key:       32-character hex AES key.

    Returns:
        A dict containing:
            ``standard_entropy``  — float in [0.0, 8.0]
            ``dynamic_entropy``   — float in [0.0, 8.0]
            ``visualization``     — byte-frequency histogram (dynamic ciphertext)
    """
    std_result = encrypt_standard(plaintext, key)
    dyn_result = encrypt_dynamic(plaintext, key)

    std_ct_bytes = bytes.fromhex(std_result["ciphertext"])
    dyn_ct_bytes = bytes.fromhex(dyn_result["ciphertext"])

    standard_entropy = _shannon_entropy(std_ct_bytes)
    dynamic_entropy  = _shannon_entropy(dyn_ct_bytes)

    # Histogram built from the dynamic ciphertext (the primary subject of study)
    visualization = build_entropy_histogram(dyn_ct_bytes)

    return {
        "standard_entropy": standard_entropy,
        "dynamic_entropy":  dynamic_entropy,
        "visualization":    visualization,
    }
