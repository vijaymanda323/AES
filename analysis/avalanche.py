"""
avalanche.py — Avalanche Effect Analysis
-----------------------------------------
Measures how a single bit-flip in the plaintext propagates into the
ciphertext — a high avalanche effect (≥ 50 %) indicates strong diffusion.

Algorithm
~~~~~~~~~
1. Encrypt the original plaintext → ciphertext_A
2. Flip bit 0 of the first plaintext byte → modified plaintext
3. Encrypt the modified plaintext → ciphertext_B
4. XOR ciphertext_A and ciphertext_B bit-by-bit
5. Count the bits that changed

Formula
~~~~~~~
    Avalanche (%) = (changed_bits / total_bits) × 100

Performed independently for both Standard AES and Dynamic AES.

Public API
~~~~~~~~~~
    compute_avalanche(plaintext, key) → dict
"""

from __future__ import annotations

from analysis.visualization import build_avalanche_heatmap
from services.crypto_service import encrypt_dynamic, encrypt_standard


def _count_bit_differences(bytes_a: bytes, bytes_b: bytes) -> tuple[int, int]:
    """Count differing bits between two equal-length byte sequences.

    Returns:
        ``(changed_bits, total_bits)``
    """
    min_len = min(len(bytes_a), len(bytes_b))
    total_bits = min_len * 8
    changed = 0
    for i in range(min_len):
        diff = bytes_a[i] ^ bytes_b[i]
        # Count set bits in diff (popcount)
        changed += bin(diff).count("1")
    return changed, total_bits


def _flip_bit(plaintext: str, bit_index: int = 0) -> str:
    """Flip a single bit of the UTF-8 encoded plaintext.

    Flips *bit_index* of byte 0 of the plaintext encoding.  The result
    is decoded back to a string using 'latin-1' to preserve all 256 byte
    values without raising a UnicodeDecodeError.

    Args:
        plaintext:  Original plaintext string.
        bit_index:  Bit to flip within the first byte (0 = LSB).

    Returns:
        Modified plaintext string with one bit changed.
    """
    pt_bytes = bytearray(plaintext.encode("utf-8"))
    pt_bytes[0] ^= (1 << bit_index)
    # Decode as latin-1 so all 256 values survive round-trip as a str
    return pt_bytes.decode("latin-1")


def compute_avalanche(plaintext: str, key: str) -> dict:
    """Compute the avalanche effect for Standard and Dynamic AES.

    Args:
        plaintext: UTF-8 string to analyse.
        key:       32-character hex AES key.

    Returns:
        A dict containing:
            ``standard_avalanche``  — float in [0, 100]
            ``dynamic_avalanche``   — float in [0, 100]
            ``visualization``       — heatmap based on dynamic ciphertext diff
    """
    modified_plaintext = _flip_bit(plaintext)

    # --- Standard AES ---
    std_orig  = encrypt_standard(plaintext, key)
    std_mod   = encrypt_standard(modified_plaintext, key)
    std_orig_bytes = bytes.fromhex(std_orig["ciphertext"])
    std_mod_bytes  = bytes.fromhex(std_mod["ciphertext"])
    std_changed, std_total = _count_bit_differences(std_orig_bytes, std_mod_bytes)
    standard_avalanche = round((std_changed / std_total) * 100, 2) if std_total else 0.0

    # --- Dynamic AES (LFSR-evolved key) ---
    dyn_orig  = encrypt_dynamic(plaintext, key)
    dyn_mod   = encrypt_dynamic(modified_plaintext, key)
    dyn_orig_bytes = bytes.fromhex(dyn_orig["ciphertext"])
    dyn_mod_bytes  = bytes.fromhex(dyn_mod["ciphertext"])
    dyn_changed, dyn_total = _count_bit_differences(dyn_orig_bytes, dyn_mod_bytes)
    dynamic_avalanche = round((dyn_changed / dyn_total) * 100, 2) if dyn_total else 0.0

    # Build heatmap using the dynamic ciphertext diff (more interesting visually)
    visualization = build_avalanche_heatmap(dyn_orig_bytes, dyn_mod_bytes)

    return {
        "standard_avalanche": standard_avalanche,
        "dynamic_avalanche":  dynamic_avalanche,
        "visualization":      visualization,
    }
