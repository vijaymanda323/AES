"""
performance.py — Encryption / Decryption Performance Analysis
--------------------------------------------------------------
Measures the wall-clock execution time of both AES variants using
``time.perf_counter()`` — the highest-resolution timer available in Python.

Each operation is timed individually:
    1. Standard AES encrypt
    2. Dynamic AES encrypt
    3. Standard AES decrypt
    4. Dynamic AES decrypt

Results are returned in **seconds** (floating-point) alongside chart-ready
visualization data.

Public API
~~~~~~~~~~
    compute_performance(plaintext, key) → dict
"""

from __future__ import annotations

import time

from analysis.visualization import build_performance_chart
from services.crypto_service import (
    decrypt_dynamic,
    decrypt_standard,
    encrypt_dynamic,
    encrypt_standard,
)


def _time_call(fn, *args) -> tuple[float, object]:
    """Measure execution time of *fn* called with *args*.

    Returns:
        ``(elapsed_seconds, return_value)``
    """
    t0 = time.perf_counter()
    result = fn(*args)
    t1 = time.perf_counter()
    return round(t1 - t0, 6), result


def compute_performance(plaintext: str, key: str) -> dict:
    """Benchmark Standard and Dynamic AES encrypt + decrypt operations.

    Args:
        plaintext: UTF-8 string to encrypt/decrypt.
        key:       32-character hex AES key.

    Returns:
        A dict containing:
            ``standard_encrypt_time``  — seconds (float)
            ``dynamic_encrypt_time``   — seconds (float)
            ``standard_decrypt_time``  — seconds (float)
            ``dynamic_decrypt_time``   — seconds (float)
            ``visualization``          — bar chart data
    """
    # --- Encrypt ---
    std_enc_time, std_enc_result = _time_call(encrypt_standard, plaintext, key)
    dyn_enc_time, dyn_enc_result = _time_call(encrypt_dynamic,  plaintext, key)

    # --- Decrypt (using the IVs captured during encryption) ---
    std_dec_time, _ = _time_call(
        decrypt_standard,
        std_enc_result["ciphertext"],
        key,
        std_enc_result["iv"],
    )
    dyn_dec_time, _ = _time_call(
        decrypt_dynamic,
        dyn_enc_result["ciphertext"],
        key,
        dyn_enc_result["iv"],
    )

    visualization = build_performance_chart(
        std_enc_time, dyn_enc_time, std_dec_time, dyn_dec_time
    )

    return {
        "standard_encrypt_time": std_enc_time,
        "dynamic_encrypt_time":  dyn_enc_time,
        "standard_decrypt_time": std_dec_time,
        "dynamic_decrypt_time":  dyn_dec_time,
        "visualization":         visualization,
    }
