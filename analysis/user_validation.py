"""
user_validation.py — User Encryption Validation Module
--------------------------------------------------------
Validates functional correctness of both AES variants for arbitrary
user-supplied plaintext and key by performing full encrypt→decrypt
round-trips and comparing the recovered text against the original.

Validation rule:
    Decrypt(Encrypt(plaintext, key), key) == plaintext   →   PASS

Both Standard AES-128-CBC and Dynamic AES-128-CBC (LFSR key evolution)
are checked independently, with per-operation timing metrics included.

Usage:
    from analysis.user_validation import validate_user_encryption
"""

from __future__ import annotations

import time
import logging
from typing import Any

from services.crypto_service import (
    decrypt_dynamic,
    decrypt_standard,
    encrypt_dynamic,
    encrypt_standard,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core validation function
# ---------------------------------------------------------------------------

def validate_user_encryption(plaintext: str, key_hex: str) -> dict[str, Any]:
    """
    Encrypt and decrypt ``plaintext`` with both AES variants using ``key_hex``,
    then verify that every round-trip recovers the original plaintext.

    Args:
        plaintext: Non-empty UTF-8 string supplied by the user.
        key_hex:   32-character lowercase hex string (AES-128 key).

    Returns a dict with the following structure::

        {
            "input": {
                "plaintext": str
            },
            "standard_aes": {
                "ciphertext":     str,   # hex
                "iv":             str,   # hex
                "decrypted":      str,   # recovered plaintext
                "validation":     "PASS" | "FAIL",
                "execution_time": float, # seconds (encrypt + decrypt combined)
                "error":          str | None
            },
            "dynamic_aes": {
                "ciphertext":     str,
                "iv":             str,
                "decrypted":      str,
                "validation":     "PASS" | "FAIL",
                "execution_time": float,
                "error":          str | None
            },
            "overall_status": "PASS" | "FAIL"
        }
    """
    standard_result = _run_standard(plaintext, key_hex)
    dynamic_result  = _run_dynamic(plaintext, key_hex)

    both_pass = (
        standard_result["validation"] == "PASS"
        and dynamic_result["validation"] == "PASS"
    )
    overall = "PASS" if both_pass else "FAIL"

    if overall == "FAIL":
        logger.warning(
            "User encryption validation FAILED — standard: %s  dynamic: %s",
            standard_result["validation"],
            dynamic_result["validation"],
        )

    return {
        "input":         {"plaintext": plaintext},
        "standard_aes":  standard_result,
        "dynamic_aes":   dynamic_result,
        "overall_status": overall,
    }


# ---------------------------------------------------------------------------
# Per-variant helpers
# ---------------------------------------------------------------------------

def _run_standard(plaintext: str, key_hex: str) -> dict[str, Any]:
    """
    Run Standard AES encrypt → decrypt and return a result dict.
    Captures wall-clock time for enc+dec combined.
    """
    try:
        t0     = time.perf_counter()

        enc    = encrypt_standard(plaintext, key_hex)
        ct     = enc["ciphertext"]
        iv     = enc["iv"]

        dec    = decrypt_standard(ct, key_hex, iv)

        elapsed = time.perf_counter() - t0

        passed = dec == plaintext
        if not passed:
            logger.warning(
                "Standard AES round-trip mismatch — original: %r  recovered: %r",
                plaintext, dec,
            )

        return {
            "ciphertext":     ct,
            "iv":             iv,
            "decrypted":      dec,
            "validation":     "PASS" if passed else "FAIL",
            "execution_time": round(elapsed, 6),
            "error":          None,
        }

    except Exception as exc:  # noqa: BLE001
        logger.error("Standard AES validation error: %s", exc)
        return {
            "ciphertext":     "",
            "iv":             "",
            "decrypted":      "",
            "validation":     "FAIL",
            "execution_time": 0.0,
            "error":          str(exc),
        }


def _run_dynamic(plaintext: str, key_hex: str) -> dict[str, Any]:
    """
    Run Dynamic AES (LFSR) encrypt → decrypt and return a result dict.
    Captures wall-clock time for enc+dec combined.
    """
    try:
        t0     = time.perf_counter()

        enc    = encrypt_dynamic(plaintext, key_hex)
        ct     = enc["ciphertext"]
        iv     = enc["iv"]

        dec    = decrypt_dynamic(ct, key_hex, iv)

        elapsed = time.perf_counter() - t0

        passed = dec == plaintext
        if not passed:
            logger.warning(
                "Dynamic AES round-trip mismatch — original: %r  recovered: %r",
                plaintext, dec,
            )

        return {
            "ciphertext":     ct,
            "iv":             iv,
            "decrypted":      dec,
            "validation":     "PASS" if passed else "FAIL",
            "execution_time": round(elapsed, 6),
            "error":          None,
        }

    except Exception as exc:  # noqa: BLE001
        logger.error("Dynamic AES validation error: %s", exc)
        return {
            "ciphertext":     "",
            "iv":             "",
            "decrypted":      "",
            "validation":     "FAIL",
            "execution_time": 0.0,
            "error":          str(exc),
        }
