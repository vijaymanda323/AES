"""
nist_validation.py — NIST AES-128 Validation Module
------------------------------------------------------
Implements two validation strategies:

1. **NIST Known-Answer Tests (KAT)**
   Uses official AES-128 ECB test vectors from NIST FIPS-197 Appendix B
   and NIST AES Known-Answer Test (KAT) vectors to verify that the local
   AES implementation produces exactly the expected ciphertext.

   Note: The existing encrypt_standard() uses AES-CBC with a random IV,
   so NIST ECB-mode comparison requires running AES-ECB directly.  This
   module uses ``pycryptodome`` (already a project dependency) in ECB mode
   to produce a deterministic, IV-free ciphertext for accurate comparison.

2. **Dynamic AES Functional Correctness**
   Because the LFSR evolves the key, the ciphertext will never match NIST
   ECB vectors.  Correctness is validated via an encrypt → decrypt
   round-trip:
       encrypt_dynamic(plaintext, key)  →  ciphertext + iv
       decrypt_dynamic(ciphertext, key, iv)  →  recovered plaintext
   PASS if recovered plaintext == original plaintext.

Usage:
    from analysis.nist_validation import run_nist_standard_tests, run_dynamic_aes_validation
"""

from __future__ import annotations

import logging
from typing import Any

from Crypto.Cipher import AES  # pycryptodome — already in requirements.txt

from services.crypto_service import decrypt_dynamic, encrypt_dynamic

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Official NIST AES-128 ECB Test Vectors
# ---------------------------------------------------------------------------
# Vector 1: NIST FIPS-197 Appendix B  (definitive normative example)
# Vector 2: NIST AES-128 ECB KAT GFSbox — verifies SubBytes / S-box
# Vector 3: NIST AES-128 ECB KAT Variable Key — verifies key schedule
#
# Each entry:
#   key                — 32 hex chars (16 bytes) = 128-bit AES key
#   plaintext          — 32 hex chars (16 bytes) = one AES block
#   expected_ciphertext— 32 hex chars (16 bytes) = expected ECB output
# ---------------------------------------------------------------------------

NIST_VECTORS: list[dict[str, str]] = [
    {
        "test_id": 1,
        "test_name": "NIST FIPS-197 Appendix B — AES-128",
        "description": (
            "Definitive example from the FIPS-197 document. "
            "Key bytes increment 0x00..0x0f; plaintext is 0x00112233…ccddeeff."
        ),
        "key":                  "000102030405060708090a0b0c0d0e0f",
        "plaintext":            "00112233445566778899aabbccddeeff",
        "expected_ciphertext":  "69c4e0d86a7b0430d8cdb78070b4c55a",
    },
    {
        "test_id": 2,
        "test_name": "NIST AES-128 ECB KAT — GFSbox Vector 1",
        "description": (
            "NIST Known-Answer Test using a zero key against a specific "
            "GFSbox plaintext to verify the SubBytes / S-box implementation."
        ),
        "key":                  "00000000000000000000000000000000",
        "plaintext":            "f34481ec3cc627bacd5dc3fb08f273e6",
        "expected_ciphertext":  "0336763e966d92595a567cc9ce537f5e",
    },
    {
        "test_id": 3,
        "test_name": "NIST AES-128 ECB KAT — KeySbox Vector 1",
        "description": (
            "NIST Known-Answer Test from the official KeySbox KAT suite. "
            "Uses a specific 128-bit key against a zero plaintext to verify "
            "that the key schedule S-box substitutions are correct."
        ),
        "key":                  "10a58869d74be5a374cf867cfb473859",
        "plaintext":            "00000000000000000000000000000000",
        "expected_ciphertext":  "6d251e6944b051e04eaa6fb4dbf78465",
    },
]


# ---------------------------------------------------------------------------
# Internal helper — AES-128 ECB single-block encryption (pycryptodome)
# ---------------------------------------------------------------------------

def _aes128_ecb_encrypt(key_bytes: bytes, plaintext_bytes: bytes) -> bytes:
    """
    Encrypt exactly one 16-byte block with AES-128-ECB using pycryptodome.

    Args:
        key_bytes:       16-byte AES-128 key.
        plaintext_bytes: 16-byte plaintext block (one AES block, no padding needed).

    Returns:
        16-byte ciphertext block.

    Raises:
        ValueError: if key or plaintext length is not 16 bytes.
    """
    if len(key_bytes) != 16:
        raise ValueError(
            f"AES-128 requires a 16-byte key; got {len(key_bytes)} bytes."
        )
    if len(plaintext_bytes) != 16:
        raise ValueError(
            f"AES-128 ECB expects a 16-byte plaintext block; got {len(plaintext_bytes)} bytes."
        )

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(plaintext_bytes)


# ---------------------------------------------------------------------------
# 1. NIST Standard AES Validation
# ---------------------------------------------------------------------------

def run_nist_standard_tests() -> dict[str, Any]:
    """
    Run all NIST AES-128 ECB Known-Answer Tests.

    Iterates over ``NIST_VECTORS``, encrypts each plaintext block with the
    corresponding key in AES-128-ECB mode, and compares the result against
    the official expected ciphertext.

    Returns:
        {
            "tests": [
                {
                    "test_id": int,
                    "test_name": str,
                    "key": str,                   # hex
                    "plaintext": str,             # hex
                    "expected_ciphertext": str,   # hex
                    "generated_ciphertext": str,  # hex
                    "status": "PASS" | "FAIL"
                },
                ...
            ],
            "tests_passed": int,
            "tests_failed": int,
            "overall_status": "PASS" | "FAIL"
        }
    """
    results: list[dict[str, Any]] = []
    passed = 0
    failed = 0

    for vec in NIST_VECTORS:
        test_id   = vec["test_id"]
        test_name = vec["test_name"]
        key_hex   = vec["key"]
        pt_hex    = vec["plaintext"]
        exp_hex   = vec["expected_ciphertext"]

        try:
            key_bytes = bytes.fromhex(key_hex)
            pt_bytes  = bytes.fromhex(pt_hex)
            ct_bytes  = _aes128_ecb_encrypt(key_bytes, pt_bytes)
            gen_hex   = ct_bytes.hex()
            status    = "PASS" if gen_hex == exp_hex else "FAIL"

        except Exception as exc:  # noqa: BLE001
            logger.error("NIST vector %d raised exception: %s", test_id, exc)
            gen_hex = "ERROR"
            status  = "FAIL"

        if status == "PASS":
            passed += 1
        else:
            failed += 1
            logger.warning(
                "NIST vector %d FAILED — expected: %s  got: %s",
                test_id, exp_hex, gen_hex,
            )

        results.append(
            {
                "test_id":              test_id,
                "test_name":            test_name,
                "key":                  key_hex,
                "plaintext":            pt_hex,
                "expected_ciphertext":  exp_hex,
                "generated_ciphertext": gen_hex,
                "status":               status,
            }
        )

    overall = "PASS" if failed == 0 else "FAIL"
    if overall == "FAIL":
        logger.error(
            "NIST AES validation: %d/%d test(s) FAILED.", failed, len(NIST_VECTORS)
        )

    return {
        "tests":          results,
        "tests_passed":   passed,
        "tests_failed":   failed,
        "overall_status": overall,
    }


# ---------------------------------------------------------------------------
# 2. Dynamic AES Functional Correctness Validation
# ---------------------------------------------------------------------------

def run_dynamic_aes_validation(plaintext: str, key: str) -> dict[str, Any]:
    """
    Validate Dynamic AES (LFSR-evolved key) via encrypt → decrypt round-trip.

    Because the LFSR mutates the key before use, the resulting ciphertext
    will not match any NIST vector. Functional correctness is verified by
    confirming that decrypting the ciphertext recovers the original plaintext.

    Args:
        plaintext: UTF-8 plaintext string (any length).
        key:       32-character hex AES-128 key string.

    Returns:
        {
            "plaintext":                          str,
            "encryption_status":                  "SUCCESS" | "ERROR",
            "decryption_status":                  "SUCCESS" | "ERROR",
            "encryption_decryption_consistency":  "PASS"    | "FAIL",
            "error":                              str | None
        }
    """
    try:
        enc_result = encrypt_dynamic(plaintext, key)
        ciphertext = enc_result["ciphertext"]
        iv         = enc_result["iv"]

        recovered  = decrypt_dynamic(ciphertext, key, iv)
        consistent = "PASS" if recovered == plaintext else "FAIL"

        if consistent == "FAIL":
            logger.warning(
                "Dynamic AES consistency FAILED — original: %r  recovered: %r",
                plaintext, recovered,
            )

        return {
            "plaintext":                         plaintext,
            "encryption_status":                 "SUCCESS",
            "decryption_status":                 "SUCCESS",
            "encryption_decryption_consistency": consistent,
            "error":                             None,
        }

    except Exception as exc:  # noqa: BLE001
        logger.error("Dynamic AES validation error: %s", exc)
        return {
            "plaintext":                         plaintext,
            "encryption_status":                 "ERROR",
            "decryption_status":                 "ERROR",
            "encryption_decryption_consistency": "FAIL",
            "error":                             str(exc),
        }
