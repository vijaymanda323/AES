"""
validation_models.py — Pydantic Models for NIST Validation Endpoint
---------------------------------------------------------------------
Covers:
    POST /analysis/nist-validation  →  ValidationRequest / ValidationResponse
    POST /validation/user-encryption → UserEncryptionRequest / UserEncryptionResponse

Both plaintext and secret_key are optional for NIST.  When provided, the
Dynamic AES round-trip validation is also executed.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Shared key validator (hex-32)
# ---------------------------------------------------------------------------

_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _validate_key(v: str) -> str:
    if not _HEX32_RE.match(v):
        raise ValueError(
            "secret_key must be exactly 32 hexadecimal characters "
            "(representing a 128-bit AES key)."
        )
    return v.lower()


# ---------------------------------------------------------------------------
# Request — NIST validation (both fields optional)
# ---------------------------------------------------------------------------

class ValidationRequest(BaseModel):
    """
    Input for POST /analysis/nist-validation.

    Both fields are optional:
      - When omitted: only NIST standard tests are executed.
      - When provided: Dynamic AES round-trip validation is also executed.
    """

    plaintext: str | None = Field(
        default=None,
        min_length=1,
        description="UTF-8 plaintext for Dynamic AES round-trip validation (optional).",
        examples=["Hello, Dynamic AES!"],
    )
    secret_key: str | None = Field(
        default=None,
        min_length=32,
        max_length=32,
        description=(
            "AES-128 key as a 32-character hexadecimal string, "
            "required when plaintext is provided."
        ),
        examples=["00112233445566778899aabbccddeeff"],
    )

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str | None) -> str | None:
        if v is not None:
            return _validate_key(v)
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "plaintext": "Hello, Dynamic AES!",
                "secret_key": "00112233445566778899aabbccddeeff"
            }
        }
    }


# ---------------------------------------------------------------------------
# Response — NIST Standard AES
# ---------------------------------------------------------------------------

class NistTestResult(BaseModel):
    """Result for a single NIST AES-128 ECB Known-Answer Test."""

    test_id: int = Field(..., description="Sequential test identifier (1-based).")
    test_name: str = Field(..., description="Human-readable test name.")
    key: str = Field(..., description="AES-128 key used (hex).")
    plaintext: str = Field(..., description="Input plaintext block (hex).")
    expected_ciphertext: str = Field(..., description="NIST-specified expected ciphertext (hex).")
    generated_ciphertext: str = Field(..., description="Ciphertext produced by the implementation (hex).")
    status: str = Field(..., description='"PASS" if generated matches expected, else "FAIL".')


class NistStandardAES(BaseModel):
    """Aggregated result for all NIST AES-128 standard tests."""

    tests_passed: int = Field(..., description="Number of test vectors that passed.")
    tests_failed: int = Field(..., description="Number of test vectors that failed.")
    overall_status: str = Field(..., description='"PASS" if all tests passed, else "FAIL".')
    tests: list[NistTestResult] = Field(..., description="Per-vector results.")


# ---------------------------------------------------------------------------
# Response — Dynamic AES (NIST endpoint)
# ---------------------------------------------------------------------------

class DynamicAESValidation(BaseModel):
    """Result of the Dynamic AES (LFSR) encrypt→decrypt round-trip test."""

    plaintext: str = Field(..., description="Original plaintext used.")
    encryption_status: str = Field(..., description='"SUCCESS" or "ERROR".')
    decryption_status: str = Field(..., description='"SUCCESS" or "ERROR".')
    encryption_decryption_consistency: str = Field(
        ..., description='"PASS" if recovered plaintext matches original, else "FAIL".'
    )
    error: str | None = Field(default=None, description="Error message if an exception occurred.")


# ---------------------------------------------------------------------------
# Top-level response — NIST
# ---------------------------------------------------------------------------

class ValidationResponse(BaseModel):
    """
    Response from POST /analysis/nist-validation.

    ``dynamic_aes`` is null when no plaintext/key was supplied in the request.
    """

    nist_standard_aes: NistStandardAES
    dynamic_aes: DynamicAESValidation | None = Field(
        default=None,
        description="Dynamic AES round-trip validation (null if no plaintext/key supplied).",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "nist_standard_aes": {
                    "tests_passed": 3,
                    "tests_failed": 0,
                    "overall_status": "PASS",
                    "tests": [
                        {
                            "test_id": 1,
                            "test_name": "NIST FIPS-197 Appendix B — AES-128",
                            "key": "000102030405060708090a0b0c0d0e0f",
                            "plaintext": "00112233445566778899aabbccddeeff",
                            "expected_ciphertext": "69c4e0d86a7b0430d8cdb78070b4c55a",
                            "generated_ciphertext": "69c4e0d86a7b0430d8cdb78070b4c55a",
                            "status": "PASS",
                        }
                    ],
                },
                "dynamic_aes": {
                    "plaintext": "Hello, Dynamic AES!",
                    "encryption_status": "SUCCESS",
                    "decryption_status": "SUCCESS",
                    "encryption_decryption_consistency": "PASS",
                    "error": None,
                },
            }
        }
    }


# ===========================================================================
# USER ENCRYPTION VALIDATION MODELS
# POST /validation/user-encryption
# ===========================================================================

# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class UserEncryptionRequest(BaseModel):
    """
    Input for POST /validation/user-encryption.

    Accepts a UTF-8 plaintext and an AES-128 key in one of two formats:
      • **32-character hex string** (e.g. ``00112233445566778899aabbccddeeff``)
      • **16-character UTF-8 string** (e.g. ``securekey1234567``) — will be
        hex-encoded automatically so the rest of the system sees a consistent
        32-char hex key.

    Rejects empty plaintext and keys that are neither 16 UTF-8 bytes nor 32
    hex characters.
    """

    plaintext: str = Field(
        ...,
        min_length=1,
        description="Non-empty UTF-8 string to encrypt and validate.",
        examples=["Hello AES"],
    )
    secret_key: str = Field(
        ...,
        min_length=1,
        description=(
            "AES-128 key — either a 32-character hex string "
            "or a 16-character UTF-8 string."
        ),
        examples=["securekey1234567", "00112233445566778899aabbccddeeff"],
    )

    # Resolved hex key (populated by validator, not part of JSON output)
    _key_hex: str = ""

    @model_validator(mode="after")
    def resolve_key(self) -> "UserEncryptionRequest":
        """
        Normalize secret_key to a 32-char lowercase hex string.

        Accepts:
          1. 32-char hex  → lowercased as-is
          2. 16-char UTF-8 → hex-encoded (16 bytes → 32 hex chars)

        Raises:
          ValueError for anything else.
        """
        k = self.secret_key
        if _HEX32_RE.match(k):
            # Already a valid 32-char hex key
            object.__setattr__(self, "_key_hex", k.lower())
        else:
            # Try UTF-8 byte encoding
            try:
                k_bytes = k.encode("utf-8")
            except Exception:
                raise ValueError(
                    "secret_key could not be encoded as UTF-8."
                )
            if len(k_bytes) != 16:
                raise ValueError(
                    "secret_key must be either a 32-character hexadecimal string "
                    "(AES-128 hex key) or exactly a 16-character UTF-8 string "
                    f"(16 bytes = 128-bit key). Got {len(k_bytes)} byte(s)."
                )
            object.__setattr__(self, "_key_hex", k_bytes.hex())
        return self

    @property
    def key_hex(self) -> str:
        """Resolved 32-char lowercase hex key ready for crypto functions."""
        return self._key_hex

    model_config = {
        "json_schema_extra": {
            "example": {
                "plaintext": "Hello AES",
                "secret_key": "securekey1234567"
            }
        }
    }


# ---------------------------------------------------------------------------
# Response — per-variant AES result
# ---------------------------------------------------------------------------

class AESVariantResult(BaseModel):
    """Encrypt→decrypt result for one AES variant (Standard or Dynamic)."""

    ciphertext: str = Field(..., description="Hex-encoded ciphertext produced by encryption.")
    iv: str = Field(..., description="Hex-encoded IV used during encryption.")
    decrypted: str = Field(..., description="Plaintext recovered by decryption.")
    validation: str = Field(
        ..., description='"PASS" if decrypted == original plaintext, else "FAIL".'
    )
    execution_time: float = Field(
        ..., description="Wall-clock time in seconds for the combined encrypt+decrypt operation."
    )
    error: str | None = Field(default=None, description="Error message if an exception occurred.")


# ---------------------------------------------------------------------------
# Response — top-level
# ---------------------------------------------------------------------------

class UserEncryptionInput(BaseModel):
    """Echo of the input plaintext (key is intentionally omitted for security)."""
    plaintext: str


class UserEncryptionResponse(BaseModel):
    """
    Response from POST /validation/user-encryption.

    Shows encryption/decryption results and validation status for both
    Standard AES and Dynamic AES (LFSR) independently, plus an overall status.
    """

    input: UserEncryptionInput
    standard_aes: AESVariantResult
    dynamic_aes: AESVariantResult
    overall_status: str = Field(
        ...,
        description='"PASS" if both variants validated successfully, else "FAIL".',
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "input": {"plaintext": "Hello AES"},
                "standard_aes": {
                    "ciphertext": "a3f1...",
                    "iv": "b2e0...",
                    "decrypted": "Hello AES",
                    "validation": "PASS",
                    "execution_time": 0.000412,
                    "error": None,
                },
                "dynamic_aes": {
                    "ciphertext": "c7d9...",
                    "iv": "f4a2...",
                    "decrypted": "Hello AES",
                    "validation": "PASS",
                    "execution_time": 0.000538,
                    "error": None,
                },
                "overall_status": "PASS",
            }
        }
    }



