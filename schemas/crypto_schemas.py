"""
crypto_schemas.py — Pydantic Request / Response Models
-------------------------------------------------------
All request bodies are validated by FastAPI automatically before any
business logic is invoked.

Key design decisions
~~~~~~~~~~~~~~~~~~~~
* The *secret_key* field accepts a 32-character hexadecimal string so
  that users supply a raw ASCII key that is then hex-encoded, or
  they can supply the hex value directly.  Either way, the field must
  be exactly 32 hex characters (= 16 bytes = 128-bit AES key).
* Both *ciphertext* and *iv* are hex-encoded strings, consistent with
  the output format produced by the encryption endpoint.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Shared validator
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _must_be_hex(value: str, field_name: str = "value") -> str:
    """Ensure *value* contains only hexadecimal characters."""
    if not _HEX_RE.match(value):
        raise ValueError(f"{field_name} must contain only hexadecimal characters (0-9, a-f, A-F).")
    return value.lower()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EncryptRequest(BaseModel):
    """Payload for POST /crypto/encrypt."""

    plaintext: str = Field(
        ...,
        min_length=1,
        description="The UTF-8 plaintext string to encrypt.",
        examples=["Hello, AES + LFSR!"],
    )
    secret_key: str = Field(
        ...,
        min_length=32,
        max_length=32,
        description=(
            "128-bit AES key encoded as a 32-character hexadecimal string. "
            "Example: '00112233445566778899aabbccddeeff'"
        ),
        examples=["00112233445566778899aabbccddeeff"],
    )

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        return _must_be_hex(v, "secret_key")

    model_config = {
        "json_schema_extra": {
            "example": {
                "plaintext": "Hello, Dynamic AES!",
                "secret_key": "00112233445566778899aabbccddeeff",
            }
        }
    }


class DecryptRequest(BaseModel):
    """Payload for POST /crypto/decrypt."""

    ciphertext: str = Field(
        ...,
        min_length=1,
        description="Hex-encoded ciphertext returned by the encrypt endpoint.",
        examples=["a3f1..."],
    )
    iv: str = Field(
        ...,
        min_length=32,
        max_length=32,
        description="Hex-encoded 16-byte Initialisation Vector returned by the encrypt endpoint.",
        examples=["0102030405060708090a0b0c0d0e0f10"],
    )
    secret_key: str = Field(
        ...,
        min_length=32,
        max_length=32,
        description="The same 32-character hex key used during encryption.",
        examples=["00112233445566778899aabbccddeeff"],
    )

    @field_validator("ciphertext", "iv", "secret_key")
    @classmethod
    def validate_hex_fields(cls, v: str, info) -> str:
        return _must_be_hex(v, info.field_name)

    model_config = {
        "json_schema_extra": {
            "example": {
                "ciphertext": "a3f1c2d4...",
                "iv": "0102030405060708090a0b0c0d0e0f10",
                "secret_key": "00112233445566778899aabbccddeeff",
            }
        }
    }


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class EncryptResponse(BaseModel):
    """Successful response from POST /crypto/encrypt."""

    ciphertext: str = Field(..., description="Hex-encoded AES-CBC ciphertext.")
    iv: str = Field(..., description="Hex-encoded 16-byte IV used during encryption.")
    message: str = Field(default="Encryption successful.")

    model_config = {
        "json_schema_extra": {
            "example": {
                "ciphertext": "a3f1c2d4e5b6a7f8...",
                "iv": "0102030405060708090a0b0c0d0e0f10",
                "message": "Encryption successful.",
            }
        }
    }


class DecryptResponse(BaseModel):
    """Successful response from POST /crypto/decrypt."""

    plaintext: str = Field(..., description="Recovered UTF-8 plaintext.")
    message: str = Field(default="Decryption successful.")

    model_config = {
        "json_schema_extra": {
            "example": {
                "plaintext": "Hello, Dynamic AES!",
                "message": "Decryption successful.",
            }
        }
    }


class ErrorResponse(BaseModel):
    """Standard error envelope returned for 4xx / 5xx responses."""

    detail: str = Field(..., description="Human-readable error description.")
