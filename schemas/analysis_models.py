"""
analysis_models.py — Pydantic Request / Response Models for Analysis Endpoints
-------------------------------------------------------------------------------
All request bodies share the same two-field input:
    plaintext   — UTF-8 string to analyse
    secret_key  — 32-character hex AES-128 key

Responses are structured for direct consumption by frontend visualisation
libraries (Chart.js, Recharts, D3.js).
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Shared validator
# ---------------------------------------------------------------------------

_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _validate_key(v: str) -> str:
    """Ensure the secret_key is a valid 32-character hex string."""
    if not _HEX32_RE.match(v):
        raise ValueError(
            "secret_key must be exactly 32 hexadecimal characters "
            "(representing a 128-bit AES key)."
        )
    return v.lower()


# ---------------------------------------------------------------------------
# Shared request model (used by POST endpoints)
# ---------------------------------------------------------------------------

class AnalysisRequest(BaseModel):
    """Shared input model used by all analysis POST endpoints."""

    plaintext: str = Field(
        ...,
        min_length=1,
        description="UTF-8 plaintext string to analyse.",
        examples=["Hello, Dynamic AES!"],
    )
    secret_key: str = Field(
        ...,
        min_length=32,
        max_length=32,
        description="AES-128 key as a 32-character hexadecimal string.",
        examples=["00112233445566778899aabbccddeeff"],
    )

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        return _validate_key(v)

    model_config = {
        "json_schema_extra": {
            "example": {
                "plaintext": "Hello, Dynamic AES!",
                "secret_key": "00112233445566778899aabbccddeeff",
            }
        }
    }


# ---------------------------------------------------------------------------
# Key Evolution
# ---------------------------------------------------------------------------

class KeyEvolutionVisualization(BaseModel):
    labels: list[str] = Field(..., description="Round labels, e.g. ['Round 0', 'Round 1', ...]")
    key_values: list[int] = Field(..., description="First-byte value of each round key (0-255).")


class KeyEvolutionResponse(BaseModel):
    """Response from GET /analysis/key-evolution."""

    round_keys: list[str] = Field(
        ...,
        description="11 AES-128 round keys as 32-character hex strings (rounds 0–10).",
    )
    visualization: KeyEvolutionVisualization

    model_config = {
        "json_schema_extra": {
            "example": {
                "round_keys": ["00112233445566778899aabbccddeeff", "..."],
                "visualization": {
                    "labels": ["Round 0", "Round 1"],
                    "key_values": [0, 163],
                },
            }
        }
    }


# ---------------------------------------------------------------------------
# AES Comparison
# ---------------------------------------------------------------------------

class AESComparisonResponse(BaseModel):
    """Response from POST /analysis/aes-comparison."""

    standard_ciphertext: str = Field(..., description="Hex-encoded standard AES ciphertext.")
    dynamic_ciphertext:  str = Field(..., description="Hex-encoded dynamic AES ciphertext.")
    standard_iv:         str = Field(..., description="Hex-encoded IV used for standard AES.")
    dynamic_iv:          str = Field(..., description="Hex-encoded IV used for dynamic AES.")


# ---------------------------------------------------------------------------
# Avalanche Effect
# ---------------------------------------------------------------------------

class AvalancheVisualization(BaseModel):
    changed_bits: list[int] = Field(
        ...,
        description="Per-bit difference array (1 = changed, 0 = unchanged) across all ciphertext bits.",
    )


class AvalancheResponse(BaseModel):
    """Response from POST /analysis/avalanche."""

    standard_avalanche: float = Field(..., description="Avalanche percentage for standard AES (0–100).")
    dynamic_avalanche:  float = Field(..., description="Avalanche percentage for dynamic AES (0–100).")
    visualization: AvalancheVisualization


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

class ByteFrequency(BaseModel):
    byte:  int = Field(..., description="Byte value (0–255).")
    count: int = Field(..., description="Number of occurrences in the ciphertext.")


class EntropyVisualization(BaseModel):
    byte_frequency: list[ByteFrequency] = Field(
        ..., description="Byte frequency histogram of the dynamic ciphertext."
    )


class EntropyResponse(BaseModel):
    """Response from POST /analysis/entropy."""

    standard_entropy: float = Field(..., description="Shannon entropy of standard AES ciphertext (0–8).")
    dynamic_entropy:  float = Field(..., description="Shannon entropy of dynamic AES ciphertext (0–8).")
    visualization: EntropyVisualization


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

class PerformanceVisualization(BaseModel):
    labels: list[str]  = Field(..., description="Operation labels.")
    values: list[float] = Field(..., description="Times in seconds for each operation.")


class PerformanceResponse(BaseModel):
    """Response from POST /analysis/performance."""

    standard_encrypt_time: float = Field(..., description="Standard AES encrypt time in seconds.")
    dynamic_encrypt_time:  float = Field(..., description="Dynamic AES encrypt time in seconds.")
    standard_decrypt_time: float = Field(..., description="Standard AES decrypt time in seconds.")
    dynamic_decrypt_time:  float = Field(..., description="Dynamic AES decrypt time in seconds.")
    visualization: PerformanceVisualization


# ---------------------------------------------------------------------------
# Full Report
# ---------------------------------------------------------------------------

class FullReportAvalanche(BaseModel):
    standard: float
    dynamic:  float


class FullReportEntropy(BaseModel):
    standard: float
    dynamic:  float


class FullReportPerformance(BaseModel):
    standard_encrypt: float
    dynamic_encrypt:  float
    standard_decrypt: float
    dynamic_decrypt:  float


class FullReportVisualization(BaseModel):
    key_evolution_chart: dict[str, Any] = Field(..., description="Key evolution line-chart data.")
    avalanche_heatmap:   dict[str, Any] = Field(..., description="Bit-change heatmap data.")
    entropy_histogram:   dict[str, Any] = Field(..., description="Byte-frequency histogram data.")
    performance_chart:   dict[str, Any] = Field(..., description="Performance bar-chart data.")


class FullReportResponse(BaseModel):
    """Response from POST /analysis/full-report."""

    standard_ciphertext: str
    dynamic_ciphertext:  str
    round_keys:   list[str]
    avalanche:    FullReportAvalanche
    entropy:      FullReportEntropy
    performance:  FullReportPerformance
    visualization: FullReportVisualization
