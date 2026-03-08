"""
round_models.py — Pydantic Models for AES Round Analysis Endpoint
-----------------------------------------------------------------
"""

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Request Model
# ---------------------------------------------------------------------------

class AESRoundsRequest(BaseModel):
    plaintext: str = Field(..., description="UTF-8 plaintext to analyze (max 1 block).")
    secret_key: str = Field(..., description="16-character UTF-8 or 32-character Hex key.")

    model_config = {
        "json_schema_extra": {
            "example": {
                "plaintext": "Hello AES",
                "secret_key": "securekey1234567"
            }
        }
    }


# ---------------------------------------------------------------------------
# Trace State Response Models
# ---------------------------------------------------------------------------

class StandardRoundTrace(BaseModel):
    round: int
    sub_bytes: str | None = None
    shift_rows: str | None = None
    mix_columns: str | None = None
    add_round_key: str | None = None
    round_key: str


class DynamicRoundTrace(BaseModel):
    round: int
    lfsr_output: str | None = None
    dynamic_round_key: str | None = None
    sub_bytes: str | None = None
    shift_rows: str | None = None
    mix_columns: str | None = None
    add_round_key: str | None = None


class StandardAESTrace(BaseModel):
    rounds: list[StandardRoundTrace]


class DynamicAESTrace(BaseModel):
    rounds: list[DynamicRoundTrace]


# ---------------------------------------------------------------------------
# Visualization Data
# ---------------------------------------------------------------------------

class VisualizationData(BaseModel):
    round_labels: list[str]
    standard_states: list[str]
    dynamic_states: list[str]


# ---------------------------------------------------------------------------
# Top-Level Response
# ---------------------------------------------------------------------------

class AESRoundsResponse(BaseModel):
    plaintext_hex: str
    standard_aes: StandardAESTrace
    dynamic_aes: DynamicAESTrace
    visualization: VisualizationData

    model_config = {
        "json_schema_extra": {
            "example": {
                "plaintext_hex": "48656c6c6f2041455300000000000000",
                "standard_aes": {
                    "rounds": [
                        {
                            "round": 0,
                            "add_round_key": "3243f6a8885a308d313198a2e0370734",
                            "round_key": "2b7e151628aed2a6abf7158809cf4f3c"
                        }
                    ]
                },
                "dynamic_aes": {
                    "rounds": [
                        {
                            "round": 0,
                            "add_round_key": "1234...",
                            "lfsr_output": "abcd...",
                            "dynamic_round_key": "5678..."
                        }
                    ]
                },
                "visualization": {
                    "round_labels": ["Round 0", "Round 1"],
                    "standard_states": ["3243f6...", "d42711..."],
                    "dynamic_states": ["123456...", "abcdef..."]
                }
            }
        }
    }
