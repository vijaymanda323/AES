"""
round_analysis_routes.py — FastAPI Router for AES Round Analysis
----------------------------------------------------------------
Registers endpoint:
    POST /analysis/aes-rounds
"""

from __future__ import annotations

import re
from fastapi import APIRouter, HTTPException, status

from schemas.round_models import (
    AESRoundsRequest,
    AESRoundsResponse,
    DynamicAESTrace,
    DynamicRoundTrace,
    StandardAESTrace,
    StandardRoundTrace,
    VisualizationData,
)
from analysis.round_trace import trace_aes_block

router = APIRouter(
    prefix="/analysis",
    tags=["Round Analysis"],
)

_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")

def _normalize_key(key: str) -> str:
    """Normalize a 16-char UTF-8 or 32-char Hex key to 32-char hex."""
    if _HEX32_RE.match(key):
        return key.lower()
    try:
        k_bytes = key.encode("utf-8")
    except Exception:
        raise ValueError("Key could not be encoded as UTF-8.")
    if len(k_bytes) != 16:
        raise ValueError("Key must be 16 UTF-8 characters or 32 hex characters.")
    return k_bytes.hex()


@router.post(
    "/aes-rounds",
    response_model=AESRoundsResponse,
    status_code=status.HTTP_200_OK,
    summary="AES Round Analysis",
    description="Exposes internal AES state for each transformation round (SubBytes, ShiftRows, MixColumns, AddRoundKey)."
)
async def analyze_aes_rounds(body: AESRoundsRequest) -> AESRoundsResponse:
    # 1. Parse Key
    try:
        raw_key_hex = _normalize_key(body.secret_key)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc)
        ) from exc

    # 2. Parse Plaintext block (pad with zeros if < 16, truncate if > 16)
    pt_bytes = body.plaintext.encode("utf-8")
    if len(pt_bytes) > 16:
        pt_bytes = pt_bytes[:16]
    elif len(pt_bytes) < 16:
        pt_bytes = pt_bytes.ljust(16, b"\x00")

    plaintext_hex = pt_bytes.hex()

    # 3. Trace Standard AES
    try:
        std_trace = trace_aes_block(pt_bytes, raw_key_hex, is_dynamic=False)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error tracing Standard AES: {exc}"
        ) from exc

    # 4. Trace Dynamic AES
    try:
        dyn_trace = trace_aes_block(pt_bytes, raw_key_hex, is_dynamic=True)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error tracing Dynamic AES: {exc}"
        ) from exc

    # 5. Build Standard Trace Models
    standard_rounds = []
    for r in std_trace:
        standard_rounds.append(StandardRoundTrace(
            round=r["round"],
            sub_bytes=r.get("sub_bytes"),
            shift_rows=r.get("shift_rows"),
            mix_columns=r.get("mix_columns"),
            add_round_key=r.get("add_round_key"),
            round_key=r["round_key"]
        ))
    standard_aes = StandardAESTrace(rounds=standard_rounds)

    # 6. Build Dynamic Trace Models
    dynamic_rounds = []
    for r in dyn_trace:
        dynamic_rounds.append(DynamicRoundTrace(
            round=r["round"],
            lfsr_output=r.get("lfsr_output"),
            dynamic_round_key=r.get("dynamic_round_key"),
            sub_bytes=r.get("sub_bytes"),
            shift_rows=r.get("shift_rows"),
            mix_columns=r.get("mix_columns"),
            add_round_key=r.get("add_round_key")
        ))
    dynamic_aes = DynamicAESTrace(rounds=dynamic_rounds)

    # 7. Visualization Data
    round_labels = [f"Round {r['round']}" for r in std_trace]
    standard_states = [r["add_round_key"] for r in std_trace]
    dynamic_states = [r["add_round_key"] for r in dyn_trace]

    visualization = VisualizationData(
        round_labels=round_labels,
        standard_states=standard_states,
        dynamic_states=dynamic_states
    )

    return AESRoundsResponse(
        plaintext_hex=plaintext_hex,
        standard_aes=standard_aes,
        dynamic_aes=dynamic_aes,
        visualization=visualization
    )
