"""
analysis_routes.py — FastAPI Router for All Analysis Endpoints
--------------------------------------------------------------
Registers 6 routes under the /analysis prefix:

    GET  /analysis/key-evolution      → Round key expansion + evolution chart
    POST /analysis/aes-comparison     → Standard vs Dynamic ciphertext
    POST /analysis/avalanche          → Avalanche effect analysis + heatmap
    POST /analysis/entropy            → Shannon entropy + byte histogram
    POST /analysis/performance        → Encrypt/decrypt timing benchmarks
    POST /analysis/full-report        → Aggregated security report (all above)

All responses are chart-library-ready JSON (Chart.js / Recharts / D3.js).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from analysis.avalanche    import compute_avalanche
from analysis.comparison   import compute_comparison
from analysis.entropy      import compute_entropy
from analysis.performance  import compute_performance
from analysis.visualization import (
    build_entropy_histogram,
    build_key_evolution_chart,
    build_performance_chart,
    build_avalanche_heatmap,
)
from schemas.analysis_models import (
    AESComparisonResponse,
    AnalysisRequest,
    AvalancheResponse,
    AvalancheVisualization,
    EntropyResponse,
    EntropyVisualization,
    ByteFrequency,
    FullReportAvalanche,
    FullReportEntropy,
    FullReportPerformance,
    FullReportResponse,
    FullReportVisualization,
    KeyEvolutionResponse,
    KeyEvolutionVisualization,
    PerformanceResponse,
    PerformanceVisualization,
)
from services.crypto_service import (
    decrypt_dynamic,
    decrypt_standard,
    encrypt_dynamic,
    encrypt_standard,
    get_round_keys,
)

import re, time

router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"],
)

_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _check_key(key: str) -> None:
    """Raise HTTP 422 if *key* is not a valid 32-char hex string."""
    if not _HEX32_RE.match(key):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "secret_key must be exactly 32 hexadecimal characters "
                "(128-bit AES key)."
            ),
        )


# ===========================================================================
# GET /analysis/key-evolution
# ===========================================================================

@router.get(
    "/key-evolution",
    response_model=KeyEvolutionResponse,
    status_code=status.HTTP_200_OK,
    summary="AES-128 Round Key Evolution",
    description=(
        "Runs the AES-128 key schedule on *secret_key* and returns all 11 "
        "round keys (rounds 0–10) together with chart-ready data for "
        "rendering a key-evolution line graph."
    ),
)
async def key_evolution(
    plaintext: str = Query(
        ...,
        min_length=1,
        description="UTF-8 plaintext (used for context; does not affect the key schedule).",
        example="Hello, Dynamic AES!",
    ),
    secret_key: str = Query(
        ...,
        min_length=32,
        max_length=32,
        description="128-bit AES key as a 32-character hexadecimal string.",
        example="00112233445566778899aabbccddeeff",
    ),
) -> KeyEvolutionResponse:
    """Expand *secret_key* into AES-128 round keys and return visualization data."""
    _check_key(secret_key)
    try:
        round_keys = get_round_keys(secret_key.lower())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    chart = build_key_evolution_chart(round_keys)
    return KeyEvolutionResponse(
        round_keys=round_keys,
        visualization=KeyEvolutionVisualization(
            labels=chart["labels"],
            key_values=chart["key_values"],
        ),
    )


# ===========================================================================
# POST /analysis/aes-comparison
# ===========================================================================

@router.post(
    "/aes-comparison",
    response_model=AESComparisonResponse,
    status_code=status.HTTP_200_OK,
    summary="Standard vs Dynamic AES Ciphertext Comparison",
    description=(
        "Encrypts the same plaintext with both **Standard AES** (raw key, no LFSR) "
        "and **Dynamic AES** (LFSR-evolved key). Returns both ciphertexts and IVs "
        "for side-by-side comparison on a dashboard."
    ),
)
async def aes_comparison(body: AnalysisRequest) -> AESComparisonResponse:
    """Return ciphertexts and IVs from both AES variants."""
    try:
        result = compute_comparison(body.plaintext, body.secret_key)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return AESComparisonResponse(**result)


# ===========================================================================
# POST /analysis/avalanche
# ===========================================================================

@router.post(
    "/avalanche",
    response_model=AvalancheResponse,
    status_code=status.HTTP_200_OK,
    summary="Avalanche Effect Analysis",
    description=(
        "Flips a single bit in the plaintext and measures how many ciphertext "
        "bits change (Avalanche %).  A strong cipher should exhibit ≈ 50 % "
        "avalanche.  Returns bit-change data for a heatmap visualization.\n\n"
        "**Formula:** `Avalanche (%) = (changed_bits / total_bits) × 100`"
    ),
)
async def avalanche_effect(body: AnalysisRequest) -> AvalancheResponse:
    """Compute avalanche effect for both Standard and Dynamic AES."""
    try:
        result = compute_avalanche(body.plaintext, body.secret_key)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return AvalancheResponse(
        standard_avalanche=result["standard_avalanche"],
        dynamic_avalanche=result["dynamic_avalanche"],
        visualization=AvalancheVisualization(
            changed_bits=result["visualization"]["changed_bits"],
        ),
    )


# ===========================================================================
# POST /analysis/entropy
# ===========================================================================

@router.post(
    "/entropy",
    response_model=EntropyResponse,
    status_code=status.HTTP_200_OK,
    summary="Shannon Entropy Analysis",
    description=(
        "Computes the Shannon entropy of each AES variant's ciphertext. "
        "A perfectly random ciphertext approaches **8.0 bits/byte**. "
        "Returns a byte-frequency histogram suitable for bar-chart rendering.\n\n"
        "**Formula:** `H = -Σ p(x) · log₂ p(x)`"
    ),
)
async def entropy_analysis(body: AnalysisRequest) -> EntropyResponse:
    """Compute Shannon entropy for both AES variants."""
    try:
        result = compute_entropy(body.plaintext, body.secret_key)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    byte_freq = [
        ByteFrequency(byte=item["byte"], count=item["count"])
        for item in result["visualization"]["byte_frequency"]
    ]
    return EntropyResponse(
        standard_entropy=result["standard_entropy"],
        dynamic_entropy=result["dynamic_entropy"],
        visualization=EntropyVisualization(byte_frequency=byte_freq),
    )


# ===========================================================================
# POST /analysis/performance
# ===========================================================================

@router.post(
    "/performance",
    response_model=PerformanceResponse,
    status_code=status.HTTP_200_OK,
    summary="Encryption / Decryption Performance Benchmark",
    description=(
        "Measures wall-clock execution time (via ``time.perf_counter()``) "
        "for encrypt and decrypt operations of both AES variants. "
        "Returns values in seconds alongside bar-chart data."
    ),
)
async def performance_benchmark(body: AnalysisRequest) -> PerformanceResponse:
    """Benchmark both AES variants and return timing results."""
    try:
        result = compute_performance(body.plaintext, body.secret_key)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return PerformanceResponse(
        standard_encrypt_time=result["standard_encrypt_time"],
        dynamic_encrypt_time=result["dynamic_encrypt_time"],
        standard_decrypt_time=result["standard_decrypt_time"],
        dynamic_decrypt_time=result["dynamic_decrypt_time"],
        visualization=PerformanceVisualization(
            labels=result["visualization"]["labels"],
            values=result["visualization"]["values"],
        ),
    )


# ===========================================================================
# POST /analysis/full-report
# ===========================================================================

@router.post(
    "/full-report",
    response_model=FullReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Full Cryptographic Security Report",
    description=(
        "Runs **all** analysis modules in a single request and returns a "
        "comprehensive security report including: AES comparison, round key "
        "evolution, avalanche effect, Shannon entropy, and performance benchmarks "
        "— all with visualization datasets for a dashboard."
    ),
)
async def full_report(body: AnalysisRequest) -> FullReportResponse:
    """Execute every analysis and return the combined security report."""
    key = body.secret_key
    plaintext = body.plaintext

    try:
        # ── Round keys ─────────────────────────────────────────────────────
        round_keys = get_round_keys(key)
        key_evo_chart = build_key_evolution_chart(round_keys)

        # ── AES comparison ─────────────────────────────────────────────────
        comparison = compute_comparison(plaintext, key)

        # ── Avalanche ──────────────────────────────────────────────────────
        avalanche = compute_avalanche(plaintext, key)

        # ── Entropy ────────────────────────────────────────────────────────
        entropy = compute_entropy(plaintext, key)

        # ── Performance ────────────────────────────────────────────────────
        perf = compute_performance(plaintext, key)

    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return FullReportResponse(
        standard_ciphertext=comparison["standard_ciphertext"],
        dynamic_ciphertext=comparison["dynamic_ciphertext"],
        round_keys=round_keys,
        avalanche=FullReportAvalanche(
            standard=avalanche["standard_avalanche"],
            dynamic=avalanche["dynamic_avalanche"],
        ),
        entropy=FullReportEntropy(
            standard=entropy["standard_entropy"],
            dynamic=entropy["dynamic_entropy"],
        ),
        performance=FullReportPerformance(
            standard_encrypt=perf["standard_encrypt_time"],
            dynamic_encrypt=perf["dynamic_encrypt_time"],
            standard_decrypt=perf["standard_decrypt_time"],
            dynamic_decrypt=perf["dynamic_decrypt_time"],
        ),
        visualization=FullReportVisualization(
            key_evolution_chart=key_evo_chart,
            avalanche_heatmap=avalanche["visualization"],
            entropy_histogram=entropy["visualization"],
            performance_chart=perf["visualization"],
        ),
    )
