"""
crypto_routes.py — API Router for Encryption / Decryption Endpoints
--------------------------------------------------------------------
Defines two routes under the /crypto prefix:

    POST /crypto/encrypt  →  encrypt plaintext with AES-128-CBC + LFSR key
    POST /crypto/decrypt  →  decrypt ciphertext with AES-128-CBC + LFSR key

Each route delegates all cryptographic work to the :mod:`crypto.aes_engine`
module.  HTTP errors are mapped to well-structured JSON responses via
FastAPI's HTTPException.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from crypto.aes_engine import decrypt_data, encrypt_data
from schemas.crypto_schemas import (
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
)

router = APIRouter(
    prefix="/crypto",
    tags=["Cryptography"],
)


# ---------------------------------------------------------------------------
# POST /crypto/encrypt
# ---------------------------------------------------------------------------

@router.post(
    "/encrypt",
    response_model=EncryptResponse,
    status_code=status.HTTP_200_OK,
    summary="Encrypt plaintext with AES-128-CBC + LFSR key evolution",
    description=(
        "Accepts a UTF-8 plaintext string and a 128-bit AES key "
        "(as a 32-character hex string). "
        "Internally the key is evolved using a Galois LFSR before "
        "it is passed to the AES-CBC cipher. "
        "Returns the hex-encoded ciphertext and a fresh random IV."
    ),
    responses={
        200: {"description": "Encryption successful."},
        422: {"description": "Request validation error (invalid key format, empty plaintext, etc.)."},
        400: {"description": "Cryptographic operation failed."},
    },
)
async def encrypt_endpoint(body: EncryptRequest) -> EncryptResponse:
    """Encrypt the supplied plaintext and return ciphertext + IV."""
    try:
        result = encrypt_data(plaintext=body.plaintext, raw_key_hex=body.secret_key)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:  # pragma: no cover — unexpected runtime errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected encryption error: {exc}",
        ) from exc

    return EncryptResponse(
        ciphertext=result["ciphertext"],
        iv=result["iv"],
        message="Encryption successful.",
    )


# ---------------------------------------------------------------------------
# POST /crypto/decrypt
# ---------------------------------------------------------------------------

@router.post(
    "/decrypt",
    response_model=DecryptResponse,
    status_code=status.HTTP_200_OK,
    summary="Decrypt ciphertext with AES-128-CBC + LFSR key evolution",
    description=(
        "Accepts a hex-encoded ciphertext, the corresponding IV, "
        "and the same 128-bit AES key used during encryption. "
        "The key is evolved with the same deterministic LFSR before "
        "decryption so the derived key always matches. "
        "Returns the original UTF-8 plaintext."
    ),
    responses={
        200: {"description": "Decryption successful."},
        422: {"description": "Request validation error."},
        400: {"description": "Decryption failed (bad key, IV, or ciphertext)."},
    },
)
async def decrypt_endpoint(body: DecryptRequest) -> DecryptResponse:
    """Decrypt the supplied ciphertext and return the original plaintext."""
    try:
        plaintext = decrypt_data(
            ciphertext_hex=body.ciphertext,
            iv_hex=body.iv,
            raw_key_hex=body.secret_key,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected decryption error: {exc}",
        ) from exc

    return DecryptResponse(
        plaintext=plaintext,
        message="Decryption successful.",
    )
