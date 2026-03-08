"""
validation_routes.py — FastAPI Routers for Validation Endpoints
---------------------------------------------------------------
Registers two routers:

    POST /analysis/nist-validation
        Always runs official NIST AES-128 ECB Known-Answer Tests.
        Optionally runs Dynamic AES round-trip if plaintext+key supplied.

    POST /validation/user-encryption
        Validates functional correctness of both AES variants for arbitrary
        user-supplied plaintext and key via encrypt→decrypt round-trips.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from analysis.nist_validation import (
    run_dynamic_aes_validation,
    run_nist_standard_tests,
)
from analysis.user_validation import validate_user_encryption
from schemas.validation_models import (
    AESVariantResult,
    DynamicAESValidation,
    NistStandardAES,
    NistTestResult,
    UserEncryptionInput,
    UserEncryptionRequest,
    UserEncryptionResponse,
    ValidationRequest,
    ValidationResponse,
)

# ---------------------------------------------------------------------------
# Router 1 — NIST validation  (prefix: /analysis)
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/analysis",
    tags=["Validation"],
)

# ---------------------------------------------------------------------------
# Router 2 — User encryption validation  (prefix: /validation)
# ---------------------------------------------------------------------------

user_router = APIRouter(
    prefix="/validation",
    tags=["User Encryption Validation"],
)


# ===========================================================================
# POST /analysis/nist-validation
# ===========================================================================

@router.post(
    "/nist-validation",
    response_model=ValidationResponse,
    status_code=status.HTTP_200_OK,
    summary="NIST AES-128 Validation",
    description=(
        "Runs official **NIST FIPS-197** AES-128 ECB Known-Answer Tests "
        "against the implementation and optionally validates **Dynamic AES** "
        "(LFSR key evolution) via an encrypt → decrypt round-trip.\n\n"
        "**NIST tests** are always executed regardless of request body.\n\n"
        "**Dynamic AES validation** is only performed when both `plaintext` "
        "and `secret_key` are supplied.\n\n"
        "NIST test vectors used:\n"
        "1. FIPS-197 Appendix B (key `000102...0e0f`, plaintext `00112233...eeff`)\n"
        "2. NIST ECB KAT GFSbox vector 1 (zero key)\n"
        "3. NIST ECB KAT KeySbox vector 1"
    ),
)
async def nist_validation(body: ValidationRequest = None) -> ValidationResponse:
    """
    Execute NIST AES-128 Known-Answer Tests and optional Dynamic AES validation.
    """
    if body is None:
        body = ValidationRequest()

    has_plaintext = body.plaintext is not None
    has_key       = body.secret_key is not None

    if has_plaintext != has_key:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Both 'plaintext' and 'secret_key' must be provided together, "
                "or both must be omitted."
            ),
        )

    try:
        nist_result = run_nist_standard_tests()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"NIST validation internal error: {exc}",
        ) from exc

    nist_standard_aes = NistStandardAES(
        tests_passed=nist_result["tests_passed"],
        tests_failed=nist_result["tests_failed"],
        overall_status=nist_result["overall_status"],
        tests=[
            NistTestResult(
                test_id=t["test_id"],
                test_name=t["test_name"],
                key=t["key"],
                plaintext=t["plaintext"],
                expected_ciphertext=t["expected_ciphertext"],
                generated_ciphertext=t["generated_ciphertext"],
                status=t["status"],
            )
            for t in nist_result["tests"]
        ],
    )

    dynamic_aes: DynamicAESValidation | None = None

    if has_plaintext and has_key:
        try:
            dyn_result = run_dynamic_aes_validation(body.plaintext, body.secret_key)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Dynamic AES validation internal error: {exc}",
            ) from exc

        dynamic_aes = DynamicAESValidation(
            plaintext=dyn_result["plaintext"],
            encryption_status=dyn_result["encryption_status"],
            decryption_status=dyn_result["decryption_status"],
            encryption_decryption_consistency=dyn_result[
                "encryption_decryption_consistency"
            ],
            error=dyn_result["error"],
        )

    return ValidationResponse(
        nist_standard_aes=nist_standard_aes,
        dynamic_aes=dynamic_aes,
    )


# ===========================================================================
# POST /validation/user-encryption
# ===========================================================================

@user_router.post(
    "/user-encryption",
    response_model=UserEncryptionResponse,
    status_code=status.HTTP_200_OK,
    summary="User Encryption Validation",
    description=(
        "Validates functional correctness of **both AES variants** for any "
        "user-supplied plaintext and key.\n\n"
        "**Validation rule:** `Decrypt(Encrypt(plaintext, key)) == plaintext`\n\n"
        "The endpoint:\n"
        "1. Encrypts the plaintext with **Standard AES-128-CBC** (no LFSR)\n"
        "2. Decrypts the result and checks it matches the original\n"
        "3. Repeats with **Dynamic AES-128-CBC** (LFSR key evolution)\n"
        "4. Returns per-variant results with ciphertext, IV, validation status "
        "and execution time\n\n"
        "**Key formats accepted:**\n"
        "- 32-character hexadecimal string (e.g. `00112233445566778899aabbccddeeff`)\n"
        "- 16-character UTF-8 string (e.g. `securekey1234567`)"
    ),
)
async def user_encryption_validation(body: UserEncryptionRequest) -> UserEncryptionResponse:
    """
    Run encrypt→decrypt round-trips for Standard and Dynamic AES and validate
    that the recovered plaintext matches the original.

    Args:
        body: ``UserEncryptionRequest`` with ``plaintext`` and ``secret_key``.

    Returns:
        ``UserEncryptionResponse`` with per-variant results and overall status.
    """
    try:
        result = validate_user_encryption(body.plaintext, body.key_hex)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"User encryption validation error: {exc}",
        ) from exc

    def _to_variant(d: dict) -> AESVariantResult:
        return AESVariantResult(
            ciphertext=d["ciphertext"],
            iv=d["iv"],
            decrypted=d["decrypted"],
            validation=d["validation"],
            execution_time=d["execution_time"],
            error=d["error"],
        )

    return UserEncryptionResponse(
        input=UserEncryptionInput(plaintext=result["input"]["plaintext"]),
        standard_aes=_to_variant(result["standard_aes"]),
        dynamic_aes=_to_variant(result["dynamic_aes"]),
        overall_status=result["overall_status"],
    )



