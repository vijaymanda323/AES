"""
main.py — FastAPI Application Entry Point
-----------------------------------------
Bootstraps the Dynamic AES Encryption API:

    * Registers the /crypto router
    * Configures Swagger UI at /docs and ReDoc at /redoc
    * Adds a root health-check endpoint at GET /

Run the server with uvicorn:

    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.crypto_routes import router as crypto_router

# ---------------------------------------------------------------------------
# Application metadata (appears in Swagger UI)
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Dynamic AES Encryption API",
    description=(
        "A cybersecurity demonstration API implementing **AES-128-CBC** encryption "
        "with **LFSR-based dynamic key evolution**.\n\n"
        "### How it works\n"
        "1. The caller supplies a 128-bit key as a 32-character hex string.\n"
        "2. A 32-bit Galois LFSR is seeded deterministically from that key.\n"
        "3. The LFSR emits 16 pseudorandom bytes.\n"
        "4. The raw key is XOR-ed with the LFSR stream to produce the **DynamicKey**.\n"
        "5. AES-128-CBC encrypts/decrypts using the DynamicKey and a random IV.\n\n"
        "Because the LFSR seed is derived from the key itself, both encrypt and "
        "decrypt always arrive at the **same** DynamicKey — no extra state exchange."
    ),
    version="1.0.0",
    contact={
        "name": "AES Project Team",
    },
    license_info={
        "name": "MIT",
    },
    docs_url="/docs",   # Swagger UI
    redoc_url="/redoc", # ReDoc
    openapi_url="/openapi.json",
)

# ---------------------------------------------------------------------------
# CORS — allow all origins (suitable for a local development / demo server)
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(crypto_router)

# ---------------------------------------------------------------------------
# Root health-check
# ---------------------------------------------------------------------------

@app.get(
    "/",
    tags=["Health"],
    summary="Health check",
    description="Returns a simple status message confirming the API is running.",
)
async def root() -> dict[str, str]:
    """Root endpoint — useful for load-balancer health checks."""
    return {
        "status": "ok",
        "service": "Dynamic AES Encryption API",
        "version": "1.0.0",
        "docs": "/docs",
    }
