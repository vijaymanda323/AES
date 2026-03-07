"""
main.py — FastAPI Application Entry Point
-----------------------------------------
Bootstraps the Dynamic AES with LFSR Key Evolution API:

    * Registers the /crypto router  (encryption / decryption)
    * Registers the /analysis router (security metrics & visualization data)
    * Configures Swagger UI at /docs and ReDoc at /redoc
    * Adds a root health-check endpoint at GET /

Run the server with uvicorn:

    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.crypto_routes   import router as crypto_router
from routes.analysis_routes import router as analysis_router

# ---------------------------------------------------------------------------
# Application metadata (appears in Swagger UI)
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Dynamic AES with LFSR Key Evolution — Analysis API",
    description=(
        "A cryptographic analysis platform for **AES-128-CBC** with **LFSR-based "
        "dynamic key evolution**.\n\n"
        "## Crypto Endpoints (`/crypto`)\n"
        "Encrypt and decrypt data using standard or LFSR-evolved AES keys.\n\n"
        "## Analysis Endpoints (`/analysis`)\n"
        "Generate security metrics and chart-ready visualization data:\n"
        "- **Key Evolution** — AES-128 round key schedule chart\n"
        "- **AES Comparison** — Standard vs Dynamic ciphertexts side-by-side\n"
        "- **Avalanche Effect** — Bit-flip propagation heatmap\n"
        "- **Shannon Entropy** — Byte-frequency histogram\n"
        "- **Performance** — Encrypt/decrypt timing benchmark\n"
        "- **Full Report** — All analyses in one request\n\n"
        "All visualization data is structured for **Chart.js**, **Recharts**, or **D3.js**."
    ),
    version="2.0.0",
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
app.include_router(analysis_router)

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
        "service": "Dynamic AES with LFSR Key Evolution — Analysis API",
        "version": "2.0.0",
        "docs": "/docs",
        "crypto_endpoints": "/crypto",
        "analysis_endpoints": "/analysis",
    }
