# pki-server/app.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
from pathlib import Path
import uvicorn
from create_and_sign import setup_pki


# Import routers
from routers import health, certificates, crl, validation, issuance

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pki-server")

app = FastAPI(
    title="PKI Server API",
    description="Certificate Authority Management Server",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all routers with api/v1 prefix
app.include_router(health.router, prefix="/api/v1")
app.include_router(certificates.router, prefix="/api/v1")
app.include_router(crl.router, prefix="/api/v1")
app.include_router(validation.router, prefix="/api/v1")
app.include_router(issuance.router, prefix="/api/v1")

@app.get("/")
async def root():
    return {
        "status": "PKI Server Running",
        "timestamp": "use /api/v1/health for detailed status",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    # Get path two levels above current file
    base_dir = Path(__file__).resolve().parent
    pki_dir = base_dir / "pki"

    print("PKI Directory:", pki_dir)

    # Check if root CA exists
    if not (pki_dir / "rootCA.crt.pem").exists():
        logger.info("PKI not initialized. Running initial setup...")
        setup_pki()

    # Start the server
    cert_path = pki_dir / "server.cert.pem"
    key_path = pki_dir / "server.key.pem"

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8443,
        ssl_certfile=str(cert_path) if cert_path.exists() else None,
        ssl_keyfile=str(key_path) if key_path.exists() else None
    )