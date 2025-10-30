# app/routers/health.py
from fastapi import APIRouter
import datetime
from pathlib import Path
import logging

logger = logging.getLogger("pki-server")

router = APIRouter(tags=["Health"])

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check if essential PKI files exist
        pki_dir = Path(__file__).resolve().parent.parent / "pki"
        status = {
            "status": "healthy",
            "root_ca_exists": (pki_dir / "rootCA.crt.pem").exists(),
            "intermediate_ca_exists": (pki_dir / "intermediateCA.crt.pem").exists(),
            "crl_exists": (pki_dir / "crl" / "intermediate.crl.pem").exists(),
            "certificate_database_exists": (pki_dir / "certificate_database.json").exists(),
            "timestamp": datetime.utcnow().isoformat()
        }
        return status
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}