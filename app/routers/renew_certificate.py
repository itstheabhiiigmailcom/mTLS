
# app/routers/renew_certificate.py
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer
from pathlib import Path
import os
import logging
from cryptography.hazmat.primitives import serialization
import sys

# Add the 'app' directory to the Python path to resolve imports
# This is necessary because main.py is run as a script, not as a module within a package.
# When main.py imports routers, it finds them relative to its own location.
# For modules within 'routers' to import from 'ca' or 'create_and_sign',
# 'app' needs to be in the sys.path.
sys.path.append(str(Path(__file__).resolve().parent.parent))

# Now, absolute imports from the 'app' directory should work
from ca.ca_manager import load_intermediate_ca, track_certificate
from create_and_sign import create_entity_certificate

logger = logging.getLogger("pki-server")

router = APIRouter(tags=["Certificates"])

# API Key authentication (copied from other routers)
API_KEYS = os.getenv("ADMIN_API_KEYS", "backend-secret-key,admin-secret-key").split(",")
security = HTTPBearer()

def verify_api_key(authorization: str = Depends(security)):
    if authorization.credentials not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return authorization.credentials

async def _renew_certificate_logic(entity_name: str, entity_type: str, validity_seconds: int, san_list: list):
    """
    Renews a single certificate for a given entity and returns its details.
    """
    logger.info(f"Attempting to renew certificate for {entity_type} '{entity_name}'...")

    # Load intermediate CA
    try:
        inter_key, inter_cert = load_intermediate_ca()
    except Exception as e:
        logger.error(f"Failed to load intermediate CA: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load intermediate CA: {e}")

    # Renew the certificate by creating a new one
    try:
        new_cert = create_entity_certificate(
            entity_name,
            inter_key,
            inter_cert,
            validity_seconds=validity_seconds,
            san_list=san_list
        )
    except Exception as e:
        logger.error(f"Failed to create new certificate for {entity_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create new certificate: {e}")

    # Track the renewed certificate in the database
    base_dir = Path(__file__).resolve().parent.parent # This resolves to the 'app' directory
    pki_dir = base_dir / "pki"
    cert_path = pki_dir / f"{entity_name}.cert.pem"
    track_certificate(f"{entity_type}s", entity_name, new_cert, cert_path)

    logger.info(f"Certificate for '{entity_name}' has been successfully renewed.")

    return {
        "success": True,
        "message": f"Certificate renewed successfully for {entity_name}",
        "certificate": new_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "expires_at": new_cert.not_valid_after_utc.isoformat(),
        "serial_number": str(new_cert.serial_number)
    }

@router.post("/renew-entity-certificate")
async def renew_entity_certificate_api(
    request: dict,
    api_key: str = Depends(verify_api_key)
):
    """
    Renews a certificate for a specified entity (broker, server, robot).
    """
    entity_name = request.get('entity_name')
    
    if not entity_name:
        raise HTTPException(status_code=400, detail="Missing required field: entity_name")

    entity_configs = {
        "broker": {
            "entity_type": "broker",
            "validity_seconds": 360000, # Default validity, can be overridden if needed
            "san_list": ["192.168.0.222", "localhost", "127.0.0.1", "broker", "mosquitto"]
        },
        "server": {
            "entity_type": "server",
            "validity_seconds": 360000, # Default validity
            "san_list": ["192.168.0.222", "localhost", "127.0.0.1", "server"]
        },
        "robot01": { # Example robot, can be generalized
            "entity_type": "robot",
            "validity_seconds": 180, # Default validity
            "san_list": ["raspberrypi.local", "robot01"]
        }
    }

    if entity_name not in entity_configs:
        raise HTTPException(status_code=400, detail=f"Unknown entity: {entity_name}. Available entities: {', '.join(entity_configs.keys())}")

    config = entity_configs[entity_name]
    
    # Allow overriding validity_seconds and san_list from the request body
    validity_seconds = request.get('validity_seconds', config["validity_seconds"])
    san_list = request.get('san_list', config["san_list"])

    try:
        result = await _renew_certificate_logic(
            entity_name,
            config["entity_type"],
            validity_seconds,
            san_list
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Certificate renewal failed for {entity_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Certificate renewal failed: {e}")
