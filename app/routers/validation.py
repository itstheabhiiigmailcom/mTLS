# app/routers/validation.py
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer
from ca.ca_manager import get_certificate_info, validate_certificate, load_cert_database, check_all_certificates
import datetime
import os
import logging
from pathlib import Path

logger = logging.getLogger("pki-server")

router = APIRouter(tags=["Validation"])
base_path = Path(__file__).resolve().parent.parent

# API Key authentication
API_KEYS = os.getenv("ADMIN_API_KEYS", "backend-secret-key,admin-secret-key").split(",")
security = HTTPBearer()

def verify_api_key(authorization: str = Depends(security)):
    if authorization.credentials not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return authorization.credentials

@router.get("/certificate-status/{entity_name}")
async def get_certificate_status(entity_name: str, api_key: str = Depends(verify_api_key)):
    """
    Check certificate status and expiry information
    """
    try:
        cert_path = base_path / f"pki/{entity_name}.cert.pem"

        if not cert_path.exists():
            raise HTTPException(status_code=404, detail=f"Certificate not found for {entity_name}")

        info = get_certificate_info(cert_path)

        # Ensure required keys exist
        if info.get("error"):
            return {
                "entity_name": entity_name,
                "is_expired": True,
                "is_revoked": False,
                "error": info["error"]
            }

        # Extract validity dates safely
        not_valid_after = info.get("not_valid_after")
        not_valid_before = info.get("not_valid_before")

        if not not_valid_after:
            logger.warning(f"Missing 'not_valid_after' in certificate info for {entity_name}")
            return {
                "entity_name": entity_name,
                "is_expired": False,
                "is_revoked": False,
                "warning": "Missing not_valid_after field in certificate",
            }

        expiry_date = datetime.datetime.fromisoformat(not_valid_after_utc.replace("Z", "+00:00"))
        days_until_expiry = (expiry_date - datetime.datetime.utcnow()).days

        # Compute flags
        is_expired = days_until_expiry <= 0
        should_renew = days_until_expiry <= 30

        result = {
            "entity_name": entity_name,
            "is_expired": is_expired,
            "is_revoked": info.get("is_revoked", False),
            "not_valid_before": not_valid_before,
            "not_valid_after": not_valid_after,
            "days_until_expiry": days_until_expiry,
            "should_renew": should_renew,
            "renewal_recommended": should_renew,
        }

        logger.info(f"Certificate status for {entity_name}: {days_until_expiry} days until expiry")
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get certificate status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get certificate status: {str(e)}")

@router.get("/certificates")
async def list_all_certificates(api_key: str = Depends(verify_api_key)):
    """
    List all tracked certificates with their status
    """
    try:
        db = load_cert_database()
        status_report = check_all_certificates()
        
        return {
            "certificate_database": db,
            "status_summary": status_report,
            "total_certificates": sum(len(certs) for certs in db.values())
        }
    except Exception as e:
        logger.error(f"Failed to list certificates: {e}")
        raise HTTPException(500, f"Failed to list certificates: {str(e)}")

@router.get("/validate/{entity_name}")
async def validate_certificate_api(entity_name: str, api_key: str = Depends(verify_api_key)):
    """
    Validate a specific certificate
    """
    try:
        cert_path = base_path / f"pki/{entity_name}.cert.pem"
        
        if not cert_path.exists():
            raise HTTPException(404, f"Certificate not found for {entity_name}")
        
        is_valid, message = validate_certificate(cert_path)
        
        return {
            "entity_name": entity_name,
            "is_valid": is_valid,
            "message": message,
            "validation_timestamp": datetime.datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Certificate validation failed: {e}")
        raise HTTPException(500, f"Certificate validation failed: {str(e)}")