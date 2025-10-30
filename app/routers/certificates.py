# app/routers/certificates.py
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.security import HTTPBearer
from cryptography import x509
from cryptography.x509 import ReasonFlags
from cryptography.hazmat.primitives import serialization
from ca.ca_manager import (
    sign_csr, revoke_certificate, load_cert_database, 
    track_certificate, is_certificate_revoked, load_intermediate_ca
)
from datetime import datetime, timezone
import os
import logging
from pathlib import Path
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("pki-server")

router = APIRouter(tags=["Certificates"])
base_path = Path(__file__).resolve().parent.parent
# API Key authentication
API_KEYS = os.getenv("ADMIN_API_KEYS", "backend-secret-key,admin-secret-key").split(",")
security = HTTPBearer()

def verify_api_key(authorization: str = Depends(security)):
    if authorization.credentials not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return authorization.credentials

@router.post("/renew-certificate")
async def renew_certificate(
    request: dict,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Renew a certificate (primarily for robots)
    """
    try:
        robot_id = request.get('robot_id')
        current_cert_pem = request.get('current_certificate')
        csr_pem = request.get('csr')
        
        logger.info(f"Certificate renewal request: robot_id={robot_id}, has_current_cert={bool(current_cert_pem)}, has_csr={bool(csr_pem)}")
        
        if not all([robot_id, csr_pem]):
            raise HTTPException(400, "Missing required fields: robot_id and csr")
        
        logger.info(f"Certificate renewal requested for robot: {robot_id}")
        
        # Load intermediate CA
        inter_key, inter_cert = load_intermediate_ca()
        
        # Validate current certificate if provided
        if current_cert_pem:
            try:
                current_cert = x509.load_pem_x509_certificate(current_cert_pem.encode('utf-8'), default_backend())
                
                # Only warn about expiry/revocation but don't block renewal
                if current_cert.not_valid_after_utc < datetime.now(timezone.utc):
                    logger.warning(f"Current certificate for {robot_id} has expired - allowing renewal")
                
                if is_certificate_revoked(current_cert.serial_number):
                    logger.warning(f"Current certificate for {robot_id} is revoked - allowing renewal")
                    
            except Exception as e:
                logger.warning(f"Could not validate current certificate: {e} - proceeding with renewal")
        
        # Sign new certificate - FIXED: Use proper days_valid and handle CSR as string
        try:
            # The CSR comes as a PEM string from the client
            new_cert = sign_csr(
                inter_key, 
                inter_cert, 
                csr_pem.encode('utf-8'),  # Convert string to bytes
                validity_seconds=30 * 60
            )
        except Exception as e:
            logger.error(f"Failed to sign CSR: {e}")
            raise HTTPException(400, f"Invalid CSR: {str(e)}")
        
        # Track in database
        cert_path = base_path / f"pki/{robot_id}.cert.pem"
        with open(cert_path, "wb") as f:
            f.write(new_cert.public_bytes(serialization.Encoding.PEM))
        track_certificate("robots", robot_id, new_cert, cert_path)
        
        logger.info(f"Certificate renewed successfully for robot: {robot_id}")
        
        # Return certificate as properly formatted PEM string
        cert_pem = new_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        return {
            "success": True,
            "message": "Certificate renewed successfully",
            "certificate": cert_pem,
            "expires_at": new_cert.not_valid_after_utc.isoformat() if hasattr(new_cert, 'not_valid_after_utc') else new_cert.not_valid_after_utc.isoformat(),
            "serial_number": str(new_cert.serial_number)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Certificate renewal failed: {str(e)}")
        raise HTTPException(500, f"Renewal failed: {str(e)}")

@router.post("/revoke-certificate")
async def revoke_certificate_api(
    request: dict,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Revoke a certificate (admin function)
    """
    try:
        entity_name = request.get('entity_name')
        entity_type = request.get('entity_type', 'robot')
        reason_str = request.get('reason', 'unspecified')  # keep input as string

        if not entity_name:
            raise HTTPException(400, "Entity name required")
        
        # For security, only allow robot revocation via API initially
        if entity_type != 'robot':
            raise HTTPException(403, "Can only revoke robots via API. Servers/brokers require manual rotation.")
        
        logger.warning(f"Revocation requested for {entity_type}: {entity_name}, reason: {reason_str}")
        
        # ✅ Convert string reason to ReasonFlags enum
        try:
            reason_flag = getattr(ReasonFlags, reason_str)
        except AttributeError:
            raise HTTPException(
                400, 
                f"Invalid revocation reason: '{reason_str}'. Must be one of: "
                "unspecified, key_compromise, ca_compromise, affiliation_changed, "
                "superseded, cessation_of_operation, certificate_hold, privilege_withdrawn, aa_compromise"
            )

        # Load certificate to get serial number
        cert_path = base_path / f"pki/{entity_name}.cert.pem"
        if not cert_path.exists():
            raise HTTPException(404, f"Certificate not found for {entity_name}")
        
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        
        # Load intermediate CA and revoke
        inter_key, inter_cert = load_intermediate_ca()
        crl = revoke_certificate(inter_key, inter_cert, cert.serial_number, reason_flag)  # ✅ pass enum, not string
        
        logger.warning(f"Certificate revoked: {entity_name}, serial: {cert.serial_number}, reason: {reason_str}")
        
        return {
            "success": True,
            "message": f"Certificate revoked for {entity_name}",
            "serial_number": str(cert.serial_number),
            "revocation_date": datetime.utcnow().isoformat(),
            "reason": reason_str
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Certificate revocation failed: {str(e)}")
        raise HTTPException(500, f"Revocation failed: {str(e)}")