# ca/ca_manager.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta
from pathlib import Path
import json
from cryptography.hazmat.backends import default_backend

BASE_DIR = Path(__file__).resolve().parent.parent
PKI_DIR = BASE_DIR / "pki"
CRL_DIR = PKI_DIR / "crl"

# Ensure directories exist
PKI_DIR.mkdir(exist_ok=True)
CRL_DIR.mkdir(exist_ok=True)

# -----------------------------
# CRL Management
# -----------------------------

def create_crl(issuer_key, issuer_cert, revoked_certs=None):
    """Create Certificate Revocation List"""
    if revoked_certs is None:
        revoked_certs = []

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=7))
    )

    for revoked_cert in revoked_certs:
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return crl


def revoke_certificate(inter_key, inter_cert, certificate_serial, reason=None):
    """Revoke a specific certificate and update CRL"""
    crl_path = CRL_DIR / "intermediate.crl.pem"
    revoked_certs = []

    if crl_path.exists():
        with open(crl_path, "rb") as f:
            existing_crl = x509.load_pem_x509_crl(f.read())
            revoked_certs = list(existing_crl)

    revoked_cert_builder = (
        x509.RevokedCertificateBuilder()
        .serial_number(certificate_serial)
        .revocation_date(datetime.now(timezone.utc))
    )

    if reason:
        revoked_cert_builder = revoked_cert_builder.add_extension(
            x509.CRLReason(reason), critical=False
        )

    revoked_cert = revoked_cert_builder.build()
    revoked_certs.append(revoked_cert)

    new_crl = create_crl(inter_key, inter_cert, revoked_certs)
    with open(crl_path, "wb") as f:
        f.write(new_crl.public_bytes(serialization.Encoding.PEM))

    print(f"✅ Certificate {certificate_serial} revoked and CRL updated")
    return new_crl


def get_crl():
    """Load current Certificate Revocation List"""
    try:
        crl_path = CRL_DIR / "intermediate.crl.pem"
        if not crl_path.exists():
            print("CRL file does not exist")
            return None

        with open(crl_path, "rb") as f:
            crl_data = f.read()
            print(f"CRL file size: {len(crl_data)} bytes")

        return x509.load_pem_x509_crl(crl_data)

    except Exception as e:
        print(f"Error loading CRL: {e}")
        import traceback
        print(traceback.format_exc())
        return None


def is_certificate_revoked(certificate_serial):
    """Check if a certificate is revoked"""
    crl = get_crl()
    if crl:
        for revoked_cert in crl:
            if revoked_cert.serial_number == certificate_serial:
                return True
    return False


# -----------------------------
# Certificate Database for Rotation Tracking
# -----------------------------
CERT_DB_PATH = PKI_DIR / "certificate_database.json"

def load_cert_database():
    if CERT_DB_PATH.exists():
        with open(CERT_DB_PATH, "r") as f:
            return json.load(f)
    return {"robots": {}, "servers": {}, "brokers": {}}


def save_cert_database(db):
    with open(CERT_DB_PATH, "w") as f:
        json.dump(db, f, indent=2)


def track_certificate(entity_type, entity_name, cert, cert_path):
    """Track certificate in database"""
    db = load_cert_database()

    if entity_name not in db[entity_type]:
        db[entity_type][entity_name] = []

    expires_at = cert.not_valid_after_utc.replace(tzinfo=timezone.utc)

    cert_info = {
        "serial_number": str(cert.serial_number),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at.isoformat(),
        "cert_path": str(cert_path),
        "status": "active",
    }

    for old_cert in db[entity_type][entity_name]:
        old_cert["status"] = "inactive"

    db[entity_type][entity_name].append(cert_info)
    save_cert_database(db)
    return cert_info
# -----------------------------
# Root CA (supports seconds)
# -----------------------------
def create_self_signed_root(common_name="MyTestRootCA", key_size=4096, validity_seconds=3650 * 24 * 3600):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=60))
        .not_valid_after(now + timedelta(seconds=validity_seconds))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    key_path = PKI_DIR / "rootCA.key.pem"
    crt_path = PKI_DIR / "rootCA.crt.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Root CA created:", key_path, crt_path)
    return key, cert

# -----------------------------
# Intermediate CA
# -----------------------------
def create_intermediate_ca(root_key, root_cert, common_name="MyIntermediateCA", key_size=4096, validity_seconds=1825 * 24 * 3600):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=60))
        .not_valid_after(now + timedelta(seconds=validity_seconds))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )

    key_path = PKI_DIR / "intermediateCA.key.pem"
    crt_path = PKI_DIR / "intermediateCA.crt.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Intermediate CA created:", key_path, crt_path)

    crl_path = CRL_DIR / "intermediate.crl.pem"
    crl = create_crl(key, cert)
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    print("Initial CRL created at", crl_path)
    return key, cert

# -----------------------------
# Sign CSR
# -----------------------------
def sign_csr(issuer_key, issuer_cert, csr_pem, validity_seconds=3600):
    csr = x509.load_pem_x509_csr(csr_pem)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(seconds=validity_seconds))
    )

    # Copy extensions (e.g. SAN)
    for ext in csr.extensions:
        cert_builder = cert_builder.add_extension(ext.value, ext.critical)

    cert = cert_builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return cert


# -----------------------------
# Write certificate + full chain
# -----------------------------
def write_cert_and_chain(cert, chain, out_cert_path: str):
    """
    cert: end-entity certificate (server/client)
    chain: list of certificates to append after (intermediate -> root)
    """
    with open(out_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        for c in chain:
            f.write(c.public_bytes(serialization.Encoding.PEM))
    print("Wrote certificate + chain to", out_cert_path)


# -----------------------------
# Certificate Validation and Monitoring
# -----------------------------
def validate_certificate(cert_path: Path):
    """
    Validate certificate expiry and revocation status (via CRL)
    """
    try:
        # Load the certificate
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Check expiry
        now = datetime.now(timezone.utc)
        if cert.not_valid_after_utc < now:
            return False, "Certificate has expired"

        # Load CRL file
        crl_path = CRL_DIR / "intermediate.crl.pem"
        if not crl_path.exists():
            return True, "CRL not found — assuming valid"

        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read(), default_backend())

        # Check if serial number is revoked
        revoked_serials = [r.serial_number for r in crl]
        if cert.serial_number in revoked_serials:
            return False, "Certificate is revoked"

        # Certificate is fine
        return True, "Certificate is valid"

    except Exception as e:
        return False, f"Certificate validation failed: {str(e)}"
    
    
def check_certificate_expiry(cert_path, days_before=30):
    """Check if certificate expires within specified days"""
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        
        now = datetime.now(timezone.utc)
        expiry_date = cert.not_valid_after_utc
        days_until_expiry = (expiry_date - now).days
        
        if days_until_expiry <= days_before:
            return True, days_until_expiry
        else:
            return False, days_until_expiry
    
    except Exception as e:
        return False, f"Error checking expiry: {str(e)}"

def get_certificate_info(cert_path):
    """Get detailed certificate information"""
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        
        info = {
            'subject': dict(cert.subject),
            'issuer': dict(cert.issuer),
            'serial_number': str(cert.serial_number),
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after_utc': cert.not_valid_after_utc.isoformat(),
            'is_expired': cert.not_valid_after_utc < datetime.now(timezone.utc),
            'is_revoked': is_certificate_revoked(cert.serial_number)
        }
        
        # Extract SANs if present
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info['subject_alt_names'] = [str(name) for name in san.value]
        except x509.ExtensionNotFound:
            info['subject_alt_names'] = []
        
        return info
    
    except Exception as e:
        return {'error': str(e)}

# -----------------------------
# Bulk Operations
# -----------------------------
def check_all_certificates(days_before=30):
    """Check status of all tracked certificates"""
    db = load_cert_database()
    results = {
        'expiring_soon': [],
        'expired': [],
        'revoked': [],
        'valid': []
    }
    
    for entity_type in ['robots', 'servers', 'brokers']:
        for entity_name, certs in db[entity_type].items():
            for cert_info in certs:
                if cert_info['status'] == 'active':
                    cert_path = Path(cert_info['cert_path'])
                    if cert_path.exists():
                        is_valid, message = validate_certificate(cert_path)
                        is_expiring, days_left = check_certificate_expiry(cert_path, days_before)
                        
                        cert_status = {
                            'entity_type': entity_type[:-1],
                            'entity_name': entity_name,
                            'serial_number': cert_info['serial_number'],
                            'expires_at': cert_info['expires_at'],
                            'days_until_expiry': days_left if isinstance(days_left, int) else -1,
                            'status': 'valid'
                        }
                        
                        if not is_valid:
                            if "expired" in message.lower():
                                results['expired'].append(cert_status)
                            elif "revoked" in message.lower():
                                results['revoked'].append(cert_status)
                        elif is_expiring:
                            results['expiring_soon'].append(cert_status)
                        else:
                            results['valid'].append(cert_status)
    
    return results

def load_intermediate_ca():
    try:
        with open(PKI_DIR / "intermediateCA.key.pem", "rb") as f:
            inter_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PKI_DIR / "intermediateCA.crt.pem", "rb") as f:
            inter_cert = x509.load_pem_x509_certificate(f.read())
        return inter_key, inter_cert
    except Exception as e:
        raise Exception(f"Failed to load intermediate CA: {e}")
# -----------------------------
# Example CLI usage
# -----------------------------
if __name__ == "__main__":
    root_key, root_cert = create_self_signed_root()
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    
    print("\n PKI Infrastructure initialized with:")
    print("   - Root CA Certificate")
    print("   - Intermediate CA Certificate") 
    print("   - Initial CRL")
    print("   - Certificate tracking database")