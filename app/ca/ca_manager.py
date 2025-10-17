# ca/ca_manager.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
from pathlib import Path
import json

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
    
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.last_update(datetime.datetime.utcnow())
    builder = builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=7))
    
    # Add revoked certificates
    for revoked_cert in revoked_certs:
        builder = builder.add_revoked_certificate(revoked_cert)
    
    crl = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return crl

def revoke_certificate(inter_key, inter_cert, certificate_serial, reason=None):
    """Revoke a specific certificate and update CRL"""
    # Load existing CRL
    crl_path = CRL_DIR / "intermediate.crl.pem"
    revoked_certs = []
    
    if crl_path.exists():
        with open(crl_path, "rb") as f:
            existing_crl = x509.load_pem_x509_crl(f.read())
            revoked_certs = list(existing_crl)
    
    # Create new revoked certificate entry
    revoked_cert_builder = x509.RevokedCertificateBuilder().serial_number(
        certificate_serial
    ).revocation_date(
        datetime.datetime.utcnow()
    )
    
    if reason:
        revoked_cert_builder = revoked_cert_builder.add_extension(
            x509.CRLReason(reason), critical=False
        )
    
    revoked_cert = revoked_cert_builder.build()
    
    # Add to revoked list
    revoked_certs.append(revoked_cert)
    
    # Create new CRL
    new_crl = create_crl(inter_key, inter_cert, revoked_certs)
    
    # Save CRL
    with open(crl_path, "wb") as f:
        f.write(new_crl.public_bytes(serialization.Encoding.PEM))
    
    print(f" Certificate {certificate_serial} revoked and CRL updated")
    return new_crl

def get_crl():
    """
    Load the current Certificate Revocation List
    """
    try:
        crl_path = CRL_DIR / "intermediate.crl.pem"
        if not crl_path.exists():
            print("CRL file does not exist")
            return None
            
        with open(crl_path, "rb") as f:
            crl_data = f.read()
            print(f"CRL file size: {len(crl_data)} bytes")
            
        # Try to load as CRL
        crl = x509.load_pem_x509_crl(crl_data)
        return crl
        
    except Exception as e:
        print(f"Error loading CRL: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
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
    """Load certificate tracking database"""
    if CERT_DB_PATH.exists():
        with open(CERT_DB_PATH, 'r') as f:
            return json.load(f)
    return {"robots": {}, "servers": {}, "brokers": {}}

def save_cert_database(db):
    """Save certificate tracking database"""
    with open(CERT_DB_PATH, 'w') as f:
        json.dump(db, f, indent=2)

def track_certificate(entity_type, entity_name, cert, cert_path):
    """Track certificate in database"""
    db = load_cert_database()
    
    if entity_name not in db[entity_type]:
        db[entity_type][entity_name] = []
    
    cert_info = {
        'serial_number': str(cert.serial_number),
        'issued_at': datetime.datetime.utcnow().isoformat(),
        'expires_at': cert.not_valid_after_utc.isoformat(),
        'cert_path': str(cert_path),
        'status': 'active'
    }
    
    # Mark previous certificates as inactive
    for old_cert in db[entity_type][entity_name]:
        old_cert['status'] = 'inactive'
    
    db[entity_type][entity_name].append(cert_info)
    save_cert_database(db)
    
    return cert_info

# -----------------------------
# Root CA (supports seconds)
# -----------------------------
def create_self_signed_root(common_name: str = "MyTestRootCA", key_size: int = 4096, validity_seconds: int = 3650*24*3600):
    """
    validity_seconds: lifetime of root CA in seconds
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=60))  # small buffer
        .not_valid_after(now + datetime.timedelta(seconds=validity_seconds))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False
        )
        # Add CRL distribution point
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://pki-server/crl/intermediate.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]),
            critical=False
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    # write files
    key_path = PKI_DIR / "rootCA.key.pem"
    crt_path = PKI_DIR / "rootCA.crt.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Root CA created:", key_path, crt_path)
    return key, cert


# -----------------------------
# Intermediate CA (supports seconds)
# -----------------------------
def create_intermediate_ca(root_key, root_cert, common_name="MyIntermediateCA", key_size: int = 4096, validity_seconds: int = 1825*24*3600):
    """
    validity_seconds: lifetime of intermediate CA in seconds
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=60))  # small buffer
        .not_valid_after(now + datetime.timedelta(seconds=validity_seconds))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False
        )
        # Add CRL distribution point
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://pki-server/crl/intermediate.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]),
            critical=False
        )
    )

    cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    # write files
    key_path = PKI_DIR / "intermediateCA.key.pem"
    crt_path = PKI_DIR / "intermediateCA.crt.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Intermediate CA created:", key_path, crt_path)
    
    # Create initial empty CRL
    initial_crl = create_crl(key, cert)
    crl_path = CRL_DIR / "intermediate.crl.pem"
    with open(crl_path, "wb") as f:
        f.write(initial_crl.public_bytes(serialization.Encoding.PEM))
    print("Initial CRL created at", crl_path)
    
    return key, cert

# -----------------------------
# Sign CSR (Server / Client Certificate)
# -----------------------------
def sign_csr(intermediate_key, intermediate_cert, csr_pem_bytes, validity_seconds=120, is_server_cert=True):
    """Sign a CSR with the intermediate CA."""
    csr = x509.load_pem_x509_csr(csr_pem_bytes)
    if not csr.is_signature_valid:
        raise ValueError("CSR signature invalid")

    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(intermediate_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=10))
        .not_valid_after(now + datetime.timedelta(seconds=validity_seconds))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()),
            critical=False
        )
        # ADD CRL DISTRIBUTION POINTS - THIS IS CRITICAL
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("https://192.168.0.134:8443/app/pki/crl/intermediate.crl.pem")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]),
            critical=False
        )
    )

    # Copy SAN if present in CSR
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san.value, critical=False)
    except x509.ExtensionNotFound:
        pass

    cert = builder.sign(private_key=intermediate_key, algorithm=hashes.SHA256())
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
def validate_certificate(cert_path):
    """Validate certificate expiry and revocation status"""
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        
        # Check expiry
        now = datetime.datetime.utcnow()
        if cert.not_valid_after < now:
            return False, "Certificate has expired"
        
        # Check revocation
        if is_certificate_revoked(cert.serial_number):
            return False, "Certificate is revoked"
        
        return True, "Certificate is valid"
    
    except Exception as e:
        return False, f"Certificate validation failed: {str(e)}"

def check_certificate_expiry(cert_path, days_before=30):
    """Check if certificate expires within specified days"""
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        
        now = datetime.datetime.utcnow()
        expiry_date = cert.not_valid_after
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
            'not_valid_after': cert.not_valid_after_utc.isoformat(),
            'is_expired': cert.not_valid_after < datetime.datetime.utcnow(),
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

# Add to ca/ca_manager.py

def load_intermediate_ca():
    """Load intermediate CA key and certificate"""
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