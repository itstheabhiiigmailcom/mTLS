# ca/ca_manager.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PKI_DIR = BASE_DIR / "pki"

# -----------------------------
# Root CA
# -----------------------------
def create_self_signed_root(common_name: str = "MyTestRootCA", key_size: int = 4096, days_valid: int = 3650):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
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
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    # write files
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
def create_intermediate_ca(root_key, root_cert, common_name="MyIntermediateCA", key_size: int = 4096, days_valid: int = 1825):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
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
    )

    cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    # write files
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
    return key, cert


# -----------------------------
# Sign CSR (Server / Client Certificate)
# -----------------------------
def sign_csr(intermediate_key, intermediate_cert, csr_pem_bytes, days_valid=825, is_server_cert=True):
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
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
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
# Example CLI usage
# -----------------------------
if __name__ == "__main__":
    root_key, root_cert = create_self_signed_root()
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)