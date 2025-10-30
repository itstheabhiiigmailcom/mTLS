# scripts/create_and_sign.py

from ca.csr_tools import generate_private_key, write_key_to_pem, create_csr, write_csr_to_pem
from ca.ca_manager import create_self_signed_root, create_intermediate_ca, sign_csr, write_cert_and_chain
from cryptography.hazmat.primitives import serialization
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PKI_DIR = BASE_DIR / "pki"


def setup_pki():
    """Create Root CA and Intermediate CA"""
    root_key, root_cert = create_self_signed_root()
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    return root_key, root_cert, inter_key, inter_cert


def create_entity_certificate(entity_name, inter_key, inter_cert, validity_seconds=120, san_list=None):
    """Create key and certificate for an entity (broker, server, client)"""
    key_path = PKI_DIR / f"{entity_name}.key.pem"
    cert_path = PKI_DIR / f"{entity_name}.cert.pem"

    # Remove existing files if present
    if key_path.exists():
        key_path.unlink()
    if cert_path.exists():
        cert_path.unlink()

    # Generate private key
    key = generate_private_key()
    write_key_to_pem(key, str(key_path))

    # Create CSR
    csr = create_csr(key, common_name=entity_name, san_list=san_list)
    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

    # Sign CSR
    cert = sign_csr(inter_key, inter_cert, csr_pem, validity_seconds=validity_seconds)

    # Write cert to file
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"{entity_name} certificate created: {cert_path} (valid for {validity_seconds} seconds)")
    return key, cert


if __name__ == "__main__":
    # Setup PKI (Root + Intermediate)
    root_key, root_cert, inter_key, inter_cert = setup_pki()

    # Create broker certificate
    broker_key, broker_cert = create_entity_certificate(
        "broker",
        inter_key,
        inter_cert,
        validity_seconds=3600,
        san_list=["192.168.0.222",  "mosquitto", "localhost", "127.0.0.1", "broker"]
    )

    # --- 🔗 Create Broker + Intermediate Chain ---
    broker_chain_path = PKI_DIR / "broker-chain.pem"
    with open(broker_chain_path, "wb") as f:
        f.write(broker_cert.public_bytes(serialization.Encoding.PEM))
        f.write(inter_cert.public_bytes(serialization.Encoding.PEM))
    print("Broker chain created at", broker_chain_path)

    # Create server certificate
    create_entity_certificate(
        "server",
        inter_key,
        inter_cert,
        validity_seconds=3600,
        san_list=["192.168.0.222", "localhost", "127.0.0.1", "server"]
    )

    # Create robot01 certificate
    create_entity_certificate(
        "robot01",
        inter_key,
        inter_cert,
        validity_seconds=3600,
        san_list=["raspberrypi.local", "robot01"]
    )

    print("\nGenerated essential files for mTLS:")
    print(" - broker.key.pem, broker.cert.pem, broker-chain.pem (for broker)")
    print(" - server.key.pem, server.cert.pem (for server)")
    print(" - robot01.key.pem, robot01.cert.pem (for raspberrypi)")
    print(" - Root certificate to distribute to clients (rootCA.crt.pem)")
