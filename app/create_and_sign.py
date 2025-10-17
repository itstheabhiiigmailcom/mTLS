# scripts/create_and_sign.py
from ca.csr_tools import generate_private_key, write_key_to_pem, create_csr, write_csr_to_pem
from ca.ca_manager import create_self_signed_root, create_intermediate_ca, sign_csr, write_cert_and_chain
from cryptography.hazmat.primitives import serialization
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PKI_DIR = BASE_DIR / "pki"

def setup_pki():
    """Create Root CA, Intermediate CA and CA chain file"""
    root_key, root_cert = create_self_signed_root()
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    
    # Create CA chain file (Intermediate + Root) for verification
    ca_chain_path = PKI_DIR / "ca-chain.pem"
    with open(ca_chain_path, "wb") as f:
        f.write(inter_cert.public_bytes(serialization.Encoding.PEM))
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    print("CA chain created at", ca_chain_path)
    
    return root_key, root_cert, inter_key, inter_cert

def create_entity_certificate(entity_name, inter_key, inter_cert, validity_seconds=120, san_list=None):
    """Create key and certificate for an entity (broker, server, client)"""

    key_path = PKI_DIR / f"{entity_name}.key.pem"
    cert_path = PKI_DIR / f"{entity_name}.cert.pem"

    # Delete old key/cert if exists
    if key_path.exists():
        key_path.unlink()
        print(f"Old key deleted: {key_path}")
    if cert_path.exists():
        cert_path.unlink()
        print(f"Old certificate deleted: {cert_path}")

    # Generate private key
    key = generate_private_key()
    write_key_to_pem(key, str(key_path))

    # Create CSR
    csr = create_csr(key, common_name=entity_name, san_list=san_list)
    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

    # Sign CSR with intermediate CA (validity in minutes)
    cert = sign_csr(inter_key, inter_cert, csr_pem, validity_seconds=validity_seconds)

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"{entity_name} certificate created: {cert_path} (valid for {validity_seconds} minutes)")
    return cert

if __name__ == "__main__":
    # Setup PKI infrastructure
    root_key, root_cert, inter_key, inter_cert = setup_pki()
    
    # Create certificates with actual IP addresses and hostnames
    create_entity_certificate("broker", inter_key, inter_cert, validity_seconds=180,
                             san_list=["192.168.0.222", "localhost", "127.0.0.1", "broker", "mosquitto"])
    
    create_entity_certificate("server", inter_key, inter_cert, validity_seconds=3600,
                             san_list=["192.168.0.222", "localhost", "127.0.0.1", "server"])
    
    create_entity_certificate("robot01", inter_key, inter_cert,  validity_seconds=180,
                             san_list=["raspberrypi.local", "robot01"])
    
    print("\n Generated essential files for mTLS with real IPs/hostnames:")
    print("   - broker.key.pem, broker.cert.pem (for 192.168.0.222)")
    print("   - server.key.pem, server.cert.pem (for 192.168.0.222)") 
    print("   - robot01.key.pem, robot01.cert.pem (for raspberrypi.local)")
    print("   - ca-chain.pem (for all entities)")