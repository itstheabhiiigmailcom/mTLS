# client/client_with_cert.py
import httpx
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PKI_DIR = BASE_DIR / "pki"

def call_server():
    url = "https://localhost:8443/hello"
    
    client_cert = str(PKI_DIR / "robot01.cert.pem")
    client_key = str(PKI_DIR / "robot01.key.pem")
    
    print(f"Client cert exists: {Path(client_cert).exists()}")
    print(f"Client key exists: {Path(client_key).exists()}")
    print(f"Server URL: {url}")
    print("Sending client certificate (server verification is optional)")

    # Still disable verification for now, but send client certificate
    with httpx.Client(
    verify=str(PKI_DIR / "rootCA.crt.pem"),
    cert=(client_cert, client_key),
    ) as client:
        try:
            print("Attempting to connect with client certificate...")
            r = client.get(url)
            print("✅ Success! Connection established with client certificate.")
            print("Status:", r.status_code)
            print("Body:", r.json())
        except httpx.ConnectError as e:
            print(f"❌ Connection error: {e}")
        except Exception as e:
            print(f"❌ Error: {type(e).__name__}: {e}")

if __name__ == "__main__":
    call_server()