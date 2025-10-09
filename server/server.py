# server/server.py
from pathlib import Path
from fastapi import FastAPI, Request
import ssl
import uvicorn

app = FastAPI()
BASE_DIR = Path(__file__).resolve().parent.parent
PKI_DIR = BASE_DIR / "pki"

@app.get("/hello")
async def hello(request: Request):
    # Optional: extract client cert info (if available)
    client_addr = request.client.host if request.client else None
    print(f"Request received from: {client_addr}")
    return {"message": "Hello from mTLS server! Optional client certificate."}


def run_server(host="127.0.0.1", port=8443):
    server_cert = PKI_DIR / "server.chain.pem"
    server_key = PKI_DIR / "server.key.pem"
    ca_bundle = PKI_DIR / "rootCA.crt.pem"

    # Optional client certificate
    ssl_cert_reqs = ssl.CERT_OPTIONAL

    print(f"Server cert exists: {server_cert.exists()}")
    print(f"Server key exists: {server_key.exists()}")
    print(f"CA bundle exists: {ca_bundle.exists()}")
    print(f"Starting Uvicorn server with optional client certs on {host}:{port}")

    uvicorn.run(
        app,
        host=host,
        port=port,
        ssl_certfile=str(server_cert),
        ssl_keyfile=str(server_key),
        ssl_ca_certs=str(ca_bundle),
        ssl_cert_reqs=ssl_cert_reqs,
        log_level="info"
    )


if __name__ == "__main__":
    run_server()
