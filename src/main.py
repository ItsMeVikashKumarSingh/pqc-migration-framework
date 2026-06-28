import os
import sys
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# Add parent directory to path so we can import pqc_sdk
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pqc_sdk.hybrid_kem import HybridKEM
from pqc_sdk.hybrid_sig import HybridSigner

app = FastAPI(title="PQC Migration Framework Control Panel")

# Setup templates
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/api/calculate-risk")
def calculate_risk(L: float, M: float, C: float):
    """
    Mosca's Theorem Risk Assessment:
    L: Data Shelf Life (years)
    M: Migration Time (years)
    C: Collapse Time (years)
    """
    risk_score = 0.0
    priority = "Low"
    
    # Simple risk modeling based on L + M vs C
    combined_time = L + M
    if combined_time >= C:
        # High exposure
        risk_score = min(100.0, 50.0 + ((combined_time - C) / C) * 50.0)
        priority = "Immediate" if L + M > C + 2 else "High"
    else:
        # Medium or Low exposure
        risk_score = max(0.0, (combined_time / C) * 50.0)
        priority = "Medium" if risk_score > 25 else "Low"
        
    return {
        "data_lifespan": L,
        "migration_time": M,
        "collapse_time": C,
        "combined_time": combined_time,
        "risk_score": round(risk_score, 1),
        "priority": priority,
        "vulnerable": combined_time >= C
    }

@app.post("/api/simulate-handshake")
def simulate_handshake():
    """
    Executes a real PQC hybrid handshake exchange (X25519 + ML-KEM-768)
    and returns hex buffers representing key material.
    """
    # 1. Client generates local keys
    client_kem = HybridKEM()
    client_x_pub, client_oqs_pub = client_kem.get_public_keys()
    
    # 2. Server receives client keys and runs encapsulation
    server_kem = HybridKEM()
    server_x_pub, server_oqs_ciphertext, server_derived_key = server_kem.encapsulate_shared_secret(
        client_x_pub, client_oqs_pub
    )
    
    # 3. Client decapsulates
    client_derived_key = client_kem.decapsulate_shared_secret(
        server_x_pub, server_oqs_ciphertext
    )
    
    return {
        "client_x_pub_hex": client_x_pub.hex(),
        "client_oqs_pub_hex": client_oqs_pub.hex()[:60] + "...",
        "server_x_pub_hex": server_x_pub.hex(),
        "server_oqs_ciphertext_hex": server_oqs_ciphertext.hex()[:60] + "...",
        "derived_key_hex": client_derived_key.hex(),
        "match": client_derived_key == server_derived_key
    }

@app.get("/api/benchmark-signatures")
def benchmark_signatures():
    """Returns size parameters for ECDSA and ML-DSA signature primitives."""
    return {
        "classical": {
            "name": "ECDSA (secp256r1)",
            "pubkey_size": 64,
            "sig_size": 64,
            "security_level": "Classical (Broken by Shor)"
        },
        "pqc": {
            "name": "ML-DSA-65 (Dilithium)",
            "pubkey_size": 1952,
            "sig_size": 3300,
            "security_level": "Post-Quantum (NIST FIPS 204)"
        }
    }
