# Post-Quantum Cryptography Migration SDK

A production-ready open-source software development kit (SDK) and migration framework implementing hybrid post-quantum cryptography (PQC) wrapping tools, dual signature verification, and secure network tunnels using Qiskit/NIST-standardized lattice schemes (ML-KEM, ML-DSA) and classical algorithms.

---

## 🚀 Key Features

*   **Drop-In `PQCSocket` Wrapper:** Subclasses Python's built-in TCP socket to establish secure tunnels with transparent hybrid handshakes and AES-256-GCM authenticated payload encryption.
*   **Hybrid Key Encapsulation (ECDH + ML-KEM-768):** Implements dual-key agreement KEM wrappers. Key exchange is secure as long as either the classical (X25519) or post-quantum (ML-KEM) scheme remains unbroken.
*   **Dual Signatures (ECDSA + ML-DSA-65):** Signs data payloads using both classical elliptic curves and lattice structures. Verification requires both signatures to be authentic.
*   **Automatic Fallback Simulator:** Automatically detects if native `liboqs` C bindings are present. If missing, it activates a self-contained, deterministic simulation layer allowing the SDK to run out of the box on any development machine.

---

## 📁 Repository Structure

```
pqc-migration-framework/
├── requirements.txt
├── README.md
├── pqc_sdk/
│   ├── __init__.py
│   ├── hybrid_kem.py (ECDH X25519 + ML-KEM Key Exchange)
│   ├── hybrid_sig.py (ECDSA + ML-DSA Dual Signatures)
│   └── secure_channel.py (PQCSocket wrapper for AES-GCM TCP tunnels)
├── examples/
│   ├── secure_chat_server.py (TCP secure listening server)
│   ├── secure_chat_client.py (TCP secure client connector)
│   └── db_field_encryptor.py (SQLite column encryption utility)
├── tests/
│   └── test_pqc_sdk.py (Unit test suites)
└── docs/
    ├── README.md (Docs index)
    ├── hybrid_cryptography.md (Handshake sequences and math models)
    ├── risk_assessment.md (Mosca's Theorem risk model)
    └── migration_roadmap.md (Phase models and Gantt charts)
```

---

## 🛠️ Installation & Setup

1.  Navigate to the repository folder:
    ```bash
    cd pqc-migration-framework
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

## 💻 Running the Examples

### 1. Secure TCP Tunnel Chat Demo
To run the secure TCP channel exchange, start the server in one terminal and connect the client in another.

*   **Terminal 1 (Start Server):**
    ```bash
    python examples/secure_chat_server.py
    ```
*   **Terminal 2 (Start Client):**
    ```bash
    python examples/secure_chat_client.py
    ```

*Expected Terminal output:*
*   Handshake completes instantly.
*   Symmetric session key is derived on both sides using HKDF over the concatenated shared secrets.
*   Messages are transmitted in encrypted GCM frames and decrypted on receipt.

### 2. SQLite Database Field Encryptor
To see how to store encrypted fields (e.g., payment data or credentials) securely in a database using hybrid key material:
```bash
python examples/db_field_encryptor.py
```

---

## 🧪 Running Unit Tests

To run the complete KEM, Signature, and Socket Loopback verification suite:
```bash
python tests/test_pqc_sdk.py
```

---

## 📚 Migration Documentation Guides

For in-depth guides on deploying this framework across enterprise environments:
*   [Hybrid Cryptography Specifications](file:///c:/Users/vikas/OneDrive/Desktop/code/quantum/pqc-migration-framework/docs/hybrid_cryptography.md)
*   [Mosca's Theorem Risk Assessment Model](file:///c:/Users/vikas/OneDrive/Desktop/code/quantum/pqc-migration-framework/docs/risk_assessment.md)
*   [5-Phase Migration Roadmap & Timeline](file:///c:/Users/vikas/OneDrive/Desktop/code/quantum/pqc-migration-framework/docs/migration_roadmap.md)
*   [Real-Time Gross Settlement Case Study](file:///c:/Users/vikas/OneDrive/Desktop/code/quantum/pqc-migration-framework/docs/case_study_rtgs.md)
