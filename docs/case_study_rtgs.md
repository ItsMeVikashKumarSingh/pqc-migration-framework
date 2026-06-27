# Case Study: Migrating RTGS Settlement Channels to PQC

This case study analyzes the migration of a national **Real-Time Gross Settlement (RTGS)** core payment channel to post-quantum hybrid security.

---

## 1. System Context & Legacy Architecture

The RTGS network handles high-value interbank transaction settlements. Each transaction packet must be signed by the originating commercial bank to verify authenticity, and transmitted over an encrypted tunnel to the central clearing house.

### Legacy Configuration
*   **Encrypted Tunnel:** TLS 1.2 using ECDHE-ECDSA-AES128-GCM-SHA256.
*   **Payload Signature:** 256-bit ECDSA (secp256r1) signature per transaction.
*   **Vulnerability:** Adversaries intercepting TLS tunnels can record the encrypted packets today, then decrypt the payload data and forge signatures once a Cryptanalytically Relevant Quantum Computer (CRQC) is built.

---

## 2. PQC Target Architecture

To transition the RTGS network, a dual-layer security upgrade is applied:

```
 Originating Bank (Client)                     Central Clearing House (Server)
 ┌───────────────────────┐                     ┌────────────────────────────┐
 │  Transaction payload  │                     │                            │
 │           │           │                     │                            │
 │           ▼           │                     │                            │
 │ [ECDSA + ML-DSA Sign] │                     │                            │
 │           │           │                     │                            │
 │           ▼           │                     │                            │
 │    Signed Payload     │                     │                            │
 │           │           │                     │                            │
 │           ▼           │   PQCSocket Tunnel  │                            │
 │    ┌─────────────┐    │                     │    ┌─────────────┐         │
 │    │  PQCSocket  ├────┼─────────────────────┼───►│  PQCSocket  │         │
 │    │ (AES-256-GCM│    │    Handshake:       │    │ (AES-256-GCM│         │
 │    └─────────────┘    │ ECDH + ML-KEM-768   │    └──────┬──────┘         │
 └───────────────────────┘                     │           │                │
                                               │           ▼                │
                                               │ [ECDSA + ML-DSA Verify]    │
                                               │           │                │
                                               │           ▼                │
                                               │  Valid / Settle Request    │
                                               └────────────────────────────┘
```

---

## 3. Migration Implementation Plan

The migration of the settlement channel is executed in three operational phases:

### Phase A: Upgrading the Network Tunnel (PQCSocket)
The standard TCP sockets connecting the commercial banks to the central settlement database are replaced with `PQCSocket`.
*   During connection establishment, the sockets exchange public keys and perform a hybrid key encapsulation (ECDH + ML-KEM-768).
*   Even if the traffic is recorded today, it remains secure because decrypting it would require breaking both the classical ECDH curve and the lattice-based ML-KEM cipher.

### Phase B: Implementing Dual Payload Signatures
Transaction messages are signed with both ECDSA and ML-DSA-65:
```python
# Originating Bank signs:
ecdsa_sig, mldsa_sig = hybrid_signer.sign(transaction_payload)
# Combined message payload structure:
packet = {
    "payload": transaction_payload,
    "ecdsa_public": ecdsa_pub_pem,
    "ecdsa_signature": ecdsa_sig,
    "mldsa_public": mldsa_pub,
    "mldsa_signature": mldsa_sig
}
```
The central clearing house verifies both signatures. If either verification fails, the transaction is rejected.

### Phase C: Performance & Bandwidth Benchmarks
Lattice-based algorithms have significantly larger key and signature sizes compared to legacy elliptic curves:

| Parameter | Legacy (ECDSA) | PQC (ML-DSA-65) | Scale Increase |
| :--- | :--- | :--- | :--- |
| **Public Key Size** | 64 Bytes | 1,952 Bytes | ~30x |
| **Signature Size** | 64 Bytes | 3,300 Bytes | ~50x |
| **Handshake RTT** | 1.2 ms | 1.8 ms | +50% |

*Because transaction payloads in RTGS are small XML/JSON packets (typically < 10KB), the increase in signature size is easily accommodated by existing network bandwidth, ensuring minimal latency impact.*
