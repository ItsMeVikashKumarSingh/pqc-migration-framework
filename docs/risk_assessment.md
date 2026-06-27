# PQC Risk Assessment Framework

A successful migration requires cataloging cryptographic assets and evaluating their exposure to quantum threats. This framework outlines the criteria used to identify, score, and prioritize enterprise systems for post-quantum updates.

---

## 1. Mosca's Theorem

We evaluate system urgency using **Mosca's Theorem**:

$$L + M > C$$

Where:
*   **$L$ (Data Shelf-Life):** How many years must the encrypted data remain completely confidential (e.g., historical banking records must remain secure for 10-25 years).
*   **$M$ (Migration Timeline):** How many years will it take to update the infrastructure and deploy quantum-resistant algorithms across the organization.
*   **$C$ (Collapse Time):** How many years until a cryptanalytically relevant quantum computer (CRQC) is built capable of breaking RSA/ECC (estimated at 10-15 years).

> [!WARNING]
> If $L + M > C$, your data is already vulnerable to **Harvest Now, Decrypt Later (HNDL)** attacks. Adversaries are actively intercepting and storing encrypted data today to decrypt it once a quantum computer is available.

---

## 2. Infrastructure Risk Matrix

To systematically evaluate systems, we classify assets into a priority matrix:

| Priority Level | Mosca's Condition | System Example | Action Plan |
| :--- | :--- | :--- | :--- |
| **Immediate** | $L + M \ge C$ | Core Transaction Ledgers, Offline Document Backups, Private Key Infrastructure (PKI) | Begin hybrid migration immediately. Use hybrid KEM and dual-signing wrappers. |
| **High** | $L + M \approx C$ | TLS Web Endpoints, Public-Facing Payment APIs, Identity Providers | Schedule migration within 6-12 months. Ensure crypto-agility in software dependencies. |
| **Medium** | $L + M < C$ | Internal Session Databases, Microservice IPCs, Ephemeral Cache Systems | Incorporate PQC updates during scheduled maintenance cycles. |
| **Low** | ephemerality | Development sandboxes, local logs, static public assets | No immediate action required. |

---

## 3. Cryptographic Asset Inventory Template

Below is a template showing how financial organizations categorize system vulnerability:

| Asset ID | System Name | Legacy Primitive | Key Size / Curve | Data Lifespan ($L$) | Est. Migration ($M$) | Priority | Recommended Target |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AST-001** | SWIFT Gateway | RSA-2048 | 2048-bit | 15 Years | 3 Years | **Immediate** | X25519 + ML-KEM-768 |
| **AST-002** | Customer DB | AES-128 | 128-bit | 20 Years | 2 Years | **High** | Upgrade to AES-256 |
| **AST-003** | Mobile App API | ECDSA | nistp256 | 0 Years (session) | 1.5 Years | **High** | ECDSA + ML-DSA-65 |
| **AST-004** | Redis Cache | RC4 | 128-bit | 0 Years | 0.5 Years | **Medium** | Upgrade to AES-GCM |
