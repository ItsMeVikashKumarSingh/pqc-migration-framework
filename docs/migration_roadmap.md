# Post-Quantum Cryptography Migration Roadmap

Implementing post-quantum cryptography requires a structured timeline to transition systems without causing operational downtime. This document outlines the five phases of the migration roadmap.

---

## 1. The 5-Phase Migration Model

```
 ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
 │   PHASE 1   │     │   PHASE 2   │     │   PHASE 3   │     │   PHASE 4   │     │   PHASE 5   │
 │  Discovery  ├────►│  Assessment ├────►│ Hybrid PQC  ├────►│ Validation  ├────►│ PQC Cutover │
 │  & Audit    │     │  & Priority │     │ Integration │     │ & Hardening │     │   (Final)   │
 └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

### Phase 1: Discovery & Audit (Months 1-3)
*   **Actions:** Identify all active encryption endpoints, SSL/TLS configurations, database field encryption layers, and digital signature verify schemes.
*   **Deliverables:** Centralized Cryptographic Inventory Registry.

### Phase 2: Threat Assessment & Priority (Months 3-6)
*   **Actions:** Apply Mosca's Theorem ($L + M > C$) to calculate threat scores. Group systems into Immediate, High, and Medium priority brackets.
*   **Deliverables:** Risk Exposure Report and Executive Budget Sign-off.

### Phase 3: Hybrid Cryptography Integration (Months 6-12)
*   **Actions:** Implement hybrid key exchanges (X25519 + ML-KEM) and dual signatures (ECDSA + ML-DSA) in dev/staging environments. Ensure all external client libraries are crypto-agile.
*   **Deliverables:** Staging Deployment of Hybrid Wrappers (such as our `pqc_sdk`).

### Phase 4: Validation & Hardening (Months 12-18)
*   **Actions:** Run compatibility stress-testing, measure bandwidth overhead (larger KEM ciphertexts/signature packets), and execute adversarial red-team simulations (simulating Harvest Now, Decrypt Later captures).
*   **Deliverables:** Performance Benchmark Metrics and Penetration Testing Sign-off.

### Phase 5: PQC Cutover (Months 18-24)
*   **Actions:** Transition production systems to hybrid mode. Deprecate legacy key templates. Prepare configuration options to transition to pure quantum-safe primitives when standardized by regulatory bodies.
*   **Deliverables:** Quantum-Hardened Production Environment.

---

## 2. Migration Timeline Gantt Chart

Below is the visual schedule of the migration pipeline:

```mermaid
gantt
    title PQC Enterprise Migration Timeline (24 Months)
    dateFormat  YYYY-MM
    axisFormat  %m-%Y

    section Phase 1: Discovery
    Audit active TLS endpoints      :active, p1_1, 2026-07, 2M
    Audit DB column encryptions     :active, p1_2, 2026-08, 2M

    section Phase 2: Assessment
    Evaluate Mosca's exposure scores :p2_1, 2026-09, 2M
    Define prioritization registers  :p2_2, 2026-10, 2M

    section Phase 3: Integration
    Deploy Hybrid KEM on sockets    :p3_1, 2026-11, 4M
    Integrate Dual Signatures (SDK) :p3_2, 2026-12, 5M

    section Phase 4: Validation
    Run performance benchmarks       :p4_1, 2027-04, 3M
    Stress test data packet sizes    :p4_2, 2027-05, 3M

    section Phase 5: Cutover
    Staged production deploy         :p5_1, 2027-07, 4M
    Deprecate legacy primitives      :p5_2, 2027-09, 3M
```
