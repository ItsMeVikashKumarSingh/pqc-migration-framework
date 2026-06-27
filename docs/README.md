# Post-Quantum Cryptographic (PQC) Migration Documentation

This directory contains the formal architectural blueprints, risk models, and deployment roadmaps for transitioning enterprise applications (specifically in the banking and financial sector) to quantum-safe security.

---

## Guide Index

1.  **[Hybrid Cryptography Blueprints](file:///c:/Users/vikas/OneDrive/Desktop/code/quantum/pqc-migration-framework/docs/hybrid_cryptography.md):**
    *   Detailed design of combined classical/quantum key encapsulation (ECDH + ML-KEM) and signatures (ECDSA + ML-DSA).
    *   Sequence flow of the secure TCP socket handshake.
2.  **[Risk Assessment & Mosca's Theorem](file:///c:/Users/vikas/OneDrive/Desktop/code/quantum/pqc-migration-framework/docs/risk_assessment.md):**
    *   Formulating risk profiles for legacy enterprise systems.
    *   Asset inventory prioritizing matrices and exposure calculations.
3.  **[Migration Roadmap & Timeline](file:///c:/Users/vikas/OneDrive/Desktop/code/quantum/pqc-migration-framework/docs/migration_roadmap.md):**
    *   The 5-phase transition pipeline (Discovery, Assessment, Hybrid, Validation, Cutover).
    *   Visual Gantt chart illustrating task allocations.
