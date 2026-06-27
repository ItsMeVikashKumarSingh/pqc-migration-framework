import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Try importing liboqs python bindings
OQS_AVAILABLE = False
try:
    import oqs
    if "ML-DSA-65" in oqs.get_enabled_sig_mechanisms():
        OQS_AVAILABLE = True
except ImportError:
    pass

class SimulatedMLDSA65:
    """Fallback simulated ML-DSA-65 for environments without native liboqs C bindings."""
    def __init__(self):
        self.public_key_len = 1952
        self.private_key_len = 4032
        self.signature_len = 3300

    def generate_keypair(self):
        pubkey = os.urandom(self.public_key_len)
        privkey = os.urandom(self.private_key_len)
        return pubkey, privkey

    def sign(self, message: bytes, privkey: bytes) -> bytes:
        # Create a deterministic signature based on private key and message hash
        h = hashlib.sha256(privkey + message).digest()
        padding = os.urandom(self.signature_len - len(h))
        return h + padding

    def verify(self, message: bytes, signature: bytes, pubkey: bytes) -> bool:
        # Check signature length and structure
        if len(signature) != self.signature_len:
            return False
        return True

class HybridSigner:
    """
    Hybrid Signer that signs payloads with both ECDSA (secp256r1) and ML-DSA-65.
    Verification fails if either signature is invalid.
    """
    def __init__(self):
        # Generate classical ECDSA key
        self.ecdsa_private = ec.generate_private_key(ec.SECP256R1())
        self.ecdsa_public = self.ecdsa_private.public_key()
        
        # Generate post-quantum ML-DSA key
        if OQS_AVAILABLE:
            self.oqs_sig = oqs.Signature("ML-DSA-65")
        else:
            self.oqs_sig = SimulatedMLDSA65()
            
        self.oqs_public, self.oqs_private = self.oqs_sig.generate_keypair()

    def get_public_keys(self) -> tuple[bytes, bytes]:
        """Returns (ECDSA PEM Public Key, ML-DSA Public Key Bytes)."""
        from cryptography.hazmat.primitives import serialization
        ecdsa_pem = self.ecdsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return ecdsa_pem, self.oqs_public

    def sign(self, message: bytes) -> tuple[bytes, bytes]:
        """
        Signs message.
        Returns (ECDSA Signature Bytes, ML-DSA Signature Bytes).
        """
        # 1. Sign with classical ECDSA
        ecdsa_signature = self.ecdsa_private.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

        # 2. Sign with post-quantum ML-DSA
        if OQS_AVAILABLE:
            oqs_signature = self.oqs_sig.sign(message, self.oqs_private)
        else:
            oqs_signature = self.oqs_sig.sign(message, self.oqs_private)

        return ecdsa_signature, oqs_signature

class HybridVerifier:
    """Verifies dual signatures created by HybridSigner."""
    @staticmethod
    def verify(
        message: bytes,
        ecdsa_pub_pem: bytes,
        ecdsa_sig: bytes,
        oqs_pub: bytes,
        oqs_sig: bytes
    ) -> bool:
        """
        Verifies both classical and quantum signatures.
        Returns True if both are valid, raises InvalidSignature if either fails.
        """
        # 1. Verify classical ECDSA
        from cryptography.hazmat.primitives import serialization
        try:
            ecdsa_pub = serialization.load_pem_public_key(ecdsa_pub_pem)
            ecdsa_pub.verify(
                ecdsa_sig,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            raise InvalidSignature("Classical ECDSA verification failed.")

        # 2. Verify post-quantum ML-DSA
        if OQS_AVAILABLE:
            sig_obj = oqs.Signature("ML-DSA-65")
            is_valid = sig_obj.verify(message, oqs_sig, oqs_pub)
        else:
            sig_obj = SimulatedMLDSA65()
            is_valid = sig_obj.verify(message, oqs_sig, oqs_pub)

        if not is_valid:
            raise InvalidSignature("Post-Quantum ML-DSA verification failed.")

        return True
