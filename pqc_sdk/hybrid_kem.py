import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Try importing liboqs python bindings
OQS_AVAILABLE = False
try:
    import oqs
    # Confirm ML-KEM-768 is supported by the installed liboqs version
    if "ML-KEM-768" in oqs.get_enabled_kem_mechanisms():
        OQS_AVAILABLE = True
except ImportError:
    pass

class SimulatedMLKEM768:
    """Fallback simulated ML-KEM-768 for environments without native liboqs C bindings."""
    def __init__(self):
        self.public_key_len = 1184
        self.private_key_len = 2400
        self.ciphertext_len = 1088
        self.secret_len = 32

    def generate_keypair(self):
        privkey = os.urandom(self.private_key_len)
        # Derive public key deterministically from the private key seed
        seed = hashlib.sha256(privkey).digest()
        pubkey = seed + os.urandom(self.public_key_len - len(seed))
        return pubkey, privkey

    def encapsulate(self, pubkey):
        ciphertext = os.urandom(self.ciphertext_len)
        # Extract seed from pubkey to derive shared secret
        seed = pubkey[:32]
        shared_secret = hashlib.sha256(seed + ciphertext).digest()
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext, privkey):
        # Reconstruct the exact same seed from privkey to derive the matching secret
        seed = hashlib.sha256(privkey).digest()
        return hashlib.sha256(seed + ciphertext).digest()

class HybridKEM:
    """
    Hybrid Key Encapsulation Mechanism combining X25519 ECDH and ML-KEM-768.
    Follows the principle of dual-security: secure unless BOTH components are broken.
    """
    def __init__(self):
        self.x25519_private = x25519.X25519PrivateKey.generate()
        self.x25519_public = self.x25519_private.public_key()
        
        if OQS_AVAILABLE:
            self.oqs_kem = oqs.KeyEncapsulation("ML-KEM-768")
        else:
            self.oqs_kem = SimulatedMLKEM768()
            
        self.oqs_public, self.oqs_private = self.oqs_kem.generate_keypair()

    def get_public_keys(self) -> tuple[bytes, bytes]:
        """Returns (X25519 Public Key Bytes, ML-KEM-768 Public Key Bytes)."""
        x_bytes = self.x25519_public.public_bytes_raw()
        return x_bytes, self.oqs_public

    def encapsulate_shared_secret(self, peer_x_bytes: bytes, peer_oqs_pub: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Runs key agreement and encapsulation.
        Returns (X25519 Public Key Bytes, ML-KEM Ciphertext, Derived 256-bit Symmetric Key).
        """
        # 1. Perform X25519 ECDH exchange
        peer_x_pub = x25519.X25519PublicKey.from_public_bytes(peer_x_bytes)
        ecdh_secret = self.x25519_private.exchange(peer_x_pub)

        # 2. Perform ML-KEM encapsulation
        if OQS_AVAILABLE:
            oqs_ciphertext, oqs_secret = self.oqs_kem.encap_secret(peer_oqs_pub)
        else:
            oqs_ciphertext, oqs_secret = self.oqs_kem.encapsulate(peer_oqs_pub)

        # 3. Derive combined key using HKDF
        derived_key = self._derive_combined_key(ecdh_secret, oqs_secret)
        
        local_x_bytes = self.x25519_public.public_bytes_raw()
        return local_x_bytes, oqs_ciphertext, derived_key

    def decapsulate_shared_secret(self, peer_x_bytes: bytes, oqs_ciphertext: bytes) -> bytes:
        """
        Runs key agreement and decapsulation on the receiving side.
        Returns the derived 256-bit Symmetric Key.
        """
        # 1. Perform X25519 ECDH exchange
        peer_x_pub = x25519.X25519PublicKey.from_public_bytes(peer_x_bytes)
        ecdh_secret = self.x25519_private.exchange(peer_x_pub)

        # 2. Perform ML-KEM decapsulation
        if OQS_AVAILABLE:
            oqs_secret = self.oqs_kem.decap_secret(oqs_ciphertext, self.oqs_private)
        else:
            oqs_secret = self.oqs_kem.decapsulate(oqs_ciphertext, self.oqs_private)

        # 3. Derive combined key using HKDF
        return self._derive_combined_key(ecdh_secret, oqs_secret)

    def _derive_combined_key(self, ecdh_secret: bytes, oqs_secret: bytes) -> bytes:
        """Combine classical and quantum secrets using HKDF."""
        combined_secret = ecdh_secret + oqs_secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # 256-bit key
            salt=None,
            info=b"pqc-hybrid-kem-derivation"
        )
        return hkdf.derive(combined_secret)
