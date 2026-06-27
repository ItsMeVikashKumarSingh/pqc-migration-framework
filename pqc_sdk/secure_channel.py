import socket
import struct
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqc_sdk.hybrid_kem import HybridKEM

class PQCSocket:
    """
    A secure socket wrapper that executes a hybrid post-quantum cryptographic
    handshake (X25519 + ML-KEM-768) and encrypts all communication using AES-256-GCM.
    """
    def __init__(self, raw_socket: socket.socket = None, derived_key: bytes = None):
        if raw_socket is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = raw_socket
            
        self.key = derived_key
        self.aesgcm = AESGCM(derived_key) if derived_key else None
        # Handshake lengths
        self.client_hello_len = 1216  # 32 (X25519) + 1184 (ML-KEM-768 pub)
        self.server_hello_len = 1120  # 32 (X25519) + 1088 (ML-KEM-768 ciphertext)

    def bind(self, address):
        self.sock.bind(address)

    def listen(self, backlog=5):
        self.sock.listen(backlog)

    def connect(self, address):
        """Connects to server and executes client-side hybrid handshake."""
        self.sock.connect(address)
        self._client_handshake()

    def accept(self) -> tuple['PQCSocket', tuple[str, int]]:
        """Accepts connection and executes server-side hybrid handshake."""
        raw_client_sock, addr = self.sock.accept()
        pqc_client_sock = PQCSocket(raw_client_sock)
        pqc_client_sock._server_handshake()
        return pqc_client_sock, addr

    def send(self, data: bytes) -> int:
        """Encrypts payload with AES-GCM and transmits over TCP."""
        if not self.aesgcm:
            raise RuntimeError("Handshake not established. Cannot send secure data.")
            
        # Generate 12-byte IV for GCM
        iv = os.urandom(12)
        encrypted_data = self.aesgcm.encrypt(iv, data, None)
        
        # Structure packet: [4-byte length] + [12-byte IV] + [encrypted payload + tag]
        packet = struct.pack("!I", len(iv) + len(encrypted_data)) + iv + encrypted_data
        self.sock.sendall(packet)
        return len(data)

    def recv(self, bufsize: int = 4096) -> bytes:
        """Reads encrypted TCP packet, decrypts, and returns plaintext."""
        if not self.aesgcm:
            raise RuntimeError("Handshake not established. Cannot receive secure data.")

        # Read 4-byte packet size prefix
        size_header = self._recv_all(4)
        if not size_header:
            return b""
        packet_len = struct.unpack("!I", size_header)[0]

        # Read the rest of the encrypted packet
        raw_packet = self._recv_all(packet_len)
        if not raw_packet:
            return b""

        # Extract IV and ciphertext
        iv = raw_packet[:12]
        ciphertext = raw_packet[12:]

        # Decrypt payload
        return self.aesgcm.decrypt(iv, ciphertext, None)

    def close(self):
        self.sock.close()

    def _client_handshake(self):
        """Initiates post-quantum hybrid key exchange from the client side."""
        # 1. Generate local KEM keys
        kem = HybridKEM()
        x_pub, oqs_pub = kem.get_public_keys()
        
        # 2. Send local public keys to server
        self.sock.sendall(x_pub + oqs_pub)

        # 3. Receive server's X25519 pub and ML-KEM ciphertext
        server_response = self._recv_all(self.server_hello_len)
        server_x_bytes = server_response[:32]
        oqs_ciphertext = server_response[32:]

        # 4. Decapsulate and derive symmetric key
        self.key = kem.decapsulate_shared_secret(server_x_bytes, oqs_ciphertext)
        self.aesgcm = AESGCM(self.key)

    def _server_handshake(self):
        """Responds to post-quantum hybrid key exchange from the server side."""
        # 1. Receive client public keys
        client_hello = self._recv_all(self.client_hello_len)
        client_x_bytes = client_hello[:32]
        client_oqs_pub = client_hello[32:]

        # 2. Generate local KEM keys and encapsulate secret
        kem = HybridKEM()
        server_x_pub, oqs_ciphertext, derived_key = kem.encapsulate_shared_secret(client_x_bytes, client_oqs_pub)

        # 3. Send server public key and ciphertext to client
        self.sock.sendall(server_x_pub + oqs_ciphertext)

        # 4. Save derived symmetric key
        self.key = derived_key
        self.aesgcm = AESGCM(self.key)

    def _recv_all(self, n: int) -> bytes:
        """Helper to receive exactly n bytes from the socket."""
        data = b""
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return b""
            data += packet
        return data
