import sys
import os
import threading
from cryptography.exceptions import InvalidSignature

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pqc_sdk.hybrid_kem import HybridKEM
from pqc_sdk.hybrid_sig import HybridSigner, HybridVerifier
from pqc_sdk.secure_channel import PQCSocket

def test_hybrid_kem():
    """Test that client-server hybrid key exchange derives the identical key."""
    client_kem = HybridKEM()
    client_x_pub, client_oqs_pub = client_kem.get_public_keys()
    
    server_kem = HybridKEM()
    server_x_pub, server_oqs_ciphertext, server_derived_key = server_kem.encapsulate_shared_secret(
        client_x_pub, client_oqs_pub
    )
    
    client_derived_key = client_kem.decapsulate_shared_secret(
        server_x_pub, server_oqs_ciphertext
    )
    
    assert client_derived_key == server_derived_key
    assert len(client_derived_key) == 32

def test_hybrid_signatures():
    """Test that dual signatures verify successfully and catch tampered payloads."""
    signer = HybridSigner()
    ecdsa_pub_pem, oqs_pub = signer.get_public_keys()
    
    message = b"Secure payment authorization payload."
    ecdsa_sig, oqs_sig = signer.sign(message)
    
    # 1. Successful verification
    assert HybridVerifier.verify(message, ecdsa_pub_pem, ecdsa_sig, oqs_pub, oqs_sig) is True
    
    # 2. Tampered message should fail
    tampered_message = b"Secure payment authorization payload!"
    try:
        HybridVerifier.verify(tampered_message, ecdsa_pub_pem, ecdsa_sig, oqs_pub, oqs_sig)
        assert False, "Verification should fail for a tampered message"
    except InvalidSignature:
        pass
        
    # 3. Tampered classical signature should fail
    tampered_ecdsa = bytearray(ecdsa_sig)
    tampered_ecdsa[0] ^= 0xFF
    try:
        HybridVerifier.verify(message, ecdsa_pub_pem, bytes(tampered_ecdsa), oqs_pub, oqs_sig)
        assert False, "Verification should fail for a tampered classical signature"
    except InvalidSignature:
        pass

def test_secure_socket_channel():
    """Test PQCSocket client-server handshake and message encryption loop on localhost."""
    host = "127.0.0.1"
    port = 18889
    
    server_socket = PQCSocket()
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    client_received = []
    server_received = []
    pqc_client_key_holder = []
    
    def run_server():
        pqc_client, _ = server_socket.accept()
        pqc_client_key_holder.append(pqc_client.key)
        msg = pqc_client.recv()
        server_received.append(msg)
        pqc_client.send(b"Server secure handshake reply.")
        pqc_client.close()
        
    t = threading.Thread(target=run_server)
    t.start()
    
    # Let server socket listen
    import time
    time.sleep(0.5)
    
    client_socket = PQCSocket()
    client_socket.connect((host, port))
    client_socket.send(b"Client secure request payload.")
    
    reply = client_socket.recv()
    client_received.append(reply)
    client_socket.close()
    
    t.join()
    server_socket.close()
    
    assert server_received[0] == b"Client secure request payload."
    assert client_received[0] == b"Server secure handshake reply."
    assert client_socket.key == pqc_client_key_holder[0]

if __name__ == "__main__":
    print("Running Hybrid KEM tests...")
    test_hybrid_kem()
    print("Running Hybrid Signatures tests...")
    test_hybrid_signatures()
    print("Running Secure Socket Channel tests...")
    test_secure_socket_channel()
    print("All SDK component tests completed successfully!")
