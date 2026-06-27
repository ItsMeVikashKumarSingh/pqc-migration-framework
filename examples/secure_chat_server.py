import sys
import os
import threading

# Add parent directory to path so we can import pqc_sdk
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pqc_sdk import PQCSocket

def handle_client(client_socket, address):
    print(f"[SERVER] Connection established with {address}")
    print("[SERVER] Executing post-quantum hybrid handshake...")
    try:
        # Handshake is automatically completed inside PQCSocket.accept()
        print(f"[SERVER] Handshake completed successfully. Session key derived: {client_socket.key.hex()[:16]}...")
        
        while True:
            # Receive encrypted message
            ciphertext = client_socket.recv()
            if not ciphertext:
                break
                
            message = ciphertext.decode('utf-8')
            print(f"[SERVER] Decrypted Message received: '{message}'")
            
            # Send secure encrypted reply
            reply = f"Acknowledged. Secured with X25519 + ML-KEM-768. Payload length: {len(message)}."
            client_socket.send(reply.encode('utf-8'))
            
    except Exception as e:
        print(f"[SERVER] Connection error with {address}: {e}")
    finally:
        client_socket.close()
        print(f"[SERVER] Connection closed with {address}")

def main():
    host = "127.0.0.1"
    port = 9099
    
    server = PQCSocket()
    server.bind((host, port))
    server.listen(5)
    print(f"[SERVER] PQC Secure Server listening on {host}:{port}")
    
    try:
        while True:
            # accept() handles the TCP acceptance and performs the hybrid handshake internally
            pqc_client, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(pqc_client, addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Server shutting down.")
    finally:
        server.close()

if __name__ == "__main__":
    main()
