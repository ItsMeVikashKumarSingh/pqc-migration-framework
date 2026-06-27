import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pqc_sdk import PQCSocket

def main():
    host = "127.0.0.1"
    port = 9099
    
    print(f"[CLIENT] Connecting to {host}:{port}...")
    client = PQCSocket()
    
    try:
        # Connect automatically runs the handshake internally
        client.connect((host, port))
        print(f"[CLIENT] Connected. Post-quantum hybrid handshake complete.")
        print(f"[CLIENT] Derived Session Key: {client.key.hex()[:16]}...")
        
        # Send test messages
        messages = [
            "Initiating interbank wire transaction request.",
            "Payload: Transfer USD 1,000,000 to Account #10023491.",
            "Finalizing session handshake."
        ]
        
        for msg in messages:
            print(f"\n[CLIENT] Sending Plaintext: '{msg}'")
            client.send(msg.encode('utf-8'))
            
            # Wait for reply
            reply = client.recv().decode('utf-8')
            print(f"[CLIENT] Received Decrypted Server Reply: '{reply}'")
            time.sleep(1)
            
    except ConnectionRefusedError:
        print("[CLIENT] Error: Server is not running. Please start secure_chat_server.py first.")
    except Exception as e:
        print(f"[CLIENT] Client error: {e}")
    finally:
        client.close()
        print("\n[CLIENT] Connection closed.")

if __name__ == "__main__":
    main()
