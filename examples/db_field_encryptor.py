import sys
import os
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pqc_sdk.hybrid_kem import HybridKEM

def setup_database():
    db_name = "secure_records.db"
    if os.path.exists(db_name):
        os.remove(db_name)
        
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    # Table containing public key material and encrypted data
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_holder TEXT,
            client_x_pub BLOB,
            client_oqs_pub BLOB,
            encrypted_payload BLOB,
            iv BLOB
        )
    """)
    conn.commit()
    return conn, db_name

def main():
    print("[DATABASE DEMO] Setting up SQLite Database...")
    conn, db_file = setup_database()
    cursor = conn.cursor()
    
    # 1. Simulate Client generating hybrid keys
    print("\n[DATABASE DEMO] 1. Client generating hybrid KEM keypair...")
    client_kem = HybridKEM()
    client_x_pub, client_oqs_pub = client_kem.get_public_keys()
    
    # 2. Simulate Server (Database admin) encapsulating a key for this client
    print("[DATABASE DEMO] 2. Server encapsulating a shared secret key...")
    server_kem = HybridKEM()
    server_x_pub, server_oqs_ciphertext, derived_key = server_kem.encapsulate_shared_secret(client_x_pub, client_oqs_pub)
    
    # 3. Server encrypts the transaction payload using the derived hybrid key
    print("[DATABASE DEMO] 3. Encrypting transaction record...")
    sensitive_data = b"Visa Card #4111-2222-3333-4444 | Exp 09/30 | CVV 999"
    iv = os.urandom(12)
    aesgcm = AESGCM(derived_key)
    encrypted_payload = aesgcm.encrypt(iv, sensitive_data, None)
    
    # Save to SQLite table
    cursor.execute(
        "INSERT INTO encrypted_transactions (account_holder, client_x_pub, client_oqs_pub, encrypted_payload, iv) VALUES (?, ?, ?, ?, ?)",
        ("John Doe", server_x_pub, server_oqs_ciphertext, encrypted_payload, iv)
    )
    conn.commit()
    print("[DATABASE DEMO] Securely wrote encrypted transaction record to SQLite table.")
    
    # 4. Read back and decrypt the record
    print("\n[DATABASE DEMO] 4. Fetching and decrypting records from SQLite table...")
    cursor.execute("SELECT account_holder, client_x_pub, client_oqs_pub, encrypted_payload, iv FROM encrypted_transactions")
    records = cursor.fetchall()
    
    for row in records:
        holder, db_x_pub, db_oqs_ciphertext, db_payload, db_iv = row
        print(f"Holder: {holder}")
        print(f"Encrypted payload stored in DB (hex): {db_payload.hex()[:40]}...")
        
        # Client decapsulates the shared secret from the stored database key material
        print("[DATABASE DEMO] Client decapsulating session key using stored parameters...")
        client_derived_key = client_kem.decapsulate_shared_secret(db_x_pub, db_oqs_ciphertext)
        
        # Client decrypts the payload
        client_aesgcm = AESGCM(client_derived_key)
        decrypted_data = client_aesgcm.decrypt(db_iv, db_payload, None)
        print(f"Decrypted plaintext record: '{decrypted_data.decode('utf-8')}'")

    conn.close()
    
    # Cleanup database file
    if os.path.exists(db_file):
        os.remove(db_file)
        print("\n[DATABASE DEMO] Temporary database secure_records.db cleaned up.")

if __name__ == "__main__":
    main()
