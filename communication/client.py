
import socket
import threading
import json
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Bob connects to Alice’s IP and port:
HOST = '192.168.72.129'  # Replace with Alice's actual IP address on the network
PORT = 65432

# Paths to keys
PRIVATE_KEY_PATH = "bob_private_key.pem"
PEER_PUBLIC_KEY_PATH = "alice_public_key.pem"

def load_rsa_private_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_rsa_public_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def sign_message(message_bytes, private_key):
    return private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), 
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(message_bytes, signature, public_key):
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def encrypt_message(plaintext_bytes, peer_public_key):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    encrypted_key = peer_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_key, nonce, ciphertext

def decrypt_message(packet_json_bytes, rsa_private_key, peer_public_key):
    packet = json.loads(packet_json_bytes)

    encrypted_key = bytes.fromhex(packet["encrypted_key"])
    nonce = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    signature = bytes.fromhex(packet["signature"])

    # Decrypt AES key
    aes_key = rsa_private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # Verify signature
    valid = verify_signature(plaintext, signature, peer_public_key)
    return plaintext.decode(), valid

def save_message_to_file(message, filename):
    with open(filename, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def handle_receive(sock, rsa_private_key, peer_public_key):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("[*] Connection closed by peer.")
                break

            plaintext, valid = decrypt_message(data, rsa_private_key, peer_public_key)
            print(f"\n[Peer]: {plaintext}")
            if valid:
                print("[*] Signature valid ✅")
            else:
                print("[!] Signature INVALID ❌")

            save_message_to_file(f"RECEIVED: {plaintext}", "received_messages.txt")

        except Exception as e:
            print("[!] Error receiving or decrypting message:", e)
            break

def send_message_loop(sock, rsa_private_key, peer_public_key):
    while True:
        msg = input("You: ")
        if msg.lower() == "exit":
            print("[*] Exiting chat.")
            sock.close()
            break

        msg_bytes = msg.encode()
        signature = sign_message(msg_bytes, rsa_private_key)
        encrypted_key, nonce, ciphertext = encrypt_message(msg_bytes, peer_public_key)

        packet = {
            "encrypted_key": encrypted_key.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "signature": signature.hex()
        }
        packet_bytes = json.dumps(packet).encode()

        try:
            sock.sendall(packet_bytes)
            save_message_to_file(f"SENT: {msg}", "sent_messages.txt")
        except Exception as e:
            print("[!] Failed to send message:", e)
            break

def main():
    rsa_priv = load_rsa_private_key(PRIVATE_KEY_PATH)
    peer_pub = load_rsa_public_key(PEER_PUBLIC_KEY_PATH)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[*] Connected to {HOST}:{PORT}")

        recv_thread = threading.Thread(target=handle_receive, args=(s, rsa_priv, peer_pub), daemon=True)
        recv_thread.start()

        send_message_loop(s, rsa_priv, peer_pub)

if __name__ == "__main__":
    main()
