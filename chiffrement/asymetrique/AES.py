from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Generate a random 256-bit (32-byte) AES key
key = os.urandom(32)

# Generate a random 128-bit (16-byte) IV
iv = os.urandom(16)

# Message to encrypt
message = b"Secret message that needs AES encryption!"

# --- Padding (PKCS7) ---
padder = padding.PKCS7(128).padder()  # AES block size = 128 bits
padded_data = padder.update(message) + padder.finalize()

# --- Encryption ---
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()

print("Ciphertext:", ciphertext)

# --- Decryption ---
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

# --- Unpadding ---
unpadder = padding.PKCS7(128).unpadder()
decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

print("Decrypted:", decrypted_data)
