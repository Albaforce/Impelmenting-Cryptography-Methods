# /home/ubuntu/cryptography_project/crypto_lib/rsa_signature.py

"""RSA Digital Signature Implementation using PyCryptodome."""

import os
from typing import Tuple, Union

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Type alias for RSA key objects
RsaKey = RSA.RsaKey

def generate_rsa_keys(key_size: int = 2048) -> Tuple[RsaKey, RsaKey]:
    """Generates a new RSA key pair (private and public).

    Args:
        key_size: The desired key size in bits. Must be a multiple of 256
                  and at least 1024. 2048 bits is recommended minimum.

    Returns:
        A tuple containing the private key and the public key.

    Raises:
        ValueError: If the key_size is invalid.
    """
    if key_size < 1024 or key_size % 256 != 0:
        raise ValueError("Invalid RSA key size. Must be >= 1024 and multiple of 256.")

    # Generate the RSA key pair
    # Uses system's random number generator (os.urandom)
    private_key = RSA.generate(key_size)
    public_key = private_key.publickey()
    return private_key, public_key

def sign_message(private_key: RsaKey, message: bytes) -> bytes:
    """Signs a message using the RSA private key with PSS padding.

    Args:
        private_key: The RSA private key object.
        message: The message to sign (as bytes).

    Returns:
        The digital signature (as bytes).

    Raises:
        TypeError: If the private_key is not a valid RSA private key.
        ValueError: If the message is empty.
    """
    if not isinstance(private_key, RsaKey) or not private_key.has_private():
        raise TypeError("Invalid private key provided.")
    if not message:
        raise ValueError("Message cannot be empty.")

    # Hash the message using SHA-256
    h = SHA256.new(message)

    # Create a PSS signer object
    # PSS (Probabilistic Signature Scheme) is recommended for new applications
    # over the older PKCS#1 v1.5 padding.
    signer = pss.new(private_key)

    # Sign the hash
    signature = signer.sign(h)
    return signature

def verify_signature(public_key: RsaKey, message: bytes, signature: bytes) -> bool:
    """Verifies a digital signature using the RSA public key and PSS padding.

    Args:
        public_key: The RSA public key object.
        message: The original message (as bytes).
        signature: The signature to verify (as bytes).

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        TypeError: If the public_key is not a valid RSA public key.
        ValueError: If the message or signature is empty.
    """
    if not isinstance(public_key, RsaKey) or public_key.has_private():
        raise TypeError("Invalid public key provided.")
    if not message:
        raise ValueError("Message cannot be empty.")
    if not signature:
        raise ValueError("Signature cannot be empty.")

    # Hash the message using SHA-256 (must use the same hash as signing)
    h = SHA256.new(message)

    # Create a PSS verifier object
    verifier = pss.new(public_key)

    # Verify the signature
    try:
        verifier.verify(h, signature)
        return True  # Signature is valid
    except (ValueError, TypeError):
        # ValueError is raised by PyCryptodome if verification fails
        return False # Signature is invalid

# --- Example Usage --- 
def run_rsa_example():
    """Demonstrates the RSA signing and verification process."""
    print("--- RSA Digital Signature Example ---")

    try:
        # 1. Key Generation
        print("Generating RSA key pair (2048 bits)...")
        private_key, public_key = generate_rsa_keys(2048)
        print(f"Private Key modulus bits: {private_key.n.bit_length()}")
        print(f"Public Key modulus bits: {public_key.n.bit_length()}")

        # 2. Message Preparation
        message = b"This is a secret message that needs to be signed."
        print(f"\nOriginal Message: {message.decode()}")

        # 3. Signing
        print("Signing the message...")
        signature = sign_message(private_key, message)
        print(f"Generated Signature (hex): {signature.hex()}")

        # 4. Verification (Successful Case)
        print("\nVerifying the signature with the correct public key...")
        is_valid = verify_signature(public_key, message, signature)
        print(f"Signature valid? {is_valid}")
        assert is_valid

        # 5. Verification (Tampered Message)
        print("\nVerifying the signature with a tampered message...")
        tampered_message = b"This is a different message."
        is_valid_tampered = verify_signature(public_key, tampered_message, signature)
        print(f"Signature valid for tampered message? {is_valid_tampered}")
        assert not is_valid_tampered

        # 6. Verification (Incorrect Key)
        print("\nGenerating a second key pair...")
        _, wrong_public_key = generate_rsa_keys(2048)
        print("Verifying the signature with an incorrect public key...")
        is_valid_wrong_key = verify_signature(wrong_public_key, message, signature)
        print(f"Signature valid with wrong key? {is_valid_wrong_key}")
        assert not is_valid_wrong_key

        print("\nRSA example completed successfully.")

    except Exception as e:
        print(f"\nAn error occurred during the RSA example: {e}")

if __name__ == '__main__':
    # This block allows running the example directly
    run_rsa_example()

