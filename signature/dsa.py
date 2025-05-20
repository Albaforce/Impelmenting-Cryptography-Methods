# /home/ubuntu/cryptography_project/crypto_lib/dsa.py

"""DSA (Digital Signature Algorithm) Implementation using PyCryptodome.

This implementation follows FIPS 186-4 standards.
"""

import os
from typing import Tuple

from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Type alias for DSA key objects
DsaKey = DSA.DsaKey

def generate_dsa_keys(key_size: int = 2048) -> Tuple[DsaKey, DsaKey]:
    """Generates a new DSA key pair (private and public).

    According to FIPS 186-4, valid key sizes are 1024, 2048, and 3072 bits.
    The size corresponds to the bit length of the prime modulus p.
    PyCryptodome handles the generation of parameters (p, q, g) internally.
    For 1024-bit p, q is 160 bits.
    For 2048-bit p, q is 256 bits.
    For 3072-bit p, q is 256 bits.

    Args:
        key_size: The desired key size in bits (1024, 2048, or 3072).
                  2048 bits is recommended.

    Returns:
        A tuple containing the private key and the public key.

    Raises:
        ValueError: If the key_size is not one of the allowed values.
    """
    if key_size not in [1024, 2048, 3072]:
        raise ValueError("Invalid DSA key size. Must be 1024, 2048, or 3072.")

    # Generate the DSA key pair. This also generates p, q, g parameters.
    # PyCryptodome uses os.urandom for randomness.
    private_key = DSA.generate(key_size)
    public_key = private_key.publickey()

    # You can access the parameters like this:
    # print(f"DSA Parameters: p={private_key.p}, q={private_key.q}, g={private_key.g}")

    return private_key, public_key

def sign_message_dsa(private_key: DsaKey, message: bytes) -> bytes:
    """Signs a message using the DSA private key.

    Args:
        private_key: The DSA private key object.
        message: The message to sign (as bytes).

    Returns:
        The DSA signature (concatenation of r and s, DER encoded or raw).
        PyCryptodome returns the raw concatenation (r || s).

    Raises:
        TypeError: If the private_key is not a valid DSA private key.
        ValueError: If the message is empty.
    """
    if not isinstance(private_key, DsaKey) or not private_key.has_private():
        raise TypeError("Invalid private key provided.")
    if not message:
        raise ValueError("Message cannot be empty.")

    # 1. Hash the message
    #    FIPS 186-4 approves SHA-2 family hashes. SHA-256 is common.
    #    The hash output length must match the bit length of q.
    #    PyCryptodome handles truncation if needed.
    h = SHA256.new(message)

    # 2. Create a DSS (Digital Signature Standard) signer object
    #    The mode is implicitly FIPS 186-3 (which is compatible with 186-4)
    signer = DSS.new(private_key, 'fips-186-3')

    # 3. Sign the hash
    #    This involves generating a random per-message secret k internally.
    signature = signer.sign(h)

    # The signature is typically represented as two integers (r, s).
    # PyCryptodome returns the raw byte concatenation r || s.
    # The length depends on q (e.g., 2 * 256/8 = 64 bytes for a 2048-bit key).
    return signature

def verify_signature_dsa(public_key: DsaKey, message: bytes, signature: bytes) -> bool:
    """Verifies a DSA signature using the public key.

    Args:
        public_key: The DSA public key object.
        message: The original message (as bytes).
        signature: The signature to verify (raw bytes r || s).

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        TypeError: If the public_key is not a valid DSA public key.
        ValueError: If the message or signature is empty or has incorrect length.
    """
    if not isinstance(public_key, DsaKey) or public_key.has_private():
        raise TypeError("Invalid public key provided.")
    if not message:
        raise ValueError("Message cannot be empty.")
    if not signature:
        raise ValueError("Signature cannot be empty.")

    # Check signature length (should be 2 * q_bytes)
    q_bytes = (public_key.q.bit_length() + 7) // 8
    if len(signature) != 2 * q_bytes:
         print(f"Warning: Signature length ({len(signature)}) does not match expected ({2 * q_bytes}).")
         # Depending on strictness, could raise ValueError here.

    # 1. Hash the message (must use the same hash as signing)
    h = SHA256.new(message)

    # 2. Create a DSS verifier object
    verifier = DSS.new(public_key, 'fips-186-3')

    # 3. Verify the signature
    try:
        verifier.verify(h, signature)
        return True  # Signature is valid
    except ValueError:
        # PyCryptodome raises ValueError if verification fails
        return False # Signature is invalid

# --- Example Usage --- 
def run_dsa_example():
    """Demonstrates the DSA signing and verification process."""
    print("\n--- DSA (FIPS 186-4) Signature Example ---")

    try:
        # 1. Key Generation (using 2048-bit key size)
        print("Generating DSA key pair (2048 bits)...")
        private_key, public_key = generate_dsa_keys(key_size=2048)
        print(f"DSA Parameters: p={private_key.p.bit_length()} bits, q={private_key.q.bit_length()} bits")
        print(f"Private Key x exists: {hasattr(private_key, 'x')}")
        print(f"Public Key y exists: {hasattr(public_key, 'y')}")

        # 2. Message Preparation
        message = b"This message will be signed using DSA."
        print(f"\nOriginal Message: {message.decode()}")

        # 3. Signing
        print("Signing the message...")
        signature = sign_message_dsa(private_key, message)
        print(f"Generated Signature (hex): {signature.hex()}")
        print(f"Signature length: {len(signature)} bytes") # Should be 64 for 2048-bit key

        # 4. Verification (Successful Case)
        print("\nVerifying the signature with the correct public key...")
        is_valid = verify_signature_dsa(public_key, message, signature)
        print(f"Signature valid? {is_valid}")
        assert is_valid

        # 5. Verification (Tampered Message)
        print("\nVerifying the signature with a tampered message...")
        tampered_message = b"This is not the original message."
        is_valid_tampered = verify_signature_dsa(public_key, tampered_message, signature)
        print(f"Signature valid for tampered message? {is_valid_tampered}")
        assert not is_valid_tampered

        # 6. Verification (Incorrect Key)
        print("\nGenerating a second key pair...")
        _, wrong_public_key = generate_dsa_keys(key_size=2048)
        print("Verifying the signature with an incorrect public key...")
        # Ensure parameters match if verifying across different key gens
        # PyCryptodome's verify checks this implicitly.
        is_valid_wrong_key = verify_signature_dsa(wrong_public_key, message, signature)
        print(f"Signature valid with wrong key? {is_valid_wrong_key}")
        assert not is_valid_wrong_key

        print("\nDSA example completed successfully.")

    except Exception as e:
        print(f"\nAn error occurred during the DSA example: {e}")
        import traceback
        traceback.print_exc()
if __name__ == '__main__':
    # This block allows running the example directly
    run_dsa_example()

