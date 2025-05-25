# /home/ubuntu/cryptography_project/crypto_lib/elgamal_signature.py

"""ElGamal Signature Scheme Implementation using PyCryptodome for number theory."""

import os
import secrets  # For cryptographically secure random numbers
from typing import Tuple, NamedTuple
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse
import random

# Define named tuples for clarity
class ElGamalParams(NamedTuple):
    p: int  # Large prime
    g: int  # Generator

class ElGamalPrivateKey(NamedTuple):
    params: ElGamalParams
    x: int  # Private key

class ElGamalPublicKey(NamedTuple):
    params: ElGamalParams
    y: int  # Public key = g^x mod p

class ElGamalSignature:
    def __init__(self, key=None):
        self.key = key

    @staticmethod
    def generate_params(bits=1024):
        """Generate ElGamal parameters (p, g)"""
        # Generate prime p
        p = getPrime(bits)
        
        # Find generator g
        g = 2
        while pow(g, (p-1)//2, p) == 1:
            g = random.randint(2, p-1)
        
        return ElGamalParams(p=p, g=g)

    @staticmethod
    def generate_keypair(params: ElGamalParams):
        """Generate public and private keys"""
        x = random.randint(2, params.p - 2)  # Private key
        y = pow(params.g, x, params.p)       # Public key
        
        private_key = ElGamalPrivateKey(params=params, x=x)
        public_key = ElGamalPublicKey(params=params, y=y)
        
        return private_key, public_key

    def sign(self, message: bytes) -> Tuple[int, int]:
        """Sign a message using ElGamal signature scheme"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if not isinstance(self.key, ElGamalPrivateKey):
            raise ValueError("Private key required for signing")
        
        p, g = self.key.params.p, self.key.params.g
        x = self.key.x
        
        # Generate k (ephemeral key)
        while True:
            k = random.randint(2, p-2)
            if self._gcd(k, p-1) == 1:
                break
        
        # Calculate r = g^k mod p
        r = pow(g, k, p)
        
        # Calculate hash
        h = int.from_bytes(SHA256.new(message).digest(), byteorder='big')
        
        # Calculate s = (h - x*r) * k^(-1) mod (p-1)
        k_inv = inverse(k, p-1)
        s = (h - x * r) * k_inv % (p-1)
        
        return (r, s)

    def verify(self, message: bytes, signature: Tuple[int, int]) -> bool:
        """Verify an ElGamal signature"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if not isinstance(self.key, ElGamalPublicKey):
            raise ValueError("Public key required for verification")
        
        p, g = self.key.params.p, self.key.params.g
        y = self.key.y
        r, s = signature
        
        if not (0 < r < p and 0 < s < p-1):
            return False
        
        # Calculate hash
        h = int.from_bytes(SHA256.new(message).digest(), byteorder='big')
        
        # Verify g^h = y^r * r^s mod p
        left = pow(g, h, p)
        right = (pow(y, r, p) * pow(r, s, p)) % p
        
        return left == right

    @staticmethod
    def _gcd(a: int, b: int) -> int:
        """Calculate Greatest Common Divisor"""
        while b:
            a, b = b, a % b
        return a

# --- Example Usage --- 
def run_elgamal_example():
    """Demonstrates the ElGamal signing and verification process."""
    print("\n--- ElGamal Signature Example ---")

    try:
        # 1. Parameter Generation (using a smaller key size for speed in example)
        print("Generating ElGamal parameters (1024 bits)...")
        # Use 1024 for example speed, recommend 2048+ for real use
        params = ElGamalSignature.generate_params(bits=1024)
        print(f"Parameters: p={params.p}, g={params.g}")

        # 2. Key Generation
        print("\nGenerating ElGamal key pair...")
        private_key, public_key = ElGamalSignature.generate_keypair(params)
        print(f"Private Key x: <hidden>") # Don't print private key
        print(f"Public Key y: {public_key.y}")

        # 3. Message Preparation
        message = b"This is the message to be signed using ElGamal."
        print(f"\nOriginal Message: {message.decode()}")

        # 4. Signing
        print("Signing the message...")
        signature = ElGamalSignature(private_key).sign(message)
        print(f"Generated Signature: r={signature.r}, s={signature.s}")

        # 5. Verification (Successful Case)
        print("\nVerifying the signature with the correct public key...")
        is_valid = ElGamalSignature(public_key).verify(message, signature)
        print(f"Signature valid? {is_valid}")
        assert is_valid

        # 6. Verification (Tampered Message)
        print("\nVerifying the signature with a tampered message...")
        tampered_message = b"This message has been tampered with."
        is_valid_tampered = ElGamalSignature(public_key).verify(tampered_message, signature)
        print(f"Signature valid for tampered message? {is_valid_tampered}")
        assert not is_valid_tampered

        # 7. Verification (Incorrect Key)
        print("\nGenerating a second key pair...")
        # Ensure the new key uses the same parameters p, g
        _, wrong_public_key = ElGamalSignature.generate_keypair(params)
        print("Verifying the signature with an incorrect public key...")
        is_valid_wrong_key = ElGamalSignature(wrong_public_key).verify(message, signature)
        print(f"Signature valid with wrong key? {is_valid_wrong_key}")
        assert not is_valid_wrong_key

        # 8. Verification (Invalid Signature component)
        print("\nVerifying with an invalid signature component (s=0)...")
        # Create signature with s=0, ensure r is valid first
        if signature.r > 0 and signature.r < public_key.params.p:
            invalid_signature = ElGamalSignature(r=signature.r, s=0)
            is_valid_invalid_sig = ElGamalSignature(public_key).verify(message, invalid_signature)
            print(f"Signature valid with s=0? {is_valid_invalid_sig}")
            assert not is_valid_invalid_sig
        else:
            print("Skipping s=0 test as original r was invalid (should not happen).")

        print("\nElGamal example completed successfully.")

    except Exception as e:
        print(f"\nAn error occurred during the ElGamal example: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    # This block allows running the example directly
    run_elgamal_example()

