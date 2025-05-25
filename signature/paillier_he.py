# /home/ubuntu/cryptography_project/crypto_lib/paillier_he.py

"""Paillier Partially Homomorphic Encryption Scheme Implementation.

Supports encryption, decryption, and homomorphic addition of plaintexts.
Uses PyCryptodome for large number arithmetic and prime generation.
"""

import secrets
import math
from typing import Tuple, NamedTuple
from Crypto.Util.number import getPrime, getRandomRange

# --- Helper Functions ---
def gcd(a: int, b: int) -> int:
    """Computes the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def lcm(a: int, b: int) -> int:
    """Computes the least common multiple of a and b."""
    return abs(a * b) // gcd(a, b)

def L(u: int, n: int) -> int:
    """L(u) = (u-1)/n"""
    return (u - 1) // n

# --- Key Structures ---
class PaillierPublicKey(NamedTuple):
    n: int  # n = p * q
    g: int  # generator (usually n + 1)
    n_sq: int  # n² (precomputed)

class PaillierPrivateKey(NamedTuple):
    p: int  # first prime
    q: int  # second prime
    lambda_val: int  # lcm(p-1, q-1)
    mu: int  # modular multiplicative inverse

class PaillierHE:
    def __init__(self, public_key: PaillierPublicKey = None, private_key: PaillierPrivateKey = None):
        self.public_key = public_key
        self.private_key = private_key

    @staticmethod
    def generate_keypair(bits: int = 1024) -> Tuple[PaillierPublicKey, PaillierPrivateKey]:
        """Generate a new Paillier keypair."""
        # Generate two large prime numbers
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        
        n = p * q
        n_sq = n * n
        
        # Calculate lambda (lcm of p-1 and q-1)
        lambda_val = lcm(p - 1, q - 1)
        
        # Generate generator g
        g = n + 1
        
        # Calculate mu (modular multiplicative inverse)
        mu = pow(lambda_val, -1, n)
        
        public_key = PaillierPublicKey(n=n, g=g, n_sq=n_sq)
        private_key = PaillierPrivateKey(p=p, q=q, lambda_val=lambda_val, mu=mu)
        
        return public_key, private_key

    def encrypt(self, plaintext: int) -> int:
        """Encrypt a message using public key."""
        if self.public_key is None:
            raise ValueError("Public key is required for encryption")
        
        if not 0 <= plaintext < self.public_key.n:
            raise ValueError(f"Plaintext must be in range [0, {self.public_key.n})")
        
        # Generate random r
        r = getRandomRange(1, self.public_key.n)
        
        # c = g^m * r^n mod n^2
        c = (pow(self.public_key.g, plaintext, self.public_key.n_sq) * 
             pow(r, self.public_key.n, self.public_key.n_sq)) % self.public_key.n_sq
        
        return c

    def decrypt(self, ciphertext: int) -> int:
        """Decrypt a message using private key."""
        if self.private_key is None or self.public_key is None:
            raise ValueError("Both public and private keys are required for decryption")
        
        if not 0 <= ciphertext < self.public_key.n_sq:
            raise ValueError(f"Ciphertext must be in range [0, {self.public_key.n_sq})")
        
        # m = L(c^lambda mod n^2) * mu mod n
        x = pow(ciphertext, self.private_key.lambda_val, self.public_key.n_sq)
        plaintext = (L(x, self.public_key.n) * self.private_key.mu) % self.public_key.n
        
        return plaintext

    @staticmethod
    def add_encrypted(c1: int, c2: int, public_key: PaillierPublicKey) -> int:
        """Add two encrypted values homomorphically."""
        return (c1 * c2) % public_key.n_sq

    @staticmethod
    def multiply_constant(c: int, k: int, public_key: PaillierPublicKey) -> int:
        """Multiply an encrypted value by a constant k."""
        return pow(c, k, public_key.n_sq)

def run_paillier_example():
    """Example usage of Paillier homomorphic encryption."""
    # Generate keys
    phe = PaillierHE()
    public_key, private_key = phe.generate_keypair(1024)
    phe.public_key = public_key
    phe.private_key = private_key

    # Example values
    m1 = 15
    m2 = 20

    # Encrypt
    c1 = phe.encrypt(m1)
    c2 = phe.encrypt(m2)

    # Homomorphic addition
    c_sum = PaillierHE.add_encrypted(c1, c2, public_key)
    
    # Decrypt
    decrypted_sum = phe.decrypt(c_sum)

    print(f"m1 = {m1}")
    print(f"m2 = {m2}")
    print(f"Decrypted sum = {decrypted_sum}")
    print(f"Actual sum = {m1 + m2}")
    
    return decrypted_sum == m1 + m2

if __name__ == "__main__":
    run_paillier_example()

