# /home/ubuntu/cryptography_project/crypto_lib/paillier_he.py

"""Paillier Partially Homomorphic Encryption Scheme Implementation.

Supports encryption, decryption, and homomorphic addition of plaintexts.
Uses PyCryptodome for large number arithmetic and prime generation.
"""

import secrets
import math
from typing import Tuple, NamedTuple

from Crypto.Util import number

# --- Helper Functions ---

def gcd(a: int, b: int) -> int:
    """Computes the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def lcm(a: int, b: int) -> int:
    """Computes the least common multiple of a and b."""
    # Ensure integer division
    return abs(a * b) // gcd(a, b) if a != 0 and b != 0 else 0

def L(u: int, n: int) -> int:
    """Defines the L function for Paillier: L(u) = (u - 1) // n."""
    # Ensure integer division
    return (u - 1) // n

# --- Paillier Key Structures ---

class PaillierPublicKey(NamedTuple):
    n: int      # Modulus n = p * q
    n_sq: int   # n squared (n*n), used frequently in calculations
    g: int      # Generator, often n + 1

class PaillierPrivateKey(NamedTuple):
    lambda_val: int # Carmichael function lambda(n) = lcm(p-1, q-1)
    mu: int         # mu = (L(g^lambda mod n^2))^-1 mod n

# --- Paillier Core Functions ---

def generate_paillier_keys(key_size: int = 2048) -> Tuple[PaillierPublicKey, PaillierPrivateKey]:
    """Generates Paillier public and private keys.

    Args:
        key_size: The desired bit length for the modulus n. The primes p and q
                  will each be approximately key_size / 2 bits.
                  Recommended >= 2048 for security.

    Returns:
        A tuple containing the PaillierPublicKey and PaillierPrivateKey.

    Raises:
        ValueError: If key_size is too small.
    """
    if key_size < 1024:
        raise ValueError("Key size should be at least 1024 bits, 2048 recommended.")

    # 1. Generate two large distinct primes p and q of roughly key_size/2 bits.
    #    Ensure gcd(pq, (p-1)(q-1)) = 1. This is automatically satisfied if p, q are distinct primes.
    print(f"Generating two primes for {key_size}-bit modulus...")
    p = number.getPrime(key_size // 2, randfunc=secrets.token_bytes)
    while True:
        q = number.getPrime(key_size // 2, randfunc=secrets.token_bytes)
        if p != q:
            break
    print(f"Generated primes p ({p.bit_length()} bits) and q ({q.bit_length()} bits).")

    # 2. Compute n = p * q and n_sq = n * n.
    n = p * q
    n_sq = n * n
    print(f"Modulus n = {n} ({n.bit_length()} bits)")

    # 3. Compute lambda(n) = lcm(p-1, q-1).
    #    lambda is the Carmichael function.
    lambda_val = lcm(p - 1, q - 1)

    # 4. Select generator g.
    #    A common choice is g = n + 1. This g always works.
    #    Check if g is of order n modulo n^2. We need L(g^lambda mod n^2) to be invertible mod n.
    g = n + 1

    # 5. Compute mu = (L(g^lambda mod n^2))^-1 mod n.
    #    First, calculate g^lambda mod n^2.
    g_pow_lambda = pow(g, lambda_val, n_sq)
    #    Then, apply the L function.
    l_val = L(g_pow_lambda, n)
    #    Finally, compute the modular inverse.
    try:
        mu = number.inverse(l_val, n)
    except ValueError:
        # This should not happen if p, q are distinct primes and g = n+1
        raise RuntimeError("Could not compute modular inverse mu. Check prime generation.")

    public_key = PaillierPublicKey(n=n, n_sq=n_sq, g=g)
    private_key = PaillierPrivateKey(lambda_val=lambda_val, mu=mu)

    return public_key, private_key

def encrypt_paillier(public_key: PaillierPublicKey, plaintext: int) -> int:
    """Encrypts a plaintext integer using the Paillier public key.

    Args:
        public_key: The PaillierPublicKey object.
        plaintext: The integer message to encrypt. Must be 0 <= plaintext < n.

    Returns:
        The ciphertext integer.

    Raises:
        ValueError: If plaintext is out of range [0, n-1].
    """
    n, n_sq, g = public_key.n, public_key.n_sq, public_key.g

    if not (0 <= plaintext < n):
        raise ValueError(f"Plaintext {plaintext} out of range [0, {n-1}].")

    # 1. Choose a random integer r such that 0 < r < n and gcd(r, n) = 1.
    while True:
        r = number.getRandomRange(1, n, randfunc=secrets.token_bytes)
        if gcd(r, n) == 1:
            break

    # 2. Compute ciphertext c = g^plaintext * r^n mod n^2.
    #    Calculate g^plaintext mod n^2
    g_pow_m = pow(g, plaintext, n_sq)
    #    Calculate r^n mod n^2
    r_pow_n = pow(r, n, n_sq)
    #    Combine them
    ciphertext = (g_pow_m * r_pow_n) % n_sq

    return ciphertext

def decrypt_paillier(private_key: PaillierPrivateKey, public_key: PaillierPublicKey, ciphertext: int) -> int:
    """Decrypts a ciphertext integer using the Paillier private key.

    Args:
        private_key: The PaillierPrivateKey object.
        public_key: The PaillierPublicKey object (needed for n and n_sq).
        ciphertext: The integer ciphertext to decrypt. Must be 0 <= ciphertext < n^2.

    Returns:
        The decrypted plaintext integer.

    Raises:
        ValueError: If ciphertext is out of range [0, n^2 - 1].
    """
    lambda_val, mu = private_key.lambda_val, private_key.mu
    n, n_sq = public_key.n, public_key.n_sq

    if not (0 <= ciphertext < n_sq):
        raise ValueError(f"Ciphertext {ciphertext} out of range [0, {n_sq - 1}].")

    # 1. Compute c^lambda mod n^2.
    c_pow_lambda = pow(ciphertext, lambda_val, n_sq)

    # 2. Apply the L function.
    l_val = L(c_pow_lambda, n)

    # 3. Compute plaintext m = L(c^lambda mod n^2) * mu mod n.
    plaintext = (l_val * mu) % n

    return plaintext

# --- Homomorphic Operations ---

def homomorphic_add(public_key: PaillierPublicKey, c1: int, c2: int) -> int:
    """Performs homomorphic addition of two ciphertexts.
    If c1 = Enc(m1) and c2 = Enc(m2), returns Enc(m1 + m2).

    Args:
        public_key: The PaillierPublicKey object.
        c1: The first ciphertext.
        c2: The second ciphertext.

    Returns:
        The resulting ciphertext Enc(m1 + m2).
    """
    n_sq = public_key.n_sq
    # The sum ciphertext is simply the product of the input ciphertexts modulo n^2.
    c_sum = (c1 * c2) % n_sq
    return c_sum

def homomorphic_multiply_const(public_key: PaillierPublicKey, c: int, k: int) -> int:
    """Performs homomorphic multiplication of a ciphertext by a plaintext constant.
    If c = Enc(m), returns Enc(k * m).

    Args:
        public_key: The PaillierPublicKey object.
        c: The ciphertext Enc(m).
        k: The plaintext constant integer. Must be 0 <= k < n.

    Returns:
        The resulting ciphertext Enc(k * m).

    Raises:
        ValueError: If constant k is out of range [0, n-1].
    """
    n, n_sq = public_key.n, public_key.n_sq
    if not (0 <= k < n):
        # Technically, k can be larger, but the result is mod n.
        # We restrict it here for clarity, as k often represents another value.
        raise ValueError(f"Constant k={k} out of range [0, {n-1}].")

    # The resulting ciphertext is c^k mod n^2.
    c_prod = pow(c, k, n_sq)
    return c_prod

# --- Example Usage ---
def run_paillier_example():
    """Demonstrates the Paillier encryption, decryption, and homomorphic properties."""
    print("\n--- Paillier Homomorphic Encryption Example ---")

    try:
        # 1. Key Generation (using smaller key size for speed in example)
        key_size = 1024 # Use 1024 for example speed, recommend 2048+ for real use
        print(f"Generating Paillier keys ({key_size} bits)...")
        public_key, private_key = generate_paillier_keys(key_size=key_size)
        print(f"Public Key (n, g): ({public_key.n}, {public_key.g})")
        # print(f"Private Key (lambda, mu): ({private_key.lambda_val}, {private_key.mu})") # Keep private key secret

        # 2. Plaintexts
        m1 = 12345
        m2 = 67890
        k = 5 # Constant for multiplication
        print(f"\nPlaintext 1 (m1): {m1}")
        print(f"Plaintext 2 (m2): {m2}")
        print(f"Constant (k): {k}")

        # Check if plaintexts are within range
        if m1 >= public_key.n or m2 >= public_key.n:
            print("Error: Plaintexts are too large for the generated key size.")
            return

        # 3. Encryption
        print("\nEncrypting m1 and m2...")
        c1 = encrypt_paillier(public_key, m1)
        c2 = encrypt_paillier(public_key, m2)
        print(f"Ciphertext 1 (c1): {c1}")
        print(f"Ciphertext 2 (c2): {c2}")

        # 4. Decryption (Verification)
        print("\nDecrypting c1 and c2 to verify...")
        decrypted_m1 = decrypt_paillier(private_key, public_key, c1)
        decrypted_m2 = decrypt_paillier(private_key, public_key, c2)
        print(f"Decrypted c1: {decrypted_m1}")
        print(f"Decrypted c2: {decrypted_m2}")
        assert decrypted_m1 == m1
        assert decrypted_m2 == m2

        # 5. Homomorphic Addition
        print("\nPerforming homomorphic addition (c1 * c2 mod n^2)...")
        c_sum = homomorphic_add(public_key, c1, c2)
        print(f"Resulting Ciphertext (c_sum): {c_sum}")

        # Decrypt the sum
        decrypted_sum = decrypt_paillier(private_key, public_key, c_sum)
        expected_sum = (m1 + m2) % public_key.n # Addition is modulo n
        print(f"Decrypted Sum: {decrypted_sum}")
        print(f"Expected Sum (m1 + m2 mod n): {expected_sum}")
        assert decrypted_sum == expected_sum

        # 6. Homomorphic Multiplication by Constant
        print(f"\nPerforming homomorphic multiplication (c1^k mod n^2) with k={k}...")
        c_prod = homomorphic_multiply_const(public_key, c1, k)
        print(f"Resulting Ciphertext (c_prod): {c_prod}")

        # Decrypt the product
        decrypted_prod = decrypt_paillier(private_key, public_key, c_prod)
        expected_prod = (m1 * k) % public_key.n # Multiplication is modulo n
        print(f"Decrypted Product: {decrypted_prod}")
        print(f"Expected Product (m1 * k mod n): {expected_prod}")
        assert decrypted_prod == expected_prod

        print("\nPaillier example completed successfully.")
        print("\nNote: Paillier is partially homomorphic (supports addition and multiplication by constant), not fully homomorphic.")
        print("It is vulnerable to chosen-plaintext attacks if used naively.")
        print("Real-world applications often require more complex protocols built upon it.")

    except Exception as e:
        print(f"\nAn error occurred during the Paillier example: {e}")
        import traceback
        traceback.print_exc()

if __name__ == \'__main__\':
    # This block allows running the example directly
    run_paillier_example()

