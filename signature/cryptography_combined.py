# Cryptography Implementations Combined

"""This script combines implementations for:
1. RSA Digital Signature
2. ElGamal Signature Scheme
3. Digital Signature Algorithm (DSA)
4. Shamir's Secret Sharing (SSS)
5. Paillier Homomorphic Encryption

Each section includes the algorithm implementation and an example usage function.
A main function at the end runs all examples.
"""

# --- Common Imports ---
import os
import secrets
import math
from typing import Tuple, NamedTuple, List, Union

# Attempt to import PyCryptodome
try:
    from Crypto.PublicKey import RSA, DSA
    from Crypto.Signature import pss, DSS
    from Crypto.Hash import SHA256
    from Crypto.Random import get_random_bytes
    from Crypto.Util import number
except ImportError:
    print("Error: PyCryptodome library not found.")
    print("Please install it using: pip install pycryptodome")
    exit()

import traceback

# =============================================
# === 1. RSA Digital Signature Implementation ===
# =============================================

print("\n--- Loading RSA Digital Signature Code ---")

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
    private_key = RSA.generate(key_size)
    public_key = private_key.publickey()
    return private_key, public_key

def sign_message_rsa(private_key: RsaKey, message: bytes) -> bytes:
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
    h = SHA256.new(message)
    signer = pss.new(private_key)
    signature = signer.sign(h)
    return signature

def verify_signature_rsa(public_key: RsaKey, message: bytes, signature: bytes) -> bool:
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
    h = SHA256.new(message)
    verifier = pss.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def run_rsa_example():
    """Demonstrates the RSA signing and verification process."""
    print("--- RSA Digital Signature Example ---")
    try:
        print("Generating RSA key pair (2048 bits)...")
        private_key, public_key = generate_rsa_keys(2048)
        print(f"Private Key modulus bits: {private_key.n.bit_length()}")
        print(f"Public Key modulus bits: {public_key.n.bit_length()}")
        message = b"This is a secret message that needs to be signed."
        print(f"\nOriginal Message: {message.decode()}")
        print("Signing the message...")
        signature = sign_message_rsa(private_key, message)
        print(f"Generated Signature (hex): {signature.hex()}")
        print("\nVerifying the signature with the correct public key...")
        is_valid = verify_signature_rsa(public_key, message, signature)
        print(f"Signature valid? {is_valid}")
        assert is_valid
        print("\nVerifying the signature with a tampered message...")
        tampered_message = b"This is a different message."
        is_valid_tampered = verify_signature_rsa(public_key, tampered_message, signature)
        print(f"Signature valid for tampered message? {is_valid_tampered}")
        assert not is_valid_tampered
        print("\nGenerating a second key pair...")
        _, wrong_public_key = generate_rsa_keys(2048)
        print("Verifying the signature with an incorrect public key...")
        is_valid_wrong_key = verify_signature_rsa(wrong_public_key, message, signature)
        print(f"Signature valid with wrong key? {is_valid_wrong_key}")
        assert not is_valid_wrong_key
        print("\nRSA example completed successfully.")
    except Exception as e:
        print(f"\nAn error occurred during the RSA example: {e}")
        traceback.print_exc()




# ==============================================
# === 2. ElGamal Signature Scheme Implementation ===
# ==============================================

print("\n--- Loading ElGamal Signature Scheme Code ---")

# Define named tuples for clarity
class ElGamalParams(NamedTuple):
    p: int  # Large safe prime
    g: int  # Generator

class ElGamalPrivateKey(NamedTuple):
    params: ElGamalParams
    x: int  # Private key (1 <= x < q)

class ElGamalPublicKey(NamedTuple):
    params: ElGamalParams
    y: int  # Public key (y = g^x mod p)

class ElGamalSignature(NamedTuple):
    r: int
    s: int

def generate_elgamal_params(key_size: int = 2048) -> ElGamalParams:
    """Generates parameters (p, g) for the ElGamal signature scheme.

    Args:
        key_size: The desired bit length for the prime p. Recommended >= 2048.

    Returns:
        An ElGamalParams object containing the prime p and generator g.

    Raises:
        ValueError: If key_size is too small.
    """
    if key_size < 1024:
        raise ValueError("Key size should be at least 1024 bits, 2048 recommended.")

    print(f"Generating {key_size}-bit prime p...")
    p = number.getPrime(key_size, randfunc=os.urandom)
    q = (p - 1) // 2
    # Ensure q is prime for subgroup security (though standard ElGamal doesn't strictly require it)
    while not number.isPrime(q):
        print(f"q={(p-1)//2} is not prime, regenerating p...")
        p = number.getPrime(key_size, randfunc=os.urandom)
        q = (p - 1) // 2
    print(f"Generated prime p (bit length {p.bit_length()}) with prime q = (p-1)/2")

    # Find a generator g of the subgroup of order q.
    # Find h such that h^2 mod p != 1. Then g = h^2 mod p.
    while True:
        h = number.getRandomRange(2, p - 1, randfunc=os.urandom)
        g = pow(h, 2, p)
        if g != 1 and pow(g, q, p) == 1:
            break
    print(f"Found generator g = {g} of order q={q}")
    return ElGamalParams(p=p, g=g)

def generate_elgamal_keys(params: ElGamalParams) -> Tuple[ElGamalPrivateKey, ElGamalPublicKey]:
    """Generates an ElGamal key pair (private x, public y) from given parameters.

    Args:
        params: The ElGamal parameters (p, g).

    Returns:
        A tuple containing the ElGamalPrivateKey and ElGamalPublicKey.
    """
    p, g = params.p, params.g
    q = (p - 1) // 2
    x = number.getRandomRange(1, q, randfunc=os.urandom)
    y = pow(g, x, p)
    private_key = ElGamalPrivateKey(params=params, x=x)
    public_key = ElGamalPublicKey(params=params, y=y)
    return private_key, public_key

def sign_message_elgamal(private_key: ElGamalPrivateKey, message: bytes) -> ElGamalSignature:
    """Signs a message using the ElGamal private key.

    Args:
        private_key: The ElGamalPrivateKey object.
        message: The message to sign (as bytes).

    Returns:
        An ElGamalSignature object containing (r, s).

    Raises:
        ValueError: If the message is empty.
    """
    if not message:
        raise ValueError("Message cannot be empty.")
    p, g = private_key.params.p, private_key.params.g
    x = private_key.x
    q = (p - 1) // 2
    h_obj = SHA256.new(message)
    h = int.from_bytes(h_obj.digest(), byteorder='big') # Corrected syntax
    while True:
        k = number.getRandomRange(1, q, randfunc=os.urandom)
        r = pow(g, k, p)
        if r == 0:
            continue
        try:
            k_inv = number.inverse(k, q)
        except ValueError:
            continue
        term1 = h % q
        term2 = (x * r) % q
        s_unsigned = (term1 - term2 + q) % q
        s = (s_unsigned * k_inv) % q
        if s != 0 and r != 0:
            break
    return ElGamalSignature(r=r, s=s)

def verify_signature_elgamal(public_key: ElGamalPublicKey, message: bytes, signature: ElGamalSignature) -> bool:
    """Verifies an ElGamal signature.

    Args:
        public_key: The ElGamalPublicKey object.
        message: The original message (as bytes).
        signature: The ElGamalSignature object (r, s) to verify.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        ValueError: If the message is empty or signature components are invalid.
    """
    if not message:
        raise ValueError("Message cannot be empty.")
    p, g = public_key.params.p, public_key.params.g
    y = public_key.y
    r, s = signature.r, signature.s
    q = (p - 1) // 2
    if not (0 < r < p and 0 < s < q):
        print(f"Signature validation failed: r or s out of range (r={r}, s={s}, p={p}, q={q})")
        return False
    h_obj = SHA256.new(message)
    h = int.from_bytes(h_obj.digest(), byteorder='big') # Corrected syntax
    try:
        v1 = pow(g, h, p)
        v2_term1 = pow(y, r, p)
        v2_term2 = pow(r, s, p)
        v2 = (v2_term1 * v2_term2) % p
        is_valid = (v1 == v2)
        if not is_valid:
             print(f"Signature validation failed: Verification equation g^h = y^r * r^s (mod p) does not hold.")
             print(f"  g^h mod p = {v1}")
             print(f"  y^r * r^s mod p = {v2}")
        return is_valid
    except Exception as e:
        print(f"Error during verification calculation: {e}")
        return False

def run_elgamal_example():
    """Demonstrates the ElGamal signing and verification process."""
    print("\n--- ElGamal Signature Example ---")
    try:
        print("Generating ElGamal parameters (1024 bits for speed)...")
        params = generate_elgamal_params(key_size=1024)
        print(f"Parameters: p={params.p}, g={params.g}")
        print("\nGenerating ElGamal key pair...")
        private_key, public_key = generate_elgamal_keys(params)
        print(f"Private Key x: <hidden>")
        print(f"Public Key y: {public_key.y}")
        message = b"This is the message to be signed using ElGamal."
        print(f"\nOriginal Message: {message.decode()}")
        print("Signing the message...")
        signature = sign_message_elgamal(private_key, message)
        print(f"Generated Signature: r={signature.r}, s={signature.s}")
        print("\nVerifying the signature with the correct public key...")
        is_valid = verify_signature_elgamal(public_key, message, signature)
        print(f"Signature valid? {is_valid}")
        assert is_valid
        print("\nVerifying the signature with a tampered message...")
        tampered_message = b"This message has been tampered with."
        is_valid_tampered = verify_signature_elgamal(public_key, tampered_message, signature)
        print(f"Signature valid for tampered message? {is_valid_tampered}")
        assert not is_valid_tampered
        print("\nGenerating a second key pair...")
        _, wrong_public_key = generate_elgamal_keys(params)
        print("Verifying the signature with an incorrect public key...")
        is_valid_wrong_key = verify_signature_elgamal(wrong_public_key, message, signature)
        print(f"Signature valid with wrong key? {is_valid_wrong_key}")
        assert not is_valid_wrong_key
        print("\nVerifying with an invalid signature component (s=0)...")
        if signature.r > 0 and signature.r < public_key.params.p:
            invalid_signature = ElGamalSignature(r=signature.r, s=0)
            is_valid_invalid_sig = verify_signature_elgamal(public_key, message, invalid_signature)
            print(f"Signature valid with s=0? {is_valid_invalid_sig}")
            assert not is_valid_invalid_sig
        else:
            print("Skipping s=0 test as original r was invalid.")
        print("\nElGamal example completed successfully.")
    except Exception as e:
        print(f"\nAn error occurred during the ElGamal example: {e}")
        traceback.print_exc()




# ======================================================
# === 3. Digital Signature Algorithm (DSA) Implementation ===
# ======================================================

print("\n--- Loading DSA (FIPS 186-4) Signature Code ---")

# Type alias for DSA key objects
DsaKey = DSA.DsaKey

def generate_dsa_keys(key_size: int = 2048) -> Tuple[DsaKey, DsaKey]:
    """Generates a new DSA key pair (private and public).

    According to FIPS 186-4, valid key sizes are 1024, 2048, and 3072 bits.
    PyCryptodome handles the generation of parameters (p, q, g) internally.

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
    private_key = DSA.generate(key_size)
    public_key = private_key.publickey()
    return private_key, public_key

def sign_message_dsa(private_key: DsaKey, message: bytes) -> bytes:
    """Signs a message using the DSA private key.

    Args:
        private_key: The DSA private key object.
        message: The message to sign (as bytes).

    Returns:
        The DSA signature (raw bytes r || s).

    Raises:
        TypeError: If the private_key is not a valid DSA private key.
        ValueError: If the message is empty.
    """
    if not isinstance(private_key, DsaKey) or not private_key.has_private():
        raise TypeError("Invalid private key provided.")
    if not message:
        raise ValueError("Message cannot be empty.")
    h = SHA256.new(message)
    # Corrected syntax:
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
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
    q_bytes = (public_key.q.bit_length() + 7) // 8
    if len(signature) != 2 * q_bytes:
         print(f"Warning: Signature length ({len(signature)}) does not match expected ({2 * q_bytes}).")
    h = SHA256.new(message)
    # Corrected syntax:
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

def run_dsa_example():
    """Demonstrates the DSA signing and verification process."""
    print("\n--- DSA (FIPS 186-4) Signature Example ---")
    try:
        print("Generating DSA key pair (2048 bits)...")
        private_key, public_key = generate_dsa_keys(key_size=2048)
        print(f"DSA Parameters: p={private_key.p.bit_length()} bits, q={private_key.q.bit_length()} bits")
        # Corrected syntax:
        print(f"Private Key x exists: {hasattr(private_key, 'x')}")
        print(f"Public Key y exists: {hasattr(public_key, 'y')}")
        message = b"This message will be signed using DSA."
        print(f"\nOriginal Message: {message.decode()}")
        print("Signing the message...")
        signature = sign_message_dsa(private_key, message)
        print(f"Generated Signature (hex): {signature.hex()}")
        print(f"Signature length: {len(signature)} bytes")
        print("\nVerifying the signature with the correct public key...")
        is_valid = verify_signature_dsa(public_key, message, signature)
        print(f"Signature valid? {is_valid}")
        assert is_valid
        print("\nVerifying the signature with a tampered message...")
        tampered_message = b"This is not the original message."
        is_valid_tampered = verify_signature_dsa(public_key, tampered_message, signature)
        print(f"Signature valid for tampered message? {is_valid_tampered}")
        assert not is_valid_tampered
        print("\nGenerating a second key pair...")
        _, wrong_public_key = generate_dsa_keys(key_size=2048)
        print("Verifying the signature with an incorrect public key...")
        is_valid_wrong_key = verify_signature_dsa(wrong_public_key, message, signature)
        print(f"Signature valid with wrong key? {is_valid_wrong_key}")
        assert not is_valid_wrong_key
        print("\nDSA example completed successfully.")
    except Exception as e:
        print(f"\nAn error occurred during the DSA example: {e}")
        traceback.print_exc()




# ======================================================
# === 4. Shamir's Secret Sharing (SSS) Implementation ===
# ======================================================

print("\n--- Loading Shamir's Secret Sharing Code ---")

# --- Finite Field Arithmetic Helpers ---

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modInverse(a: int, m: int) -> int:
    """Modular Inverse using Extended Euclidean Algorithm.
    Returns x such that a*x % m == 1.
    Raises ValueError if inverse does not exist (i.e., gcd(a, m) != 1).
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m

# --- Polynomial Functions (Modulo p) ---

def evaluate_poly(coeffs: List[int], x: int, p: int) -> int:
    """Evaluates a polynomial P(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[k-1]*x^(k-1) modulo p.
    The constant term (secret) is coeffs[0].
    """
    result = 0
    x_power = 1
    for coeff in coeffs:
        term = (coeff * x_power) % p
        result = (result + term) % p
        x_power = (x_power * x) % p
    return result

# --- Shamir's Secret Sharing Core Functions ---

# Define a suitable prime field. Using a 256-bit prime for general purpose secrets.
# Note: Using a fixed prime for simplicity in this combined script.
# In a real application, consider dynamic prime generation based on secret size.
_SSS_PRIME = number.getPrime(256, randfunc=secrets.token_bytes)

def get_sss_prime() -> int:
    """Returns the prime modulus used for SSS calculations."""
    return _SSS_PRIME

def generate_sss_shares(secret: int, k: int, n: int, p: int = _SSS_PRIME) -> List[Tuple[int, int]]:
    """Generates N shares for a given secret using a K-threshold scheme.

    Args:
        secret: The integer secret to share.
        k: The minimum number of shares required for reconstruction (threshold).
        n: The total number of shares to generate.
        p: The prime modulus for the finite field. Must be > secret and > n.

    Returns:
        A list of N shares, where each share is a tuple (x_i, y_i).

    Raises:
        ValueError: If parameters are invalid (k > n, k < 2, n < 2, secret >= p, n >= p).
    """
    if k > n:
        raise ValueError("Threshold K cannot be greater than the number of shares N.")
    if k < 2:
        raise ValueError("Threshold K must be at least 2.")
    if n < 2:
        raise ValueError("Number of shares N must be at least 2.")
    if secret >= p:
        raise ValueError(f"Secret ({secret}) must be smaller than the prime modulus ({p}).")
    if n >= p:
        raise ValueError(f"Number of shares N ({n}) must be smaller than the prime modulus ({p}).")

    coeffs = [secret]
    for _ in range(k - 1):
        coeff = secrets.randbelow(p)
        coeffs.append(coeff)

    shares = []
    for i in range(1, n + 1):
        x_i = i
        y_i = evaluate_poly(coeffs, x_i, p)
        shares.append((x_i, y_i))

    return shares

def reconstruct_sss_secret(shares: List[Tuple[int, int]], p: int = _SSS_PRIME) -> int:
    """Reconstructs the secret from a list of K or more shares using Lagrange Interpolation.

    Args:
        shares: A list of at least K shares, where each share is (x_i, y_i).
        p: The prime modulus used during share generation.

    Returns:
        The reconstructed secret integer.

    Raises:
        ValueError: If fewer than 2 shares are provided or if shares are inconsistent.
    """
    if len(shares) < 2:
        raise ValueError("At least 2 shares are required for reconstruction.")

    k = len(shares)
    x_coords = [s[0] for s in shares]
    if len(set(x_coords)) != len(x_coords):
        raise ValueError("Duplicate x coordinates found in shares.")

    secret = 0
    for j in range(k):
        x_j, y_j = shares[j]
        numerator = 1
        denominator = 1
        for m in range(k):
            if m != j:
                x_m = shares[m][0]
                numerator = (numerator * x_m) % p
                diff = (x_m - x_j + p) % p
                if diff == 0:
                     raise ValueError(f"Internal error: division by zero in Lagrange (x_{m}={x_m}, x_{j}={x_j})")
                denominator = (denominator * diff) % p
        try:
            lagrange_basis_at_zero = (numerator * modInverse(denominator, p)) % p
        except ValueError:
            raise ValueError("Could not compute modular inverse for Lagrange interpolation.")
        term = (y_j * lagrange_basis_at_zero) % p
        secret = (secret + term) % p

    return secret

def run_sss_example():
    """Demonstrates Shamir's Secret Sharing generation and reconstruction."""
    print("\n--- Shamir's Secret Sharing Example ---")
    try:
        secret_message = "MyTopSecretPassword123!"
        # Corrected syntax:
        secret_int = int.from_bytes(secret_message.encode("utf-8"), "big")
        k = 3
        n = 5
        prime = get_sss_prime()

        print(f"Secret Message: {secret_message}")
        print(f"Secret as Integer: {secret_int}")
        print(f"Threshold (K): {k}")
        print(f"Total Shares (N): {n}")
        print(f"Prime Modulus (P): {prime} (bit length: {prime.bit_length()})")

        if secret_int >= prime:
            print("Error: Chosen prime is too small for the secret integer.")
            return

        print("\nGenerating shares...")
        shares = generate_sss_shares(secret_int, k, n, prime)
        print("Generated Shares (x, y):")
        for i, share in enumerate(shares):
            print(f"  Share {i+1}: ({share[0]}, {share[1]})" )

        print(f"\nReconstructing secret with {k} shares (Shares 1, 3, 5)...")
        subset_k = [shares[0], shares[2], shares[4]]
        reconstructed_k = reconstruct_sss_secret(subset_k, prime)
        reconstructed_msg_k = reconstructed_k.to_bytes((reconstructed_k.bit_length() + 7) // 8, "big").decode("utf-8")
        print(f"Reconstructed Integer: {reconstructed_k}")
        print(f"Reconstructed Message: {reconstructed_msg_k}")
        assert reconstructed_k == secret_int
        assert reconstructed_msg_k == secret_message

        print(f"\nReconstructing secret with all {n} shares...")
        reconstructed_n = reconstruct_sss_secret(shares, prime)
        reconstructed_msg_n = reconstructed_n.to_bytes((reconstructed_n.bit_length() + 7) // 8, "big").decode("utf-8")
        print(f"Reconstructed Integer: {reconstructed_n}")
        print(f"Reconstructed Message: {reconstructed_msg_n}")
        assert reconstructed_n == secret_int
        assert reconstructed_msg_n == secret_message

        print(f"\nAttempting reconstruction with {k-1} shares (Shares 2, 4)...")
        subset_k_minus_1 = [shares[1], shares[3]]
        try:
            reconstructed_fail = reconstruct_sss_secret(subset_k_minus_1, prime)
            reconstructed_msg_fail = reconstructed_fail.to_bytes((reconstructed_fail.bit_length() + 7) // 8, "big").decode("utf-8", errors="ignore")
            print(f"Reconstructed Integer (Incorrect): {reconstructed_fail}")
            print(f"Reconstructed Message (Incorrect): {reconstructed_msg_fail}")
            assert reconstructed_fail != secret_int
        except ValueError as e:
            print(f"Reconstruction failed as expected: {e}")
        except Exception as e:
            print(f"An unexpected error occurred during failed reconstruction: {e}")

        print("\nShamir's Secret Sharing example completed successfully.")
    except ValueError as e:
        print(f"\nAn error occurred: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred during the SSS example: {e}")
        traceback.print_exc()




# ============================================================
# === 5. Paillier Homomorphic Encryption (HE) Implementation ===
# ============================================================

print("\n--- Loading Paillier Homomorphic Encryption Code ---")

# --- Helper Functions (gcd, lcm already defined in SSS section) ---

def L_paillier(u: int, n: int) -> int:
    """Defines the L function for Paillier: L(u) = (u - 1) // n."""
    return (u - 1) // n

# --- Paillier Key Structures ---

class PaillierPublicKey(NamedTuple):
    n: int      # Modulus n = p * q
    n_sq: int   # n squared (n*n)
    g: int      # Generator, often n + 1

class PaillierPrivateKey(NamedTuple):
    lambda_val: int # Carmichael function lambda(n) = lcm(p-1, q-1)
    mu: int         # mu = (L(g^lambda mod n^2))^-1 mod n

# --- Paillier Core Functions ---

def generate_paillier_keys(key_size: int = 2048) -> Tuple[PaillierPublicKey, PaillierPrivateKey]:
    """Generates Paillier public and private keys.

    Args:
        key_size: The desired bit length for the modulus n. Recommended >= 2048.

    Returns:
        A tuple containing the PaillierPublicKey and PaillierPrivateKey.

    Raises:
        ValueError: If key_size is too small.
    """
    if key_size < 1024:
        raise ValueError("Key size should be at least 1024 bits, 2048 recommended.")

    print(f"Generating two primes for {key_size}-bit modulus...")
    p = number.getPrime(key_size // 2, randfunc=secrets.token_bytes)
    while True:
        q = number.getPrime(key_size // 2, randfunc=secrets.token_bytes)
        if p != q:
            break
    print(f"Generated primes p ({p.bit_length()} bits) and q ({q.bit_length()} bits).")

    n = p * q
    n_sq = n * n
    print(f"Modulus n = {n} ({n.bit_length()} bits)")

    lambda_val = lcm(p - 1, q - 1)
    g = n + 1 # Common choice for g

    # Calculate mu = (L(g^lambda mod n^2))^-1 mod n
    g_pow_lambda = pow(g, lambda_val, n_sq)
    l_val = L_paillier(g_pow_lambda, n)
    try:
        mu = number.inverse(l_val, n)
    except ValueError:
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

    while True:
        r = number.getRandomRange(1, n, randfunc=secrets.token_bytes)
        if gcd(r, n) == 1:
            break

    g_pow_m = pow(g, plaintext, n_sq)
    r_pow_n = pow(r, n, n_sq)
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

    c_pow_lambda = pow(ciphertext, lambda_val, n_sq)
    l_val = L_paillier(c_pow_lambda, n)
    plaintext = (l_val * mu) % n
    return plaintext

# --- Homomorphic Operations ---

def homomorphic_add_paillier(public_key: PaillierPublicKey, c1: int, c2: int) -> int:
    """Performs homomorphic addition of two ciphertexts.
    If c1 = Enc(m1) and c2 = Enc(m2), returns Enc(m1 + m2).
    """
    n_sq = public_key.n_sq
    c_sum = (c1 * c2) % n_sq
    return c_sum

def homomorphic_multiply_const_paillier(public_key: PaillierPublicKey, c: int, k: int) -> int:
    """Performs homomorphic multiplication of a ciphertext by a plaintext constant.
    If c = Enc(m), returns Enc(k * m).
    """
    n, n_sq = public_key.n, public_key.n_sq
    if not (0 <= k < n):
        # Allow k >= n, result is mod n anyway
        print(f"Warning: Constant k={k} >= n={n}. Result will be (m*k) mod n.")
        # raise ValueError(f"Constant k={k} out of range [0, {n-1}].")

    c_prod = pow(c, k, n_sq)
    return c_prod

def run_paillier_example():
    """Demonstrates the Paillier encryption, decryption, and homomorphic properties."""
    print("\n--- Paillier Homomorphic Encryption Example ---")
    try:
        key_size = 1024 # Use 1024 for example speed
        print(f"Generating Paillier keys ({key_size} bits)...")
        public_key, private_key = generate_paillier_keys(key_size=key_size)
        print(f"Public Key (n={public_key.n.bit_length()} bits)")

        m1 = 12345
        m2 = 67890
        k = 5
        print(f"\nPlaintext 1 (m1): {m1}")
        print(f"Plaintext 2 (m2): {m2}")
        print(f"Constant (k): {k}")

        if m1 >= public_key.n or m2 >= public_key.n:
            print("Error: Plaintexts are too large for the generated key size.")
            return

        print("\nEncrypting m1 and m2...")
        c1 = encrypt_paillier(public_key, m1)
        c2 = encrypt_paillier(public_key, m2)
        print(f"Ciphertext 1 (c1): ...{str(c1)[-20:]}") # Print last 20 digits
        print(f"Ciphertext 2 (c2): ...{str(c2)[-20:]}")

        print("\nDecrypting c1 and c2 to verify...")
        decrypted_m1 = decrypt_paillier(private_key, public_key, c1)
        decrypted_m2 = decrypt_paillier(private_key, public_key, c2)
        print(f"Decrypted c1: {decrypted_m1}")
        print(f"Decrypted c2: {decrypted_m2}")
        assert decrypted_m1 == m1
        assert decrypted_m2 == m2

        print("\nPerforming homomorphic addition (c1 * c2 mod n^2)...")
        c_sum = homomorphic_add_paillier(public_key, c1, c2)
        print(f"Resulting Ciphertext (c_sum): ...{str(c_sum)[-20:]}")
        decrypted_sum = decrypt_paillier(private_key, public_key, c_sum)
        expected_sum = (m1 + m2) % public_key.n
        print(f"Decrypted Sum: {decrypted_sum}")
        print(f"Expected Sum (m1 + m2 mod n): {expected_sum}")
        assert decrypted_sum == expected_sum

        print(f"\nPerforming homomorphic multiplication (c1^k mod n^2) with k={k}...")
        c_prod = homomorphic_multiply_const_paillier(public_key, c1, k)
        print(f"Resulting Ciphertext (c_prod): ...{str(c_prod)[-20:]}")
        decrypted_prod = decrypt_paillier(private_key, public_key, c_prod)
        expected_prod = (m1 * k) % public_key.n
        print(f"Decrypted Product: {decrypted_prod}")
        print(f"Expected Product (m1 * k mod n): {expected_prod}")
        assert decrypted_prod == expected_prod

        print("\nPaillier example completed successfully.")
        print("\nNote: Paillier is partially homomorphic (supports addition and multiplication by constant).")

    except Exception as e:
        print(f"\nAn error occurred during the Paillier example: {e}")
        traceback.print_exc()




# =============================================
# === Main Function to Run All Examples ===
# =============================================

def main():
    """Runs all cryptography examples from the combined script."""
    print("=============================================")
    print(" Cryptography Implementations Demonstration ")
    print("=============================================")

    # Run RSA Example
    print("\nRunning RSA Digital Signature Example...")
    run_rsa_example()
    print("\n---------------------------------------------")

    # Run ElGamal Example
    print("\nRunning ElGamal Signature Example...")
    run_elgamal_example()
    print("\n---------------------------------------------")

    # Run DSA Example
    print("\nRunning DSA Signature Example...")
    run_dsa_example()
    print("\n---------------------------------------------")
    # Run Shamir SSS Example
    print("\nRunning Shamir's Secret Sharing Example...")
    run_sss_example()
    print("\n---------------------------------------------")

    # Run Paillier HE Example
    print("\nRunning Paillier Homomorphic Encryption Example...")
    run_paillier_example()
    print("\n---------------------------------------------")

    print("\nAll cryptography examples executed.")

if __name__ == "__main__":
    main()

