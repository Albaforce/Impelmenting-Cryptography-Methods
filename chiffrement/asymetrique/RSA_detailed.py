import random
import base64
from math import gcd

# -------------------- Helpers --------------------

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n <= 1 or n % 2 == 0:
        return n == 2
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for __ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generates a prime number of 'bits' length."""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

def modinv(a, m):
    """Modular inverse using extended Euclidean algorithm."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y

# -------------------- RSA Core --------------------

def generate_keys(bits=512, e=65537):
    """Generates public and private RSA keys."""
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise Exception("e and φ(n) are not coprime.")
    d = modinv(e, phi)
    return (n, e), (n, d)

def text_to_int(text):
    """Convert string to integer using UTF-8 encoding."""
    return int.from_bytes(text.encode('utf-8'), byteorder='big')

def int_to_text(number):
    """Convert integer to string using UTF-8 decoding."""
    length = (number.bit_length() + 7) // 8
    return number.to_bytes(length, byteorder='big').decode('utf-8')

def encrypt_text(message, public_key):
    """Encrypt text and return base64 encoded ciphertext."""
    n, e = public_key
    m_int = text_to_int(message)
    if m_int >= n:
        raise ValueError("Message is too long for the key size.")
    c = pow(m_int, e, n)
    return base64.b64encode(c.to_bytes((c.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')

def decrypt_text(cipher_b64, private_key):
    """Decrypt base64 encoded ciphertext and return original string."""
    n, d = private_key
    c_bytes = base64.b64decode(cipher_b64)
    c_int = int.from_bytes(c_bytes, byteorder='big')
    m_int = pow(c_int, d, n)
    return int_to_text(m_int)

# -------------------- Example Usage --------------------

if __name__ == "__main__":
    bits = 256  # 512+ for real use, 256 for testing
    message = "hello world! this is RSA 🔐"

    public_key, private_key = generate_keys(bits=bits)

    print("Public Key:", public_key)
    print("Private Key:", private_key)

    encrypted = encrypt_text(message, public_key)
    print("\nEncrypted (base64):", encrypted)

    decrypted = decrypt_text(encrypted, private_key)
    print("Decrypted message:", decrypted)

    assert message == decrypted, "Decryption failed!"
