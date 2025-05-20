from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# 1. Generate DH parameters (shared between Alice and Bob)
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# 2. Alice generates her private/public key
private_key_alice = parameters.generate_private_key()
public_key_alice = private_key_alice.public_key()

# 3. Bob generates his private/public key
private_key_bob = parameters.generate_private_key()
public_key_bob = private_key_bob.public_key()

# 4. Each party computes the shared secret
shared_key_alice = private_key_alice.exchange(public_key_bob)
shared_key_bob = private_key_bob.exchange(public_key_alice)

# 5. Derive a symmetric key from the shared secret using HKDF (key derivation function)
derived_key_alice = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key_alice)

derived_key_bob = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key_bob)

# 6. Verify both derived the same key
assert derived_key_alice == derived_key_bob

print("✅ Shared symmetric key (for AES or other crypto):", derived_key_alice.hex())
