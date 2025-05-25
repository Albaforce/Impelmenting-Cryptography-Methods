# /home/ubuntu/cryptography_project/crypto_lib/__init__.py

"""Cryptography Library Package.

This package provides implementations of various cryptographic algorithms:
- RSA Digital Signature
- ElGamal Signature Scheme
- Digital Signature Algorithm (DSA)
- Shamir's Secret Sharing (SSS)
- Paillier Homomorphic Encryption
"""

# Import key functions/classes from each module to make them accessible
# directly from the crypto_lib package.

from .rsa_signature import (
    generate_rsa_keys,
    sign_message as sign_message_rsa,
    verify_signature as verify_signature_rsa,
    run_rsa_example
)

from .elgamal_signature import ElGamalSignature

from .dsa import (
    generate_dsa_keys,
    sign_message_dsa,
    verify_signature_dsa,
    run_dsa_example
)

from .shamir_sss import ShamirSecretSharing

from .paillier_he import PaillierHE, PaillierPublicKey, PaillierPrivateKey

__all__ = [
    # RSA
    'generate_rsa_keys',
    'sign_message_rsa',
    'verify_signature_rsa',
    'run_rsa_example',    # ElGamal
    'ElGamalSignature',
    # DSA
    'generate_dsa_keys',
    'sign_message_dsa',
    'verify_signature_dsa',
    'run_dsa_example',    # Shamir SSS
    'ShamirSecretSharing',
    # Paillier HE
    'PaillierPublicKey',
    'PaillierPrivateKey',
    'PaillierHE',
]

