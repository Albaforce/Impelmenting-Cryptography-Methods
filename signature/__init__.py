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

from .elgamal_signature import (
    ElGamalParams,
    ElGamalPrivateKey,
    ElGamalPublicKey,
    ElGamalSignature,
    generate_elgamal_params,
    generate_elgamal_keys,
    sign_message_elgamal,
    verify_signature_elgamal,
    run_elgamal_example
)

from .dsa import (
    generate_dsa_keys,
    sign_message_dsa,
    verify_signature_dsa,
    run_dsa_example
)

from .shamir_sss import (
    generate_shares as generate_sss_shares,
    reconstruct_secret as reconstruct_sss_secret,
    get_sss_prime,
    run_sss_example
)

from .paillier_he import (
    PaillierPublicKey,
    PaillierPrivateKey,
    generate_paillier_keys,
    encrypt_paillier,
    decrypt_paillier,
    homomorphic_add as homomorphic_add_paillier,
    homomorphic_multiply_const as homomorphic_multiply_const_paillier,
    run_paillier_example
)

__all__ = [
    # RSA
    'generate_rsa_keys',
    'sign_message_rsa',
    'verify_signature_rsa',
    'run_rsa_example',
    # ElGamal
    'ElGamalParams',
    'ElGamalPrivateKey',
    'ElGamalPublicKey',
    'ElGamalSignature',
    'generate_elgamal_params',
    'generate_elgamal_keys',
    'sign_message_elgamal',
    'verify_signature_elgamal',
    'run_elgamal_example',
    # DSA
    'generate_dsa_keys',
    'sign_message_dsa',
    'verify_signature_dsa',
    'run_dsa_example',
    # Shamir SSS
    'generate_sss_shares',
    'reconstruct_sss_secret',
    'get_sss_prime',
    'run_sss_example',
    # Paillier HE
    'PaillierPublicKey',
    'PaillierPrivateKey',
    'generate_paillier_keys',
    'encrypt_paillier',
    'decrypt_paillier',
    'homomorphic_add_paillier',
    'homomorphic_multiply_const_paillier',
    'run_paillier_example',
]

