
#!/usr/bin/env python3
"""
RSA Digital Signature Implementation
Module: signatures/rsa_signature.py

Provides the RSASignature class for RSA key generation, signing, and verification.
"""

import hashlib
import random
import sympy
from typing import Tuple, Optional


class RSASignature:
    def __init__(self, key: Tuple[int, int], key_size: int = 2048):
        """
        Initialize RSA signature with a key pair.
        
        Args:
            key: Tuple containing (n, d) for private key or (n, e) for public key.
            key_size: Key size in bits (default 2048).
        """
        self.n, self.key_component = key
        self.key_size = key_size

    @staticmethod
    def generate_keypair(key_size: int = 2048) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Generate RSA key pair.
        
        Returns:
            Tuple of private key (n, d) and public key (n, e).
        """
        bit_length = key_size // 2
        p = sympy.nextprime(random.getrandbits(bit_length))
        q = sympy.nextprime(random.getrandbits(bit_length))

        while p == q:
            q = sympy.nextprime(random.getrandbits(bit_length))

        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = 65537

        while sympy.gcd(e, phi_n) != 1:
            e += 2

        d = sympy.mod_inverse(e, phi_n)

        return (n, d), (n, e)

    def sign(self, message: str) -> bytes:
        """
        Sign a message using RSA with PKCS#1 v1.5 padding.

        Args:
            message: Message to sign.

        Returns:
            Signature as bytes.
        """
        message_hash = hashlib.sha256(message.encode('utf-8')).digest()
        padded_hash = self._apply_signature_padding(message_hash)
        m = int.from_bytes(padded_hash, byteorder='big')
        signature_int = pow(m, self.key_component, self.n)
        return signature_int.to_bytes((self.n.bit_length() + 7) // 8, byteorder='big')

    def verify(self, message: str, signature: bytes) -> bool:
        """
        Verify a digital signature.

        Args:
            message: Original message.
            signature: Signature bytes.

        Returns:
            True if valid, False otherwise.
        """
        try:
            signature_int = int.from_bytes(signature, byteorder='big')
            decrypted_int = pow(signature_int, self.key_component, self.n)
            decrypted_bytes = decrypted_int.to_bytes((self.n.bit_length() + 7) // 8, byteorder='big')
            extracted_hash = self._remove_signature_padding(decrypted_bytes)
            if extracted_hash is None:
                return False
            message_hash = hashlib.sha256(message.encode('utf-8')).digest()
            return extracted_hash == message_hash
        except Exception:
            return False

    def _apply_signature_padding(self, message_hash: bytes) -> bytes:
        """
        Apply PKCS#1 v1.5 padding.

        Args:
            message_hash: SHA-256 hash of the message.

        Returns:
            Padded data ready for signing.
        """
        sha256_prefix = bytes.fromhex('3031300d060960864801650304020105000420')
        key_len = (self.n.bit_length() + 7) // 8
        padding_len = key_len - len(sha256_prefix) - len(message_hash) - 3
        padded_msg = b'\x00\x01' + b'\xff' * padding_len + b'\x00' + sha256_prefix + message_hash
        return padded_msg

    def _remove_signature_padding(self, padded_data: bytes) -> Optional[bytes]:
        """
        Remove and verify PKCS#1 v1.5 padding.

        Args:
            padded_data: Decrypted signature.

        Returns:
            Extracted SHA-256 hash or None if padding invalid.
        """
        try:
            if len(padded_data) < 11 or padded_data[0] != 0x00 or padded_data[1] != 0x01:
                return None

            separator_index = None
            for i in range(2, len(padded_data)):
                if padded_data[i] == 0x00:
                    separator_index = i
                    break
                elif padded_data[i] != 0xff:
                    return None

            if separator_index is None:
                return None

            digest_info = padded_data[separator_index + 1:]
            sha256_prefix = bytes.fromhex('3031300d060960864801650304020105000420')

            if digest_info[:len(sha256_prefix)] != sha256_prefix:
                return None

            return digest_info[len(sha256_prefix):]
        except Exception:
            return None
