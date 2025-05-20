# /home/ubuntu/cryptography_project/main.py

"""Main script to demonstrate the usage of the cryptography library.

Runs the example functions for each implemented algorithm.
"""

# Import the example runner functions from the library package
from crypto_lib import (
    run_rsa_example,
    run_elgamal_example,
    run_dsa_example,
    run_sss_example,
    run_paillier_example
)

def main():
    """Runs all cryptography examples."""
    print("=============================================")
    print(" Cryptography Project Demonstration Script ")
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

