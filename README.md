# Implementing-Cryptography-Methods
# Cryptography Methods Implementation

A comprehensive Python implementation of classical and modern cryptographic algorithms for educational and research purposes.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Implemented Algorithms](#implemented-algorithms)
- [Project Structure](#project-structure)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## 🔒 Overview

This project provides a complete implementation of various cryptographic methods, ranging from classical ciphers to modern encryption standards. It serves as both an educational resource and a practical toolkit for understanding cryptographic principles.

## ✨ Features

- **Classical Ciphers**: Historical encryption methods
- **Modern Symmetric Encryption**: Industry-standard algorithms
- **Asymmetric Encryption**: Public-key cryptography
- **Hash Functions**: Secure message digesting
- **Digital Signatures**: Authentication and non-repudiation
- **Interactive Menu**: Easy-to-use command-line interface
- **Educational Examples**: Clear demonstrations of each algorithm

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Required Dependencies

```bash
pip install rich cryptography numpy
```

### Optional Dependencies

```bash
pip install pycryptodome  # For additional cryptographic functions
```

## 💻 Usage

### Running Individual Implementations

```bash
# Run RSA encryption/decryption
python chiffrement/asymetrique/RSA.py

# Run AES implementation
python chiffrement/asymetrique/AES.py

# Run SHA-256 hashing
python hachage/SHA_256.py

# Run DSA digital signatures
python signature/dsa.py

# Run combined cryptography systems
python signature/cryptography_combined.py
```

### Using the Menu Systems

```bash
# Run symmetric encryption menu
python chiffrement/symetrique/main.py

# Run signature schemes menu
python signature/main.py
```

## 🔐 Implementation Status

### ✅ **IMPLEMENTED ALGORITHMS**

#### **Asymmetric Encryption** (`chiffrement/asymetrique/`)
- ✅ **AES Implementation** (`AES_implementation.py`, `AES.py`)
  - Advanced Encryption Standard with multiple variants
  - 128, 192, and 256-bit key support
  
- ✅ **RSA Encryption** (`RSA.py`, `RSA_detailed.py`)
  - Complete RSA implementation with detailed version
  - Key generation, encryption, and decryption
  - Public-key cryptography foundation
  
- ✅ **Diffie-Hellman Key Exchange** (`Diffie-Hellman.py`)
  - Secure key agreement protocol
  - Discrete logarithm problem foundation

#### **Hash Functions** (`hachage/`)
- ✅ **RIPEMD-160** (`RIPEMD_160.py`)
  - 160-bit variant implementation
  - RACE Integrity Primitives Evaluation
  
- ✅ **SHA-256** (`SHA_256.py`)
  - Secure Hash Algorithm
  - 256-bit message digest
  - Industry standard implementation

#### **Digital Signatures** (`signature/`)
- ✅ **DSA (Digital Signature Algorithm)** (`dsa.py`)
  - NIST standard for digital signatures
  - Authentication and non-repudiation
  
- ✅ **ElGamal Signature** (`elgamal_signature.py`)
  - Digital signature scheme
  - Based on discrete logarithm problem
  
- ✅ **RSA Signature** (`rsa_signature.py`)
  - RSA-based digital signatures
  - PKCS#1 compliant implementation

#### **Advanced Cryptographic Schemes** (`signature/`)
- ✅ **Paillier Homomorphic Encryption** (`paillier_he.py`)
  - Homomorphic encryption properties
  - Privacy-preserving computations
  
- ✅ **Shamir's Secret Sharing** (`shamir_sss.py`)
  - Threshold secret sharing scheme
  - Distributed key management
  
- ✅ **Combined Cryptography Systems** (`cryptography_combined.py`, `cryptography_combined2.py`)
  - Integrated cryptographic solutions
  - Multiple algorithm combinations

### 📋 **PLANNED IMPLEMENTATIONS** (Not Yet Implemented)

#### **Classical Ciphers** (To be implemented)
- ⏳ **César Cipher** - Simple substitution with fixed shift
- ⏳ **Random Substitution Cipher** - Monoalphabetic substitution
- ⏳ **Affine Cipher** - Mathematical modular arithmetic approach
- ⏳ **Hill Cipher** - Matrix-based polyalphabetic cipher
- ⏳ **Playfair Cipher** - Digraph substitution cipher
- ⏳ **Vigenère Cipher** - Polyalphabetic substitution

#### **Additional Symmetric Encryption** (To be implemented)
- ⏳ **Block Cipher Implementation** - Custom block cipher modes
- ⏳ **Stream Cipher Implementation** - Custom stream cipher
- ⏳ **DES (Data Encryption Standard)** - 56-bit DES implementation
- ⏳ **Triple DES (3DES)** - Enhanced security through triple encryption
- ⏳ **DESX** - DES variant with key whitening

#### **Additional Asymmetric Methods** (To be implemented)
- ⏳ **ElGamal Encryption** - Probabilistic public-key system

#### **Additional Hash Functions** (To be implemented)
- ⏳ **RIPEMD-128/256** - Additional RIPEMD variants
- ⏳ **Merkle-Damgård Construction** - Hash function design paradigm

## 📁 Project Structure

```
cryptography-implementation/
├── README.md
├── chiffrement/
│   ├── asymetrique/
│   │   ├── __pycache__/
│   │   ├── AES_implementation.py
│   │   ├── AES.py
│   │   ├── Diffie-Hellman.py
│   │   ├── RSA_detailed.py
│   │   └── RSA.py
│   └── symetrique/
│       ├── __pycache__/
│       └── main.py
├── hachage/
│   ├── __pycache__/
│   ├── RIPEMD_160.py
│   └── SHA_256.py
└── signature/
    ├── __pycache__/
    ├── __init__.py
    ├── cryptography_combined.py
    ├── cryptography_combined2.py
    ├── dsa.py
    ├── elgamal_signature.py
    ├── main.py
    ├── paillier_he.py
    ├── rsa_signature.py
    └── shamir_sss.py
```

**Note**: Formal unit testing suite is planned for future implementation.

## 📚 Educational Resources

Each implementation includes:

- **Detailed comments** explaining the algorithm
- **Mathematical foundations** and formulas
- **Security analysis** and known vulnerabilities
- **Historical context** and practical applications
- **Performance benchmarks** and complexity analysis

## ⚠️ Security Notice

This implementation is for **educational purposes only**. While the algorithms are correctly implemented, they may not include all security measures required for production use. For real-world applications, use established cryptographic libraries.

## 🔍 Current Features

### **Implemented Cryptographic Categories:**

#### **Modern Asymmetric Cryptography**
- **RSA**: Complete implementation with both standard and detailed versions
- **AES**: Advanced Encryption Standard with comprehensive implementation
- **Diffie-Hellman**: Secure key exchange protocol

#### **Cryptographic Hash Functions**
- **SHA-256**: Industry standard secure hash algorithm
- **RIPEMD-160**: Alternative hash function implementation

#### **Digital Signature Schemes**
- **DSA**: Digital Signature Algorithm (NIST standard)
- **ElGamal Signatures**: Discrete logarithm based signatures
- **RSA Signatures**: RSA-based digital signatures

#### **Advanced Cryptographic Protocols**
- **Paillier Homomorphic Encryption**: Privacy-preserving computation
- **Shamir's Secret Sharing**: Threshold cryptography
- **Combined Cryptographic Systems**: Integrated multi-algorithm solutions

### **Planned Expansions:**
- Classical cipher implementations (César, Vigenère, Hill, etc.)
- Additional symmetric encryption algorithms (DES, 3DES, DESX)
- Stream and block cipher implementations
- Additional hash function variants
- More comprehensive testing framework



