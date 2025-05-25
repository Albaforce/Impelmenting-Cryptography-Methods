import numpy as np
import random
import string
from typing import List, Tuple, Dict, Optional
import secrets
import argparse
import sys
import base64

# Utilisation de bibliothèques cryptographiques standard pour DES et autres algorithmes modernes
try:
    from Crypto.Cipher import DES, DES3
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_LIBS_AVAILABLE = True
except ImportError:
    CRYPTO_LIBS_AVAILABLE = False
    print("Warning: pycryptodome library not found. Using custom implementations for all algorithms.")
    print("For better security, install pycryptodome: pip install pycryptodome")

# ======== CÉSAR ========
def cesar_encrypt(text: str, shift: int) -> str:
    
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            # Décaler et faire le modulo pour rester dans l'alphabet
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def cesar_decrypt(text: str, shift: int) -> str:
    """Déchiffrement de César avec un décalage donné."""
    # Pour déchiffrer, on utilise le décalage inverse
    return cesar_encrypt(text, -shift)

# ======== SUBSTITUTION ALÉATOIRE ========
def generate_random_substitution() -> Dict[str, str]:
    """Génère une table de substitution aléatoire."""
    alphabet = string.ascii_lowercase
    shuffled = list(alphabet)
    random.shuffle(shuffled)
    return {alphabet[i]: shuffled[i] for i in range(len(alphabet))}

def substitution_encrypt(text: str, substitution_table: Dict[str, str]) -> str:
    """Chiffrement par substitution aléatoire."""
    result = ""
    for char in text.lower():
        if char in substitution_table:
            result += substitution_table[char]
        else:
            result += char
    return result

def substitution_decrypt(text: str, substitution_table: Dict[str, str]) -> str:
    """Déchiffrement par substitution aléatoire."""
    # Créer la table inverse pour le déchiffrement
    inverse_table = {v: k for k, v in substitution_table.items()}
    return substitution_encrypt(text, inverse_table)

# ======== CHIFFREMENT AFFINE ========
def pgcd(a: int, b: int) -> int:
    """Calcule le PGCD de deux nombres."""
    while b:
        a, b = b, a % b
    return a

def inverse_modulaire(a: int, m: int) -> Optional[int]:
    """Calcule l'inverse modulaire de a modulo m."""
    if pgcd(a, m) != 1:
        return None  # L'inverse n'existe pas
    
    # Algorithme d'Euclide étendu
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    
    return u1 % m

def affine_encrypt(text: str, a: int, b: int) -> str:
    """Chiffrement affine E(x) = (ax + b) mod 26."""
    if pgcd(a, 26) != 1:
        raise ValueError("La valeur de 'a' doit être première avec 26")
    
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            # Appliquer la fonction affine
            x = ord(char) - ascii_offset
            y = (a * x + b) % 26
            result += chr(y + ascii_offset)
        else:
            result += char
    return result

def affine_decrypt(text: str, a: int, b: int) -> str:
    """Déchiffrement affine D(y) = a^(-1) * (y - b) mod 26."""
    a_inv = inverse_modulaire(a, 26)
    if a_inv is None:
        raise ValueError("La valeur de 'a' doit être première avec 26")
    
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            # Appliquer la fonction inverse
            y = ord(char) - ascii_offset
            x = (a_inv * (y - b)) % 26
            result += chr(x + ascii_offset)
        else:
            result += char
    return result

# ======== CHIFFRE DE HILL ========
def matrix_mod_inverse(matrix: np.ndarray, modulus: int) -> np.ndarray:
    """Calcule l'inverse modulaire d'une matrice."""
    det = int(round(np.linalg.det(matrix))) % modulus
    det_inv = inverse_modulaire(det, modulus)
    
    if det_inv is None:
        raise ValueError("La matrice n'est pas inversible modulo 26")
    
    # Calculer la matrice des cofacteurs
    size = matrix.shape[0]
    adjoint = np.zeros_like(matrix)
    
    for i in range(size):
        for j in range(size):
            # Sous-matrice en excluant la ligne i et la colonne j
            minor = np.delete(np.delete(matrix, i, axis=0), j, axis=1)
            # Cofacteur
            cofactor = round(np.linalg.det(minor)) * (-1) ** (i + j)
            adjoint[j, i] = cofactor  # Transposée de la matrice des cofacteurs
    
    # Calculer l'inverse
    inverse = (det_inv * adjoint) % modulus
    return inverse

def hill_encrypt(text: str, key_matrix: np.ndarray) -> str:
    """Chiffrement de Hill."""
    # S'assurer que la matrice est carrée
    n = key_matrix.shape[0]
    
    # Préparer le texte (convertir en nombres et ajouter du padding si nécessaire)
    # Supprimer les caractères non alphabétiques et convertir en minuscules
    text = ''.join(c for c in text if c.isalpha()).lower()
    
    # Ajouter du padding si nécessaire
    if len(text) % n != 0:
        text += 'x' * (n - len(text) % n)
    
    # Convertir le texte en vecteurs de nombres
    vectors = []
    for i in range(0, len(text), n):
        vector = [ord(text[i+j]) - ord('a') for j in range(n)]
        vectors.append(vector)
    
    # Chiffrer chaque vecteur
    result = ""
    for vector in vectors:
        # Multiplier le vecteur par la matrice clé
        encrypted_vector = np.dot(key_matrix, vector) % 26
        # Convertir en caractères
        for num in encrypted_vector:
            result += chr(int(num) + ord('a'))
    
    return result

def hill_decrypt(text: str, key_matrix: np.ndarray) -> str:
    """Déchiffrement de Hill."""
    # Calculer l'inverse de la matrice clé
    inverse_key = matrix_mod_inverse(key_matrix, 26)
    
    # Utiliser l'inverse pour déchiffrer
    return hill_encrypt(text, inverse_key)

# ======== CHIFFRE DE PLAYFAIR ========
def create_playfair_matrix(key: str) -> List[List[str]]:
    """Crée la matrice de Playfair à partir d'une clé."""
    # Remplacer J par I pour avoir un alphabet de 25 lettres
    key = key.upper().replace('J', 'I')
    
    # Créer un alphabet sans doublons à partir de la clé
    alphabet = []
    for char in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if char not in alphabet and char.isalpha():
            alphabet.append(char)
    
    # Créer la matrice 5x5
    matrix = []
    for i in range(0, 25, 5):
        matrix.append(alphabet[i:i+5])
    
    return matrix

def find_position(matrix: List[List[str]], char: str) -> Tuple[int, int]:
    """Trouve la position d'un caractère dans la matrice de Playfair."""
    char = char.upper()
    if char == 'J':
        char = 'I'
    
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return (i, j)
    
    return (-1, -1)  # Ne devrait jamais arriver

def playfair_encrypt(text: str, key: str) -> str:
    """Chiffrement de Playfair."""
    matrix = create_playfair_matrix(key)
    
    # Préparer le texte
    text = ''.join(c for c in text.upper() if c.isalpha()).replace('J', 'I')
    
    # Diviser le texte en paires de lettres
    pairs = []
    i = 0
    while i < len(text):
        if i == len(text) - 1 or text[i] == text[i+1]:
            # Ajouter X si la dernière lettre est seule ou si deux lettres consécutives sont identiques
            pairs.append(text[i] + 'X')
            i += 1
        else:
            pairs.append(text[i:i+2])
            i += 2
    
    # Chiffrer chaque paire
    result = ""
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        
        if row1 == row2:  # Même ligne
            result += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Même colonne
            result += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:  # Rectangle
            result += matrix[row1][col2] + matrix[row2][col1]
    
    return result

def playfair_decrypt(text: str, key: str) -> str:
    """Déchiffrement de Playfair."""
    matrix = create_playfair_matrix(key)
    
    # Préparer le texte
    text = ''.join(c for c in text.upper() if c.isalpha())
    
    # Diviser le texte en paires de lettres
    pairs = [text[i:i+2] for i in range(0, len(text), 2)]
    
    # Déchiffrer chaque paire
    result = ""
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        
        if row1 == row2:  # Même ligne
            result += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:  # Même colonne
            result += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:  # Rectangle
            result += matrix[row1][col2] + matrix[row2][col1]
    
    return result

# ======== CHIFFRE DE VIGENÈRE ========
def vigenere_encrypt(text: str, key: str) -> str:
    """Chiffrement de Vigenère."""
    result = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(k) - ord('A') for k in key]
    
    for i, char in enumerate(text):
        if char.isalpha():
            # Déterminer le décalage basé sur la lettre de la clé
            key_index = i % key_length
            key_shift = key_as_int[key_index]
            
            # Appliquer le décalage
            if char.isupper():
                result += chr((ord(char) - ord('A') + key_shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') + key_shift) % 26 + ord('a'))
        else:
            result += char
    
    return result

def vigenere_decrypt(text: str, key: str) -> str:
    """Déchiffrement de Vigenère."""
    result = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(k) - ord('A') for k in key]
    
    for i, char in enumerate(text):
        if char.isalpha():
            # Déterminer le décalage basé sur la lettre de la clé
            key_index = i % key_length
            key_shift = key_as_int[key_index]
            
            # Appliquer le décalage inverse
            if char.isupper():
                result += chr((ord(char) - ord('A') - key_shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') - key_shift) % 26 + ord('a'))
        else:
            result += char
    
    return result

# ======== CHIFFREMENT PAR BLOC/FLUX ========
def pad_text(text: str, block_size: int) -> str:
    """Ajoute du padding au texte pour qu'il soit un multiple du block_size."""
    padding_length = block_size - (len(text) % block_size)
    return text + chr(padding_length) * padding_length

def unpad_text(text: str) -> str:
    """Enlève le padding du texte."""
    padding_length = ord(text[-1])
    return text[:-padding_length]

def block_cipher_encrypt(text: str, key: str, block_size: int = 8) -> str:
    """Chiffrement par bloc simple (XOR avec la clé)."""
    # Ajouter du padding
    padded_text = pad_text(text, block_size)
    
    # Étendre la clé si nécessaire
    extended_key = key * (len(padded_text) // len(key) + 1)
    extended_key = extended_key[:len(padded_text)]
    
    # Chiffrer bloc par bloc
    result = ""
    for i in range(0, len(padded_text), block_size):
        block = padded_text[i:i+block_size]
        key_block = extended_key[i:i+block_size]
        
        # XOR chaque caractère avec la clé
        encrypted_block = ''.join(chr(ord(block[j]) ^ ord(key_block[j])) for j in range(block_size))
        result += encrypted_block
    
    # Convertir en base64 pour faciliter le stockage
    return base64.b64encode(result.encode()).decode()

def block_cipher_decrypt(b64_text: str, key: str, block_size: int = 8) -> str:
    """Déchiffrement par bloc simple."""
    # Convertir de base64 à texte
    text = base64.b64decode(b64_text).decode()
    
    # Étendre la clé si nécessaire
    extended_key = key * (len(text) // len(key) + 1)
    extended_key = extended_key[:len(text)]
    
    # Déchiffrer bloc par bloc
    result = ""
    for i in range(0, len(text), block_size):
        block = text[i:i+block_size]
        key_block = extended_key[i:i+block_size]
        
        # XOR chaque caractère avec la clé
        decrypted_block = ''.join(chr(ord(block[j]) ^ ord(key_block[j])) for j in range(len(block)))
        result += decrypted_block
    
    # Enlever le padding
    return unpad_text(result)

def stream_cipher_encrypt(text: str, key: str) -> str:
    """Chiffrement par flux simple (XOR avec la clé)."""
    # Étendre la clé si nécessaire
    extended_key = key * (len(text) // len(key) + 1)
    extended_key = extended_key[:len(text)]
    
    # XOR chaque caractère avec la clé
    result = ''.join(chr(ord(text[i]) ^ ord(extended_key[i])) for i in range(len(text)))
    
    # Convertir en base64 pour faciliter le stockage
    return base64.b64encode(result.encode()).decode()

def stream_cipher_decrypt(b64_text: str, key: str) -> str:
    """Déchiffrement par flux simple."""
    # Convertir de base64 à texte
    text = base64.b64decode(b64_text).decode()
    
    # Étendre la clé si nécessaire
    extended_key = key * (len(text) // len(key) + 1)
    extended_key = extended_key[:len(text)]
    
    # XOR chaque caractère avec la clé
    return ''.join(chr(ord(text[i]) ^ ord(extended_key[i])) for i in range(len(text)))

# ======== DES ET VARIANTES ========
# Tables complètes pour DES
# Permutation initiale (IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Permutation finale (IP^-1)
IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

# Expansion D-box (E)
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Permutation (P)
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# S-boxes complètes
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Permutation de choix 1 (PC-1)
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permutation de choix 2 (PC-2)
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Nombre de rotations à gauche pour chaque round
ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute(block: List[int], table: List[int]) -> List[int]:
    """Permute le bloc selon la table de permutation."""
    return [block[i-1] for i in table]

def string_to_bits(text: str) -> List[int]:
    """Convertit une chaîne de caractères en liste de bits."""
    result = []
    for char in text:
        # Convertir chaque caractère en 8 bits
        bits = bin(ord(char))[2:].zfill(8)
        result.extend([int(bit) for bit in bits])
    return result


def bits_to_string(bits: List[int]) -> str:
    """Convertit une liste de bits en chaîne de caractères."""
    result = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        result += chr(int(''.join(map(str, byte)), 2))
    return result

def split_blocks(bits: List[int], size: int) -> List[List[int]]:
    """Divise une liste de bits en blocs de taille donnée."""
    return [bits[i:i+size] for i in range(0, len(bits), size)]

def generate_subkeys(key: str) -> List[List[int]]:
    """Génère les sous-clés pour DES."""
    # Convertir la clé en bits
    key_bits = string_to_bits(key)
    
    # Assurer que la clé a 64 bits
    if len(key_bits) < 64:
        key_bits.extend([0] * (64 - len(key_bits)))
    key_bits = key_bits[:64]
    
    # Appliquer PC-1
    key_56 = permute(key_bits, PC1)
    
    # Diviser en moitiés gauche et droite
    left = key_56[:28]
    right = key_56[28:]
    
    # Générer 16 sous-clés
    subkeys = []
    for i in range(16):
        # Rotation à gauche
        left = left[ROTATIONS[i]:] + left[:ROTATIONS[i]]
        right = right[ROTATIONS[i]:] + right[:ROTATIONS[i]]
        
        # Combiner et appliquer PC-2
        combined = left + right
        subkey = permute(combined, PC2)
        
        subkeys.append(subkey)
    
    return subkeys

def des_round(block: List[int], subkey: List[int]) -> List[int]:
    """Un round de lalgorithme DES."""
    # Diviser le bloc en deux moitiés
    left, right = block[:32], block[32:]
    
    # Expansion
    expanded_right = permute(right, E)
    
    # XOR avec la sous-clé
    xor_result = [expanded_right[i] ^ subkey[i] for i in range(48)]
    
    # S-boxes
    s_box_result = []
    for i in range(8):
        # Prendre 6 bits
        group = xor_result[i*6:(i+1)*6]
        
        # Calculer la ligne et la colonne pour la S-box
        row = group[0] * 2 + group[5]
        col = group[1] * 8 + group[2] * 4 + group[3] * 2 + group[4]
        
        # Obtenir la valeur de la S-box
        val = S_BOXES[i][row][col]
        
        # Convertir en 4 bits
        s_box_result.extend([int(bit) for bit in bin(val)[2:].zfill(4)])
    
    # Permutation P
    permuted = permute(s_box_result, P)
    
    # XOR avec la partie gauche
    new_right = [left[i] ^ permuted[i] for i in range(32)]
    
    # Retourner la nouvelle combinaison (ancien droit, nouveau droit)
    return right + new_right

def des_encrypt_manual(text: str, key: str) -> str:
    """Chiffrement DES manuel."""
    # Convertir le texte en bits
    text_bits = string_to_bits(text)
    
    # Ajouter du padding si nécessaire
    if len(text_bits) % 64 != 0:
        text_bits.extend([0] * (64 - (len(text_bits) % 64)))
    
    # Générer les sous-clés
    subkeys = generate_subkeys(key)
    
    # Chiffrer chaque bloc de 64 bits
    result_bits = []
    for i in range(0, len(text_bits), 64):
        block = text_bits[i:i+64]
        
        # Permutation initiale
        block = permute(block, IP)
        
        # 16 rounds
        for j in range(16):
            block = des_round(block, subkeys[j])
        
        # Échanger les moitiés gauche et droite
        block = block[32:] + block[:32]
        
        # Permutation finale
        block = permute(block, IP_INV)
        
        result_bits.extend(block)
    
    # Convertir les bits en chaîne base64
    result_bytes = bytearray()
    for i in range(0, len(result_bits), 8):
        byte = result_bits[i:i+8]
        result_bytes.append(int(''.join(map(str, byte)), 2))
    
    return base64.b64encode(result_bytes).decode()

def des_decrypt_manual(b64_text: str, key: str) -> str:
    """Déchiffrement DES manuel."""
    # Convertir le base64 en bits
    text_bytes = base64.b64decode(b64_text)
    text_bits = []
    for byte in text_bytes:
        text_bits.extend([int(bit) for bit in bin(byte)[2:].zfill(8)])
    
    # Générer les sous-clés (dans l'ordre inverse pour le déchiffrement)
    subkeys = generate_subkeys(key)
    subkeys.reverse()
    
    # Déchiffrer chaque bloc de 64 bits
    result_bits = []
    for i in range(0, len(text_bits), 64):
        block = text_bits[i:i+64]
        
        # Permutation initiale
        block = permute(block, IP)
        
        # 16 rounds
        for j in range(16):
            block = des_round(block, subkeys[j])
        
        # Échanger les moitiés gauche et droite
        block = block[32:] + block[:32]
        
        # Permutation finale
        block = permute(block, IP_INV)
        
        result_bits.extend(block)
    
    # Convertir les bits en chaîne de caractères
    return bits_to_string(result_bits).rstrip('\x00')

# Utilisation de la bibliothèque pycryptodome pour DES si disponible
def des_encrypt(text: str, key: str) -> str:
    """Chiffrement DES."""
    if CRYPTO_LIBS_AVAILABLE:
        # Utiliser la bibliothèque pycryptodome
        # Assurer que la clé a 8 octets
        key_bytes = key.encode()[:8].ljust(8, b'\0')
        
        # Créer le chiffreur
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        
        # Ajouter du padding et chiffrer
        padded_text = pad(text.encode(), 8)
        encrypted = cipher.encrypt(padded_text)
        
        # Retourner en base64
        return base64.b64encode(encrypted).decode()
    else:
        # Utiliser l'implémentation manuelle
        return des_encrypt_manual(text, key)

def des_decrypt(b64_text: str, key: str) -> str:
    """Déchiffrement DES."""
    if CRYPTO_LIBS_AVAILABLE:
        # Utiliser la bibliothèque pycryptodome
        # Assurer que la clé a 8 octets
        key_bytes = key.encode()[:8].ljust(8, b'\0')
        
        # Créer le déchiffreur
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        
        # Déchiffrer
        encrypted = base64.b64decode(b64_text)
        decrypted = cipher.decrypt(encrypted)
        
        # Enlever le padding
        try:
            unpadded = unpad(decrypted, 8)
            return unpadded.decode()
        except ValueError:
            # Si le padding est incorrect, retourner le texte brut
            return decrypted.decode(errors='replace')
    else:
        # Utiliser l'implémentation manuelle
        return des_decrypt_manual(b64_text, key)

def triple_des_encrypt(text: str, key1: str, key2: str, key3: str) -> str:
    """Chiffrement Triple DES."""
    if CRYPTO_LIBS_AVAILABLE:
        # Utiliser la bibliothèque pycryptodome
        # Combiner les clés
        key_bytes = (key1.encode()[:8].ljust(8, b'\0') + 
                     key2.encode()[:8].ljust(8, b'\0') + 
                     key3.encode()[:8].ljust(8, b'\0'))
        
        # Créer le chiffreur
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
        
        # Ajouter du padding et chiffrer
        padded_text = pad(text.encode(), 8)
        encrypted = cipher.encrypt(padded_text)
        
        # Retourner en base64
        return base64.b64encode(encrypted).decode()
    else:
        # Implémentation manuelle
        encrypted1 = des_encrypt(text, key1)
        decrypted = des_decrypt(encrypted1, key2)
        return des_encrypt(decrypted, key3)

def triple_des_decrypt(b64_text: str, key1: str, key2: str, key3: str) -> str:
    """Déchiffrement Triple DES."""
    if CRYPTO_LIBS_AVAILABLE:
        # Utiliser la bibliothèque pycryptodome
        # Combiner les clés
        key_bytes = (key1.encode()[:8].ljust(8, b'\0') + 
                     key2.encode()[:8].ljust(8, b'\0') + 
                     key3.encode()[:8].ljust(8, b'\0'))
        
        # Créer le déchiffreur
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
        
        # Déchiffrer
        encrypted = base64.b64decode(b64_text)
        decrypted = cipher.decrypt(encrypted)
        
        # Enlever le padding
        try:
            unpadded = unpad(decrypted, 8)
            return unpadded.decode()
        except ValueError:
            # Si le padding est incorrect, retourner le texte brut
            return decrypted.decode(errors='replace')
    else:
        # Implémentation manuelle
        decrypted1 = des_decrypt(b64_text, key3)
        encrypted = des_encrypt(decrypted1, key2)
        return des_decrypt(encrypted, key1)

def desx_encrypt(text: str, key: str, key_pre: str, key_post: str) -> str:
    """Chiffrement DESX corrigé."""
    # Étendre key_pre à la longueur du texte
    extended_key_pre = (key_pre * (len(text) // len(key_pre) + 1))[:len(text)]
    
    # XOR avec la première clé (pré-blanchiment)
    pre_xor = ''.join(chr(ord(text[i]) ^ ord(extended_key_pre[i])) for i in range(len(text)))
    
    # Chiffrer avec DES
    des_result = des_encrypt(pre_xor, key)
    
    # Convertir le base64 en bytes pour post-blanchiment
    des_bytes = base64.b64decode(des_result)
    
    # Étendre key_post à la longueur des bytes DES
    extended_key_post = (key_post * (len(des_bytes) // len(key_post) + 1))[:len(des_bytes)]
    
    # XOR avec la troisième clé (post-blanchiment)
    post_xor = bytes(des_bytes[i] ^ ord(extended_key_post[i % len(key_post)]) for i in range(len(des_bytes)))
    
    # Convertir en base64
    return base64.b64encode(post_xor).decode()

def desx_decrypt(b64_text: str, key: str, key_pre: str, key_post: str) -> str:
    """Déchiffrement DESX corrigé."""
    # Convertir le base64 en bytes
    encrypted_bytes = base64.b64decode(b64_text)
    
    # Étendre key_post à la longueur des bytes chiffrés
    extended_key_post = (key_post * (len(encrypted_bytes) // len(key_post) + 1))[:len(encrypted_bytes)]
    
    # XOR avec la troisième clé (annuler le post-blanchiment)
    post_xor = bytes(encrypted_bytes[i] ^ ord(extended_key_post[i % len(key_post)]) for i in range(len(encrypted_bytes)))
    
    # Convertir en base64 pour DES
    post_xor_b64 = base64.b64encode(post_xor).decode()
    
    # Déchiffrer avec DES
    des_result = des_decrypt(post_xor_b64, key)
    
    # Étendre key_pre à la longueur du résultat DES
    extended_key_pre = (key_pre * (len(des_result) // len(key_pre) + 1))[:len(des_result)]
    
    # XOR avec la première clé (annuler le pré-blanchiment)
    pre_xor = ''.join(chr(ord(des_result[i]) ^ ord(extended_key_pre[i])) for i in range(len(des_result)))
    
    return pre_xor

# Version alternative plus robuste qui évite les problèmes d'encodage
def desx_encrypt_robust(text: str, key: str, key_pre: str, key_post: str) -> str:
    """Chiffrement DESX robuste."""
    # Convertir tout en bytes dès le début
    text_bytes = text.encode('utf-8')
    key_pre_bytes = key_pre.encode('utf-8')
    key_post_bytes = key_post.encode('utf-8')
    
    # Pré-blanchiment : XOR avec key_pre
    pre_xor = bytes(text_bytes[i] ^ key_pre_bytes[i % len(key_pre_bytes)] for i in range(len(text_bytes)))
    
    # Chiffrer avec DES
    # Convertir pre_xor en string pour la fonction DES existante
    pre_xor_str = pre_xor.decode('latin-1')  # latin-1 préserve tous les bytes
    des_result = des_encrypt(pre_xor_str, key)
    
    # Convertir le résultat DES de base64 vers bytes
    des_bytes = base64.b64decode(des_result)
    
    # Post-blanchiment : XOR avec key_post
    post_xor = bytes(des_bytes[i] ^ key_post_bytes[i % len(key_post_bytes)] for i in range(len(des_bytes)))
    
    # Retourner en base64
    return base64.b64encode(post_xor).decode()

def desx_decrypt_robust(b64_text: str, key: str, key_pre: str, key_post: str) -> str:
    """Déchiffrement DESX robuste."""
    # Convertir les clés en bytes
    key_pre_bytes = key_pre.encode('utf-8')
    key_post_bytes = key_post.encode('utf-8')
    
    # Décoder de base64
    encrypted_bytes = base64.b64decode(b64_text)
    
    # Annuler le post-blanchiment
    post_unxor = bytes(encrypted_bytes[i] ^ key_post_bytes[i % len(key_post_bytes)] for i in range(len(encrypted_bytes)))
    
    # Convertir en base64 pour DES
    post_unxor_b64 = base64.b64encode(post_unxor).decode()
    
    # Déchiffrer avec DES
    des_result = des_decrypt(post_unxor_b64, key)
    
    # Convertir le résultat DES en bytes
    des_bytes = des_result.encode('latin-1')
    
    # Annuler le pré-blanchiment
    pre_unxor = bytes(des_bytes[i] ^ key_pre_bytes[i % len(key_pre_bytes)] for i in range(len(des_bytes)))
    
    # Convertir en string
    return pre_unxor.decode('utf-8')

# ======== INTERFACE UTILISATEUR ========
def print_banner():
    """Affiche une bannière pour l'application."""
    print("=" * 80)
    print("                     OUTIL DE CRYPTOGRAPHIE                     ")
    print("=" * 80)
    print("Cet outil permet de chiffrer et déchiffrer des textes avec différentes méthodes.")
    print("=" * 80)

def get_method_choice():
    """Demande à l'utilisateur de choisir une méthode de chiffrement."""
    print("\nMéthodes disponibles:")
    print("1. César")
    print("2. Substitution aléatoire")
    print("3. Chiffrement Affine")
    print("4. Chiffre de Hill")
    print("5. Chiffre de Playfair")
    print("6. Chiffre de Vigenère")
    print("7. Chiffrement par bloc")
    print("8. Chiffrement par flux")
    print("9. DES")
    print("10. Triple DES")
    print("11. DESX")
    print("0. Quitter")
    
    while True:
        try:
            choice = int(input("\nChoisissez une méthode (0-11): "))
            if 0 <= choice <= 11:
                return choice
            else:
                print("Choix invalide. Veuillez entrer un nombre entre 0 et 11.")
        except ValueError:
            print("Entrée invalide. Veuillez entrer un nombre.")

def get_action_choice():
    """Demande à l'utilisateur de choisir entre chiffrer et déchiffrer."""
    print("\nActions disponibles:")
    print("1. Chiffrer")
    print("2. Déchiffrer")
    
    while True:
        try:
            choice = int(input("\nChoisissez une action (1-2): "))
            if choice in [1, 2]:
                return choice
            else:
                print("Choix invalide. Veuillez entrer 1 ou 2.")
        except ValueError:
            print("Entrée invalide. Veuillez entrer un nombre.")

def get_text():
    """Demande à l'utilisateur d'entrer un texte."""
    return input("\nEntrez le texte: ")

def get_cesar_params():
    """Demande les paramètres pour le chiffrement de César."""
    while True:
        try:
            shift = int(input("\nEntrez le décalage (1-25): "))
            if 1 <= shift <= 25:
                return shift
            else:
                print("Décalage invalide. Veuillez entrer un nombre entre 1 et 25.")
        except ValueError:
            print("Entrée invalide. Veuillez entrer un nombre.")

def get_substitution_table():
    """Génère ou demande une table de substitution."""
    choice = input("\nVoulez-vous générer une table de substitution aléatoire? (o/n): ").lower()
    if choice == 'o':
        table = generate_random_substitution()
        print("\nTable de substitution générée:")
        for k, v in table.items():
            print(f"{k} -> {v}", end=", ")
        print()
        return table
    else:
        print("\nVeuillez entrer une table de substitution sous forme de dictionnaire Python.")
        print("Exemple: {'a': 'q', 'b': 'w', ...}")
        while True:
            try:
                table_str = input("\nTable de substitution: ")
                table = eval(table_str)
                if isinstance(table, dict):
                    return table
                else:
                    print("Format invalide. Veuillez entrer un dictionnaire.")
            except:
                print("Format invalide. Veuillez entrer un dictionnaire valide.")

def get_affine_params():
    """Demande les paramètres pour le chiffrement affine."""
    while True:
        try:
            a = int(input("\nEntrez le paramètre a (doit être premier avec 26): "))
            b = int(input("Entrez le paramètre b (0-25): "))
            if pgcd(a, 26) == 1 and 0 <= b <= 25:
                return a, b
            else:
                if pgcd(a, 26) != 1:
                    print("Le paramètre a doit être premier avec 26.")
                if not (0 <= b <= 25):
                    print("Le paramètre b doit être entre 0 et 25.")
        except ValueError:
            print("Entrée invalide. Veuillez entrer des nombres.")

def get_hill_params():
    """Demande les paramètres pour le chiffre de Hill."""
    print("\nPour le chiffre de Hill, nous utiliserons une matrice 2x2.")
    while True:
        try:
            a = int(input("Entrez le premier élément (a11): "))
            b = int(input("Entrez le deuxième élément (a12): "))
            c = int(input("Entrez le troisième élément (a21): "))
            d = int(input("Entrez le quatrième élément (a22): "))
            
            matrix = np.array([[a, b], [c, d]])
            det = int(round(np.linalg.det(matrix))) % 26
            
            if pgcd(det, 26) == 1:
                return matrix
            else:
                print("La matrice n'est pas inversible modulo 26. Veuillez entrer d'autres valeurs.")
        except ValueError:
            print("Entrée invalide. Veuillez entrer des nombres.")

def get_playfair_key():
    """Demande la clé pour le chiffre de Playfair."""
    while True:
        key = input("\nEntrez la clé pour Playfair: ")
        if key.strip():
            return key
        else:
            print("La clé ne peut pas être vide.")

def get_vigenere_key():
    """Demande la clé pour le chiffre de Vigenère."""
    while True:
        key = input("\nEntrez la clé pour Vigenère: ")
        if key.strip() and key.isalpha():
            return key
        else:
            print("La clé doit contenir uniquement des lettres et ne peut pas être vide.")

def get_block_key():
    """Demande la clé pour le chiffrement par bloc."""
    while True:
        key = input("\nEntrez la clé pour le chiffrement par bloc: ")
        if key.strip():
            return key
        else:
            print("La clé ne peut pas être vide.")

def get_des_key():
    """Demande la clé pour DES."""
    while True:
        key = input("\nEntrez la clé pour DES (8 caractères recommandés): ")
        if key.strip():
            if len(key) < 8:
                print("Attention: La clé est inférieure à 8 caractères et sera complétée.")
            return key
        else:
            print("La clé ne peut pas être vide.")

def get_triple_des_keys():
    """Demande les clés pour Triple DES."""
    key1 = input("\nEntrez la première clé pour Triple DES: ")
    key2 = input("Entrez la deuxième clé pour Triple DES: ")
    key3 = input("Entrez la troisième clé pour Triple DES: ")
    return key1, key2, key3

def get_desx_keys():
    """Demande les clés pour DESX."""
    key = input("\nEntrez la clé principale pour DESX: ")
    key_pre = input("Entrez la clé de pré-blanchiment pour DESX: ")
    key_post = input("Entrez la clé de post-blanchiment pour DESX: ")
    return key, key_pre, key_post

def main():
    """Fonction principale."""
    print_banner()
    
    while True:
        method = get_method_choice()
        
        if method == 0:
            print("\nAu revoir!")
            break
        
        action = get_action_choice()
        is_encrypt = action == 1
        
        text = get_text()
        result = ""
        
        try:
            if method == 1:  # César
                shift = get_cesar_params()
                if is_encrypt:
                    result = cesar_encrypt(text, shift)
                else:
                    result = cesar_decrypt(text, shift)
                
            elif method == 2:  # Substitution
                table = get_substitution_table()
                if is_encrypt:
                    result = substitution_encrypt(text, table)
                else:
                    result = substitution_decrypt(text, table)
                
            elif method == 3:  # Affine
                a, b = get_affine_params()
                if is_encrypt:
                    result = affine_encrypt(text, a, b)
                else:
                    result = affine_decrypt(text, a, b)
                
            elif method == 4:  # Hill
                matrix = get_hill_params()
                if is_encrypt:
                    result = hill_encrypt(text, matrix)
                else:
                    result = hill_decrypt(text, matrix)
                
            elif method == 5:  # Playfair
                key = get_playfair_key()
                if is_encrypt:
                    result = playfair_encrypt(text, key)
                else:
                    result = playfair_decrypt(text, key)
                
            elif method == 6:  # Vigenère
                key = get_vigenere_key()
                if is_encrypt:
                    result = vigenere_encrypt(text, key)
                else:
                    result = vigenere_decrypt(text, key)
                
            elif method == 7:  # Bloc
                key = get_block_key()
                if is_encrypt:
                    result = block_cipher_encrypt(text, key)
                else:
                    result = block_cipher_decrypt(text, key)
                
            elif method == 8:  # Flux
                key = get_block_key()
                if is_encrypt:
                    result = stream_cipher_encrypt(text, key)
                else:
                    result = stream_cipher_decrypt(text, key)
                
            elif method == 9:  # DES
                key = get_des_key()
                if is_encrypt:
                    result = des_encrypt(text, key)
                else:
                    result = des_decrypt(text, key)
                
            elif method == 10:  # Triple DES
                key1, key2, key3 = get_triple_des_keys()
                if is_encrypt:
                    result = triple_des_encrypt(text, key1, key2, key3)
                else:
                    result = triple_des_decrypt(text, key1, key2, key3)
                
            elif method == 11:  # DESX
                key, key_pre, key_post = get_desx_keys()
                if is_encrypt:
                    result = desx_encrypt_robust(text, key, key_pre, key_post)
                else:
                    result = desx_decrypt_robust(text, key, key_pre, key_post)

            print("\nRésultat:")
            print(result)
            
        except Exception as e:
            print(f"\nErreur: {e}")
    
if __name__ == "__main__":
    main()