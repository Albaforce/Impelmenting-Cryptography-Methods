import struct

# Left Rotate Function (ROL)
def rol(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & 0xffffffff

# Define the round functions
def f(j, x, y, z):
    if 0 <= j <= 15:
        return x ^ y ^ z
    elif 16 <= j <= 31:
        return (x & y) | (~x & z)
    elif 32 <= j <= 47:
        return (x | ~y) ^ z
    elif 48 <= j <= 63:
        return (x & z) | (y & ~z)
    elif 64 <= j <= 79:
        return x ^ (y | ~z)

# Constants
K = [0x00000000]*16 + [0x5a827999]*16 + [0x6ed9eba1]*16 + [0x8f1bbcdc]*16 + [0xa953fd4e]*16
KK = [0x50a28be6]*16 + [0x5c4dd124]*16 + [0x6d703ef3]*16 + [0x7a6d76e9]*16 + [0x00000000]*16

# Message word order for left and right lines
X = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
    3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
    1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
    4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
]

XX = [
    5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
    6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
    15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
    8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
    12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
]

# Rotation amounts for left line
R = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
]

# Rotation amounts for right line
RR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
]

# RIPEMD-160 hash function
def ripemd160(message: bytes) -> str:
    # Initial values
    h = [
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0
    ]

    # Preprocessing
    ml = len(message) * 8
    message += b'\x80'
    while (len(message) % 64) != 56:
        message += b'\x00'
    message += ml.to_bytes(8, byteorder='little')

    # Process each 512-bit block
    for offset in range(0, len(message), 64):
        block = message[offset:offset+64]
        X_words = list(struct.unpack('<16I', block))

        A1, B1, C1, D1, E1 = h
        A2, B2, C2, D2, E2 = h

        # Main loop
        for j in range(80):
            T = rol((A1 + f(j, B1, C1, D1) + X_words[X[j]] + K[j]) & 0xffffffff, R[j])
            T = (T + E1) & 0xffffffff
            A1, E1, D1, C1, B1 = E1, D1, rol(C1, 10), B1, T

            T = rol((A2 + f(79-j, B2, C2, D2) + X_words[XX[j]] + KK[j]) & 0xffffffff, RR[j])
            T = (T + E2) & 0xffffffff
            A2, E2, D2, C2, B2 = E2, D2, rol(C2, 10), B2, T

        T = (h[1] + C1 + D2) & 0xffffffff
        h[1] = (h[2] + D1 + E2) & 0xffffffff
        h[2] = (h[3] + E1 + A2) & 0xffffffff
        h[3] = (h[4] + A1 + B2) & 0xffffffff
        h[4] = (h[0] + B1 + C2) & 0xffffffff
        h[0] = T

    # Return the final hash as a hex string
    return ''.join(f'{value:08x}' for value in h)
def RIPEMD160(data):
    """Wrapper to accept str or bytes and return RIPEMD-160 hex string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return ripemd160(data)

# Example usage
ripemd_hash = RIPEMD160(b"hello world")
print("RIPEMD-160 Hash of 'hello world':", ripemd_hash)
