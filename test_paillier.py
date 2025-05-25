from signature.paillier_he import PaillierHE

def test_paillier():
    phe = PaillierHE()
    public_key, private_key = phe.generate_keypair(1024)
    phe.public_key = public_key
    phe.private_key = private_key
    print("Keys generated successfully")
    
    # Test encryption/decryption
    m = 42
    c = phe.encrypt(m)
    d = phe.decrypt(c)
    print(f"Original: {m}, Decrypted: {d}, Match: {m == d}")
    
    # Test homomorphic addition
    m1 = 30
    m2 = 12
    c1 = phe.encrypt(m1)
    c2 = phe.encrypt(m2)
    c_sum = PaillierHE.add_encrypted(c1, c2, phe.public_key)
    d_sum = phe.decrypt(c_sum)
    print(f"Sum test: {m1} + {m2} = {d_sum}, Expected: {m1 + m2}")
    
if __name__ == "__main__":
    test_paillier()
