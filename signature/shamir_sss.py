import random
from Crypto.Util.number import getPrime

try:
    # Parameters
    secret_message = "MyTopSecretPassword123!"
    # Convert secret string to integer. Ensure prime is large enough.
    secret_int = int.from_bytes(secret_message.encode('utf-8'), 'big')
    k = 3  # Threshold: 3 shares needed
    n = 5  # Total shares: 5 generated

    # Define a function to get a prime larger than the secret integer
    def get_sss_prime(secret_int):
        # A simple way: use a known large prime or find the next prime after secret_int
        # For demonstration, use a hardcoded large prime (should be > secret_int)
        # Example: 2^127 - 1 (Mersenne prime)
        return 170141183460469231731687303715884105727

    prime = get_sss_prime(secret_int)

    print(f"Secret Message: {secret_message}")
    print(f"Secret as Integer: {secret_int}")
    print(f"Threshold (K): {k}")

except Exception as e:
    print(f"An error occurred: {e}")
    raise

class ShamirSecretSharing:
    def __init__(self, threshold, total_shares):
        self.t = threshold  # minimum shares needed
        self.n = total_shares  # total number of shares
        self.prime = getPrime(256)  # Field size
    
    def generate_shares(self, secret):
        if not isinstance(secret, int):
            secret = int.from_bytes(secret.encode(), 'big')
        
        # Generate random coefficients
        coef = [secret] + [random.randrange(self.prime) for _ in range(self.t - 1)]
        
        # Generate shares
        shares = []
        for i in range(1, self.n + 1):
            # Evaluate polynomial
            accum = 0
            for j in range(self.t):
                accum += coef[j] * pow(i, j)
            shares.append((i, accum % self.prime))
        
        return shares
    
    def reconstruct_secret(self, shares):
        if len(shares) < self.t:
            raise ValueError(f"Need at least {self.t} shares")
        
        # Use Lagrange interpolation
        secret = 0
        for i, share_i in shares[:self.t]:
            numerator = denominator = 1
            for j, share_j in shares[:self.t]:
                if i != j:
                    numerator = (numerator * -j) % self.prime
                    denominator = (denominator * (i - j)) % self.prime
            
            lagrange = (numerator * pow(denominator, -1, self.prime)) % self.prime
            secret = (secret + share_i * lagrange) % self.prime
        
        return secret