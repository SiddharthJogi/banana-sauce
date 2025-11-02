import random
import math
import time
from hashlib import sha256
# --- Utilities ---
def is_probable_prime(n, k=8):
    """Miller-Rabin primality test"""
    if n < 2: return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d*2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
def generate_prime(bits):
    """Generate a prime of approx 'bits' bits."""
    while True:
        p = random.getrandbits(bits) | (1 << bits-1) | 1  # ensure top bit and odd
        if is_probable_prime(p):
            return p
def egcd(a, b):
    """Extended Euclidean Algorithm"""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    """Modular multiplicative inverse"""
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m
# --- RSA Key generation ---
def rsa_keygen(bits=1024):
    """Generate RSA key pair. bits is the size of modulus n (approx)."""
    half = bits // 2
    p = generate_prime(half)
    q = generate_prime(half)
    while q == p:
        q = generate_prime(half)
    n = p * q
    phi = (p - 1) * (q - 1)
    # common public exponent
    e = 65537
    if math.gcd(e, phi) != 1:
        # fallback: find small odd e
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}

# --- RSA operations ---
def rsa_encrypt(m_int, pub):
    """Encrypts message integer using public key (c = m^e mod n)"""
    return pow(m_int, pub['e'], pub['n'])


def rsa_decrypt(c_int, priv):
    """Decrypts ciphertext integer using private key (m = c^d mod n)"""
    return pow(c_int, priv['d'], priv['n'])

def int_from_bytes(b):
    """Converts bytes to a large integer."""
    return int.from_bytes(b, byteorder='big')

def int_to_bytes(i):
    """Converts a large integer to bytes (minimum length)."""
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length if length>0 else 1, byteorder='big')

def rsa_sign(message_bytes, priv):
    """Creates a signature by decrypting the message's hash."""
    # sign the SHA-256 hash (simple textbook-style)
    h = sha256(message_bytes).digest()
    m = int_from_bytes(h)
    s = pow(m, priv['d'], priv['n'])
    return s

def rsa_verify(message_bytes, signature_int, pub):
    """Verifies a signature by encrypting it and comparing with the hash."""
    h = sha256(message_bytes).digest()
    m = int_from_bytes(h)
    m2 = pow(signature_int, pub['e'], pub['n'])
    return m == m2

# --- Analysis / demo functions ---
def demo_round(bits=512, message="Hello RSA!"):
    """Runs a single round of RSA key generation, encryption, decryption, and signing."""
    print(f"\n--- RSA demo with {bits}-bit modulus (approx) ---")
    
    # 1. Key Generation
    t0 = time.perf_counter()
    keypair = rsa_keygen(bits)
    t1 = time.perf_counter()
    gen_time = t1 - t0
    pub = {'n': keypair['n'], 'e': keypair['e']}
    priv = {'n': keypair['n'], 'd': keypair['d']}
    print(f"Key Generation: {gen_time:.3f} s (Modulus N: {keypair['n'].bit_length()} bits)")

    # --- ADDED: Private Key Components for Educational Purposes ---
    print("\n--- Private Key Components (Educational Demo) ---")
    print(f"Prime p: {keypair['p']}")
    print(f"Prime q: {keypair['q']}")
    # Truncate private exponent d for readability
    d_str = str(priv['d'])
    print(f"Private exponent d (truncated): {d_str[:20]}... (length: {len(d_str)} digits)")
    print("--------------------------------------------------")
    # -----------------------------------------------------------------

    # 2. Preparation (Plaintext -> Integer)
    m_bytes = message.encode('utf-8')
    m_int = int_from_bytes(m_bytes)
    if m_int >= pub['n']:
        raise ValueError("Message too long for this key size.")
    
    # Print original message (Plaintext)
    print(f"Plaintext message: '{message}'")
    
    # 3. Encrypt
    t2 = time.perf_counter()
    c = rsa_encrypt(m_int, pub)
    t3 = time.perf_counter()
    enc_time = t3 - t2
    
    # Print Ciphertext (truncated)
    c_bytes_hex = int_to_bytes(c).hex()
    print(f"Encrypted message (Ciphertext Hex, truncated): {c_bytes_hex[:40]}...")
    
    # 4. Decrypt
    t4 = time.perf_counter()
    m2 = rsa_decrypt(c, priv)
    t5 = time.perf_counter()
    dec_time = t5 - t4
    
    decrypted = int_to_bytes(m2).decode('utf-8')
    
    # Print decrypted message
    print(f"Decrypted message: '{decrypted}'")
    print(f"Encrypt/Decrypt Time: Enc={enc_time:.6f} s, Dec={dec_time:.6f} s")
    print(f"End-to-end check: {'SUCCESS' if message == decrypted else 'FAILED'}")

    # 5. Sign & Verify
    sig = rsa_sign(m_bytes, priv)
    ok = rsa_verify(m_bytes, sig, pub)
    print(f"Signature valid: {ok}")
    
    return {'bits': bits, 'keygen_s': gen_time, 'enc_s': enc_time, 'dec_s': dec_time, 'n_bits': keypair['n'].bit_length()}

def performance_test(sizes=[512, 768, 1024], message="hello world"):
    """Runs the demo for multiple key sizes using a fixed message."""
    results = []
    print(f"--- Running performance tests with message: '{message}' ---")
    for s in sizes:
        r = demo_round(bits=s, message=message)
        results.append(r)
    print("\n\n--- Performance Summary ---")
    print("Bits | Keygen (s) | Enc (s) | Dec (s) | N bits")
    print("------------------------------------------------")
    for r in results:
        print(f"{r['bits']:4} | {r['keygen_s']:.5f} | {r['enc_s']:.6f} | {r['dec_s']:.6f} | {r['n_bits']}")

if __name__ == "__main__":
    # Change sizes below for more analysis—be careful, >2048 may take a long time in pure Python.
    # The message is now fixed to 'hello world' for all tests as requested.
    sizes_to_test = [512, 768, 1024]
    performance_test(sizes_to_test, message="hello world")
