import hashlib
import hmac

# Function to demonstrate hash functions
def hash_demo(message):
    print("Original Message:", message)
    
    # SHA-256 Hash
    sha256_hash = hashlib.sha256(message.encode()).hexdigest()
    print("SHA-256 Hash:", sha256_hash)
    
    # SHA-512 Hash
    sha512_hash = hashlib.sha512(message.encode()).hexdigest()
    print("SHA-512 Hash:", sha512_hash)
    
    return sha256_hash, sha512_hash

# Function to demonstrate HMAC
def hmac_demo(message, key):
    print("\nUsing HMAC for message authentication:")
    key_bytes = key.encode()
    message_bytes = message.encode()
    
    # Using SHA256 for HMAC
    hmac_sha256 = hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()
    print("HMAC-SHA256:", hmac_sha256)
    
    # Using SHA512 for HMAC
    hmac_sha512 = hmac.new(key_bytes, message_bytes, hashlib.sha512).hexdigest()
    print("HMAC-SHA512:", hmac_sha512)
    return hmac_sha256, hmac_sha512

# Main program
if __name__ == "__main__":
    message = input("Enter the message: ")
    key = input("Enter the secret key for HMAC: ")
    # Demonstrate Hash Functions
    hash_demo(message)
    # Demonstrate HMAC
    hmac_demo(message, key)
