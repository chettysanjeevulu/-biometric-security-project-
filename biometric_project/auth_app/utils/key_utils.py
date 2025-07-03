import hashlib
import os

def generate_private_key():
    """Generates a secure private key."""
    return os.urandom(32).hex()

def generate_session_key(biometric_hash, private_key):
    """Generates a session key from biometric hash and private key."""
    # A simple but effective way to combine them
    combined = biometric_hash.encode() + private_key.encode()
    # Use SHA-256 to create a 32-byte (256-bit) key, suitable for AES
    return hashlib.sha256(combined).digest()