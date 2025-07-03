from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_file(data, key):
    """Encrypts file data using AES."""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

def decrypt_file(encrypted_data, key):
    """Decrypts file data using AES."""
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt
