# Importing the necessary modules
from Crypto.Cipher import AES
import base64
import hashlib
import os

# Padding function to add padding to the input data
def pad(s):
    return s.encode('utf-8') + (AES.block_size - len(s) % AES.block_size) * b"\0"


def encrypt(message, key):
    message = message.encode('utf-8') + (AES.block_size - len(message) % AES.block_size) * b"\0"
    iv = b"1111111111111111" # Initialization vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(message))

# # Decryption function to decrypt the input data using AES
# def decrypt(ciphertext, key):
#     ciphertext = base64.b64decode(ciphertext)
#     iv = ciphertext[:16]
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     plaintext = cipher.decrypt(ciphertext[16:])
#     return plaintext.rstrip(b"\0")

# Hash function to generate SHA1 hash of the input data
def sha1_hash(data):
    hash_object = hashlib.sha1(data)
    return hash_object.hexdigest()

# Example usage
message = b"5678" 
hash_value = sha1_hash(message)
print("SHA1 hash value:", hash_value)

# Example usage
key = os.urandom(16) # 16-byte key for AES-128
encrypted_message = encrypt(hash_value, key)
print("Encrypted message:", (encrypted_message))

# decrypted_message = decrypt(encrypted_message, key)
# print("Decrypted message:", decrypted_message)
