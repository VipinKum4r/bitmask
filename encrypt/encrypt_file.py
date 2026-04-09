import os
import hashlib
import sys
import argparse

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Match OpenSSL's default: PBKDF2-HMAC-SHA256, 10000 iterations
_PBKDF2_ITERATIONS = 10000
_SALT_SIZE = 8        # OpenSSL uses 8-byte salt
_OPENSSL_MAGIC = b"Salted__"

def _read_passphrase(keyphrase_file):
    """Read passphrase from file, stripping trailing whitespace (mirrors openssl file: behaviour)."""
    with open(keyphrase_file, "rb") as f:
        return f.read().rstrip()

def _derive_key_iv(passphrase: bytes, salt: bytes):
    """Derive a 256-bit key + 128-bit IV via PBKDF2-HMAC-SHA256 (OpenSSL-compatible)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,          # 32 bytes key + 16 bytes IV
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    derived = kdf.derive(passphrase)
    return derived[:32], derived[32:48]

def encrypt_file(filename, keyphrase_file, output_dir=None):
    try:
        # Check if the encrypted file exists
        if not os.path.exists(filename):
            print(f"Error: File '{filename}' not found.")
            sys.exit(1)

        # Check if the keyphrase file exists
        if not os.path.exists(keyphrase_file):
            print(f"Error: Key file '{keyphrase_file}' not found.")
            sys.exit(1)
        
        # Set output file path with extension
        encrypted_file = os.path.join(
            output_dir if output_dir else os.getcwd(), os.path.basename(filename) + ".enc")

        passphrase = _read_passphrase(keyphrase_file)
        salt = os.urandom(_SALT_SIZE)
        key, iv = _derive_key_iv(passphrase, salt)

        with open(filename, "rb") as f:
            plaintext = f.read()

        # PKCS7 padding
        padder = sym_padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # AES-256-CBC encryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Write OpenSSL-compatible output: "Salted__" + salt + ciphertext
        with open(encrypted_file, "wb") as f:
            f.write(_OPENSSL_MAGIC + salt + ciphertext)
        
        # Generate SHA256 digest of the encrypted file
        sha256_filename = f"{encrypted_file}.sha256"
        with open(encrypted_file, "rb") as enc_file:
            enc_data = enc_file.read()
            sha256_hash = hashlib.sha256(enc_data).hexdigest()
        with open(sha256_filename, "w") as hash_file:
            hash_file.write(sha256_hash)
        
        print(f"File encrypted successfully: {encrypted_file}")
        print(f"SHA256 digest saved: {sha256_filename}")
    
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt a file with a key.")
    parser.add_argument("filename", help="File to encrypt")
    parser.add_argument("keyphrase_file", help="Keyphrase file to use for symmetric encryption")
    parser.add_argument("-o", "--output", help="Output directory for the encrypted file")
    args = parser.parse_args()
    
    encrypt_file(args.filename, args.keyphrase_file, args.output)

