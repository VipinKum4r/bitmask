import os
import sys
import argparse

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

_PBKDF2_ITERATIONS = 10000
_OPENSSL_MAGIC = b"Salted__"


def _read_passphrase(keyphrase_file):
    """Read passphrase from file, stripping trailing whitespace (mirrors openssl file: behaviour)."""
    with open(keyphrase_file, "rb") as f:
        return f.read().rstrip()


def _derive_key_iv(passphrase: bytes, salt: bytes):
    """Derive a 256-bit key + 128-bit IV via PBKDF2-HMAC-SHA256 (OpenSSL-compatible)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    derived = kdf.derive(passphrase)
    return derived[:32], derived[32:48]


def decrypt_file(encrypted_filename, keyphrase_file, output_path=None):
    try:
        # Check if the encrypted file exists
        if not os.path.exists(encrypted_filename):
            print(f"Error: Encrypted file '{encrypted_filename}' not found.")
            sys.exit(1)

        # Check if the keyphrase file exists
        if not os.path.exists(keyphrase_file):
            print(f"Error: Key file '{keyphrase_file}' not found.")
            sys.exit(1)

        # Remove .enc extension if it exists, otherwise maintain the original filename
        if encrypted_filename.endswith(".enc"):
            output_filename = encrypted_filename[:-4]
        else:
            output_filename = encrypted_filename

        # If an output path is provided, use it; otherwise, output to the current directory
        output_filename = os.path.join(
            output_path if output_path else os.getcwd(), os.path.basename(output_filename))

        with open(encrypted_filename, "rb") as f:
            data = f.read()

        if not data.startswith(_OPENSSL_MAGIC):
            print("Error: File does not appear to be an OpenSSL-compatible encrypted file "
                  "(missing 'Salted__' header).", file=sys.stderr)
            sys.exit(1)

        salt       = data[8:16]
        ciphertext = data[16:]

        passphrase = _read_passphrase(keyphrase_file)
        key, iv = _derive_key_iv(passphrase, salt)

        # AES-256-CBC decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        try:
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError:
            print("Error: Decryption failed — wrong keyphrase or corrupted file.", file=sys.stderr)
            sys.exit(1)

        with open(output_filename, "wb") as f:
            f.write(plaintext)

        print(f"File decrypted successfully: {output_filename}")

    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt an encrypted file using a keyphrase file.")
    parser.add_argument("filename", help="Encrypted file to decrypt")
    parser.add_argument("keyphrase_file", help="Keyphrase file used for symmetric decryption")
    parser.add_argument("-o", "--output", help="Optional output directory to save the decrypted file", default=None)
    args = parser.parse_args()
    
    decrypt_file(args.filename, args.keyphrase_file, args.output)

