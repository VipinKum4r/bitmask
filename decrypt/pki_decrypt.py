import os
import sys
import argparse
import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def pki_decrypt(encrypted_file, privkey, output_path=None):
    try:
        # Ensure the encrypted file and private key exist
        if not os.path.isfile(encrypted_file):
            print(f"Error: File '{encrypted_file}' does not exist.", file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(privkey):
            print(f"Error: Private key '{privkey}' does not exist.", file=sys.stderr)
            sys.exit(1)

        # Remove .apg extension if it exists, otherwise maintain the original filename
        if encrypted_file.endswith(".apg"):
            output_file = encrypted_file[:-4]
        else:
            output_file = encrypted_file

        output_file = os.path.join(
            output_path if output_path else os.getcwd(), os.path.basename(output_file))

        # Prompt for private key passphrase (mirrors openssl interactive behaviour)
        passphrase = getpass.getpass(f"Enter passphrase for private key '{privkey}': ")

        # Load the encrypted private key
        with open(privkey, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=passphrase.encode(),
                backend=default_backend()
            )

        with open(encrypted_file, "rb") as f:
            ciphertext = f.read()

        # RSA PKCS#1 v1.5 decryption — matches openssl pkeyutl -decrypt default
        plaintext = private_key.decrypt(ciphertext, padding.PKCS1v15())

        with open(output_file, "wb") as f:
            f.write(plaintext)

        print(f"File decrypted successfully: {output_file}")

    except ValueError as e:
        print(f"Error: Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt an encrypted file using a private key.")
    parser.add_argument("filename", help="Encrypted file to decrypt")
    parser.add_argument("private_key", help="Private key file used for asymmetric decryption")
    parser.add_argument("-o", "--output", help="Optional output directory to save the decrypted file", default=None)
    args = parser.parse_args()

    pki_decrypt(args.filename, args.private_key, args.output)