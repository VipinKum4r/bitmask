import sys
import argparse
import getpass

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

RSA_PUBLIC_EXPONENT = 65537  # F4/Fermat number — standard RSA public exponent, prime and efficient for modular exponentiation
RSA_KEY_SIZE = 2048  # NIST-recommended RSA key size in bits — balances security and performance, secure beyond 2030

def generate_keypair(private_key_base, public_key_base):
    private_key_file = f"{private_key_base}.pem"
    public_key_file = f"{public_key_base}.pem"

    try:
        passphrase = getpass.getpass("Enter passphrase for private key: ")
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            print("Error: Passphrases do not match.", file=sys.stderr)
            sys.exit(1)
        if not passphrase:
            print("Error: Passphrase cannot be empty.", file=sys.stderr)
            sys.exit(1)

        # Generate a 2048-bit RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )

        # Serialize private key — TraditionalOpenSSL PEM + AES-256 encryption
        # (compatible with OpenSSL genrsa -aes256)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        )
        with open(private_key_file, "wb") as f:
            f.write(private_pem)
        print(f"Private key generated: {private_key_file}")

        # Serialize public key (compatible with OpenSSL rsa -pubout)
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_file, "wb") as f:
            f.write(public_pem)
        print(f"Public key generated: {public_key_file}")

    except Exception as ex:
        print(f"An unexpected error occurred: {ex}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a PKI keypair (no openssl required).")
    parser.add_argument(
        "-s",
        "--priv",
        type=str,
        default="secretkey",
        help="Base name for the private key file without extension.",
    )
    parser.add_argument(
        "-p",
        "--pub",
        type=str,
        default="publickey",
        help="Base name for the public key file without extension.",
    )
    args = parser.parse_args()

    generate_keypair(args.priv, args.pub)