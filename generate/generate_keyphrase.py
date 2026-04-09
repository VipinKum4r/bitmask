import os
import base64
import hashlib
import sys
import argparse
from datetime import datetime

def generate_keyphrase(name, email=None):
    try:
        # Create a unique identifier for the key file
        identifier = name + (email or "")
        unique_hash = hashlib.sha256(identifier.encode()).hexdigest()[:8]  # First 8 chars of hash
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")  # Unique timestamp
        key_filename = f"{name[:3]}{unique_hash}{timestamp}.bin".lower()

        # Create a fingerprint filename
        fingerprint_filename = f"{key_filename}.sha256"

        # Generate a random 32-byte keyphrase (base64-encoded) — no openssl needed
        random_bytes = os.urandom(32)
        keyphrase = base64.b64encode(random_bytes).decode("utf-8")

        # Write the keyphrase without trailing newline (matches openssl rand -base64 32 stripped)
        with open(key_filename, "w", newline="") as key_file:
            key_file.write(keyphrase)

        # Generate a SHA-256 fingerprint of the keyphrase and save it to the fingerprint file
        with open(key_filename, "rb") as key_file:
            key_data = key_file.read()
            sha256_fingerprint = hashlib.sha256(key_data).hexdigest()
            with open(fingerprint_filename, "w") as fingerprint_file:
                fingerprint_file.write(sha256_fingerprint)

        print(f"Keyphrase generated: {key_filename}")
        print(f"SHA-256 fingerprint saved: {fingerprint_filename}")

    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a keyphrase for symmetric encryption.")
    parser.add_argument("name", help="Recipient name (mandatory)")
    parser.add_argument("-e", "--email", help="Recipient email (optional)", default=None)
    args = parser.parse_args()
    
    generate_keyphrase(args.name, args.email)

