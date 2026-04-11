# bitmask
This repository provides a set of scripts for securely storing, exchanging files and messages using Public Key Infrastructure (PKI) and symmetric encryption. For small files and text messages we can use asymmetric encryption directly but larger files like binaries, images and videos demand a different solution for which we use hybrid encryption scheme.  

For asymmetric encryption, I use a 2048-bit RSA keypair with the private key further encrypted by AES-256 cipher. This adds an additional layer of security so that private key files cannot be read in plain text on the filesystem and mitigates risk of data breach in case of key leaks. The private key can be used for decryption with a passphrase.

> [!CAUTION]
> Keep your private key and keyphrase safe and don't share it with anyone.

> [!WARNING]
> Don't set a predictable or short passphrase. Your encrypted data may be compromised in event of a key leak.

Symmetric encryption uses random base64 encoded keyphrase. Note that this is not the actual key used for symmetric encryption but a password or passphrase which is used by PBKDF2 KDF (Key Derivation Function) to derive a symmetric key. Further, the encryption is carried out using the AES-256 algorithm and salt to eliminate determinism in the encrypted output. Salt ensures randomness but it is stored in the encrypted file.
---

## Cross-platform support

All scripts now work **out of the box on Linux, macOS, and Windows** — no `openssl` binary required.

The only dependency is the [`cryptography`](https://cryptography.io) Python package:

```bash
pip install -r requirements.txt
```

> [!NOTE]
> Files encrypted with the old openssl-based scripts are **fully compatible** with the new scripts, and vice versa. The on-disk format is identical to OpenSSL's `enc -aes-256-cbc -pbkdf2` output.

---

## How it works
### You send me a file
- Generate a PKI keypair **generate/generate_pki_keypair.py** if you don't already have one
- Share the public key with it's sha256 fingerprint over [email](amoldhamale1105@gmail.com)
- Decrypt the received file `*.apg` from me with your private key using **decrypt/pki_decrypt.py**
- Encrypt the file you want to send me with the decrypted `*.bin` keyphrase file using **encrypt/encrypt_file.py**
- Send me the encrypted file `*.enc` with sha256 digest on any medium

### I send you a file
- Generate a unique keyphrase for me with **generate/generate_keyphrase.py**
- Encrypt the `*.bin` keyphrase file with my public key **keys/entropy.pem** using **encrypt/pki_encrypt.py**
- Share the encrypted keyphrase file with it's sha256 fingerprint over [email](amoldhamale1105@gmail.com)
- Decrypt the received file `*.enc` from me with your keyphrase file using **decrypt/decrypt_file.py**

You can use these scripts for secure storage by encrypting the files on your computer or hard drive. For encrcypting files you can generate a keyphrase for yourself and symmetrically encrypt the files with it. Once done, you can encrypt the keyphrase file with your public key. For decryption of your encrypted files, you will first need to decrypt the keyphrase file with your private key and associated passphrase. Use the decrypted keyphrase to symmetrically decrypt the encrypted files.  

It's a good practice to destroy the raw keyphrase file once it's usage is over and it is safely encrypted since it poses a significantly higher risk of your files being exposed being the only key required to both encrypt and decrypt your data.  

## Contribution
With the migration to the `cryptography` Python library, these scripts work out of box on Linux, macOS, BSD and Windows without requiring openssl to be installed. Install the single dependency with `pip install -r requirements.txt`.

Feel free to test on other platforms and create issues/pull requests accordingly.
