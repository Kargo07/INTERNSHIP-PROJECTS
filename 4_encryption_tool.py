"""
============================================================
CODTECH INTERNSHIP - TASK 4
ADVANCED ENCRYPTION TOOL
============================================================
Description : Encrypt and decrypt files using AES-256
              (CBC mode) with a user-friendly CLI interface.
Author      : Intern
Libraries   : cryptography (pip install cryptography)
Algorithm   : AES-256-CBC with PBKDF2-HMAC-SHA256 key
              derivation from a user password.
============================================================
"""

import os
import struct
import hashlib
import getpass
from pathlib import Path

# ─────────────────────────────────────────────
# Install dependency check
# ─────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, hashes, hmac as crypto_hmac
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[ERROR] cryptography library not installed.")
    print("        Run: pip install cryptography")
    exit(1)


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
SALT_SIZE     = 16          # 16 bytes random salt
IV_SIZE       = 16          # AES block size = 16 bytes
KEY_SIZE      = 32          # AES-256 = 32 bytes key
ITERATIONS    = 200_000     # PBKDF2 iteration count (NIST recommended)
MAGIC         = b"CTENC01"  # File magic header to identify our format
BUFFER_SIZE   = 64 * 1024   # 64 KB read chunks


# ─────────────────────────────────────────────
# 1. Derive AES-256 key from password + salt
# ─────────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256.
    This makes brute-force attacks computationally expensive.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


# ─────────────────────────────────────────────
# 2. Encrypt a file
# ─────────────────────────────────────────────
def encrypt_file(input_path: str, output_path: str, password: str) -> bool:
    """
    Encrypt a file using AES-256-CBC.

    Encrypted file format:
    ┌──────────────────────────────────────────────────────┐
    │ Magic Header (7 bytes)                               │
    │ Salt (16 bytes)  — random, for key derivation        │
    │ IV   (16 bytes)  — random, AES initialization vector │
    │ Ciphertext (padded to AES block boundary)            │
    └──────────────────────────────────────────────────────┘
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        print(f"[ERROR] Input file not found: {input_path}")
        return False

    # Generate random salt and IV
    salt = os.urandom(SALT_SIZE)
    iv   = os.urandom(IV_SIZE)

    # Derive encryption key from password
    print("[*] Deriving key from password (this may take a moment)...")
    key = derive_key(password, salt)

    # Set up AES-256-CBC cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # PKCS7 padding (pads data to block-size multiple)
    padder = padding.PKCS7(128).padder()

    file_size = input_path.stat().st_size
    processed = 0

    try:
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            # Write header
            fout.write(MAGIC)   # 7 bytes magic
            fout.write(salt)    # 16 bytes salt
            fout.write(iv)      # 16 bytes IV

            # Encrypt file in chunks
            while True:
                chunk = fin.read(BUFFER_SIZE)
                if not chunk:
                    break

                # Apply padding to last chunk; encrypt
                padded = padder.update(chunk)
                fout.write(encryptor.update(padded))
                processed += len(chunk)
                percent = int(processed / file_size * 100) if file_size else 100
                print(f"  Progress: {percent}%", end="\r")

            # Finalize padding and encryption
            fout.write(encryptor.update(padder.finalize()))
            fout.write(encryptor.finalize())

        print(f"\n[✔] File encrypted successfully!")
        print(f"    Input  : {input_path}  ({file_size:,} bytes)")
        print(f"    Output : {output_path}  ({output_path.stat().st_size:,} bytes)")
        return True

    except Exception as e:
        print(f"\n[ERROR] Encryption failed: {e}")
        # Remove partial output file on error
        if output_path.exists():
            output_path.unlink()
        return False


# ─────────────────────────────────────────────
# 3. Decrypt a file
# ─────────────────────────────────────────────
def decrypt_file(input_path: str, output_path: str, password: str) -> bool:
    """
    Decrypt a file that was encrypted with encrypt_file().
    Reads salt and IV from the file header, re-derives the key,
    and decrypts the ciphertext.
    """
    input_path  = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        print(f"[ERROR] Input file not found: {input_path}")
        return False

    try:
        with open(input_path, "rb") as fin:
            # Read and verify magic header
            magic = fin.read(len(MAGIC))
            if magic != MAGIC:
                print("[ERROR] Not a valid encrypted file or wrong format.")
                return False

            # Read salt and IV from header
            salt = fin.read(SALT_SIZE)
            iv   = fin.read(IV_SIZE)

            # Derive key from password using stored salt
            print("[*] Deriving key from password...")
            key = derive_key(password, salt)

            # Set up AES-256-CBC decryptor
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            unpadder  = padding.PKCS7(128).unpadder()

            with open(output_path, "wb") as fout:
                while True:
                    chunk = fin.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    decrypted = decryptor.update(chunk)
                    fout.write(unpadder.update(decrypted))

                # Finalize decryption and remove padding
                remaining = decryptor.finalize()
                fout.write(unpadder.update(remaining))
                fout.write(unpadder.finalize())

        print(f"\n[✔] File decrypted successfully!")
        print(f"    Input  : {input_path}")
        print(f"    Output : {output_path}  ({output_path.stat().st_size:,} bytes)")
        return True

    except ValueError as e:
        print(f"\n[ERROR] Decryption failed — wrong password or corrupted file.")
        print(f"        Detail: {e}")
        if output_path.exists():
            output_path.unlink()
        return False
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        if output_path.exists():
            output_path.unlink()
        return False


# ─────────────────────────────────────────────
# 4. Compute file hash (for integrity check)
# ─────────────────────────────────────────────
def compute_sha256(filepath: str) -> str:
    """Compute SHA-256 checksum of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(BUFFER_SIZE):
            h.update(chunk)
    return h.hexdigest()


# ─────────────────────────────────────────────
# 5. Encrypt a text string (quick use)
# ─────────────────────────────────────────────
def encrypt_text(plaintext: str, password: str) -> bytes:
    """
    Encrypt a short text string. Returns raw bytes.
    Format: MAGIC + SALT + IV + CIPHERTEXT
    """
    salt = os.urandom(SALT_SIZE)
    iv   = os.urandom(IV_SIZE)
    key  = derive_key(password, salt)

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder    = padding.PKCS7(128).padder()

    data = plaintext.encode("utf-8")
    padded_data = padder.update(data) + padder.finalize()
    ciphertext  = encryptor.update(padded_data) + encryptor.finalize()

    return MAGIC + salt + iv + ciphertext


# ─────────────────────────────────────────────
# 6. Decrypt a text string
# ─────────────────────────────────────────────
def decrypt_text(encrypted_bytes: bytes, password: str) -> str:
    """Decrypt bytes produced by encrypt_text()."""
    if not encrypted_bytes.startswith(MAGIC):
        raise ValueError("Invalid data format.")

    offset = len(MAGIC)
    salt = encrypted_bytes[offset:offset + SALT_SIZE]
    iv   = encrypted_bytes[offset + SALT_SIZE:offset + SALT_SIZE + IV_SIZE]
    ciphertext = encrypted_bytes[offset + SALT_SIZE + IV_SIZE:]

    key = derive_key(password, salt)

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder  = padding.PKCS7(128).unpadder()

    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()
    plain = unpadder.update(padded_plain) + unpadder.finalize()
    return plain.decode("utf-8")


# ─────────────────────────────────────────────
# 7. Main Interactive CLI
# ─────────────────────────────────────────────
def main():
    print("=" * 60)
    print("   CODTECH INTERNSHIP - ADVANCED ENCRYPTION TOOL")
    print("   Algorithm : AES-256-CBC + PBKDF2-SHA256")
    print("=" * 60)

    while True:
        print("\nOptions:")
        print("  1. Encrypt a File")
        print("  2. Decrypt a File")
        print("  3. Encrypt a Text Message")
        print("  4. Decrypt a Text Message")
        print("  5. Compute File SHA-256 Hash")
        print("  6. Exit")

        choice = input("\nEnter choice [1-6]: ").strip()

        # ── Encrypt File ──
        if choice == "1":
            src = input("  Source file path: ").strip()
            default_out = src + ".enc"
            dst = input(f"  Output file path (default: {default_out}): ").strip()
            dst = dst if dst else default_out

            pwd = getpass.getpass("  Enter password: ")
            pwd2 = getpass.getpass("  Confirm password: ")
            if pwd != pwd2:
                print("  [ERROR] Passwords do not match!")
                continue

            encrypt_file(src, dst, pwd)

        # ── Decrypt File ──
        elif choice == "2":
            src = input("  Encrypted file path: ").strip()
            default_out = src.replace(".enc", ".decrypted") if src.endswith(".enc") else src + ".dec"
            dst = input(f"  Output file path (default: {default_out}): ").strip()
            dst = dst if dst else default_out

            pwd = getpass.getpass("  Enter password: ")
            decrypt_file(src, dst, pwd)

        # ── Encrypt Text ──
        elif choice == "3":
            text = input("  Enter text to encrypt: ").strip()
            pwd  = getpass.getpass("  Enter password: ")
            encrypted = encrypt_text(text, pwd)
            hex_output = encrypted.hex()
            print(f"\n  [✔] Encrypted (hex):\n  {hex_output}")
            save = input("\n  Save to file? (y/n): ").strip().lower()
            if save == "y":
                fpath = input("  File path: ").strip()
                with open(fpath, "w") as f:
                    f.write(hex_output)
                print(f"  Saved to {fpath}")

        # ── Decrypt Text ──
        elif choice == "4":
            hex_input = input("  Enter encrypted hex string (or file path): ").strip()
            # Check if it's a file path
            if Path(hex_input).is_file():
                with open(hex_input, "r") as f:
                    hex_input = f.read().strip()

            try:
                encrypted_bytes = bytes.fromhex(hex_input)
            except ValueError:
                print("  [ERROR] Invalid hex string.")
                continue

            pwd = getpass.getpass("  Enter password: ")
            try:
                plaintext = decrypt_text(encrypted_bytes, pwd)
                print(f"\n  [✔] Decrypted text:\n  {plaintext}")
            except Exception as e:
                print(f"  [ERROR] Decryption failed: {e}")

        # ── SHA-256 Hash ──
        elif choice == "5":
            fpath = input("  File path: ").strip()
            if not Path(fpath).is_file():
                print("  [ERROR] File not found.")
                continue
            sha = compute_sha256(fpath)
            print(f"\n  SHA-256: {sha}")

        elif choice == "6":
            print("\n[BYE] Encrypt everything. Stay secure!")
            break

        else:
            print("[ERROR] Invalid choice. Enter 1-6.")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    main()
