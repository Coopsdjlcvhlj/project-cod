#!/usr/bin/env python3
import os
import sys
import argparse
import getpass
import base64
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import constant_time
import secrets

MAGIC = b'ENCv1'
SALT_SIZE = 16
ITERATIONS = 390000

def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)

def encrypt_file(path: Path, password: str, remove_original: bool = False) -> None:
    if not path.is_file():
        return
    out_path = path.with_name(path.name + '.enc')
    if out_path.exists():
        print(f"[skip] {out_path} already exists")
        return
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    data = path.read_bytes()
    token = fernet.encrypt(data)
    out_path.write_bytes(MAGIC + salt + token)
    if remove_original:
        path.unlink()
    print(f"[enc] {path} -> {out_path}")

def decrypt_file(path: Path, password: str, remove_encrypted: bool = False) -> None:
    if not path.is_file():
        return
    raw = path.read_bytes()
    if len(raw) < len(MAGIC) + SALT_SIZE:
        print(f"[skip] {path} (too small or invalid)")
        return
    if raw[:len(MAGIC)] != MAGIC:
        print(f"[skip] {path} (invalid header)")
        return
    salt = raw[len(MAGIC):len(MAGIC)+SALT_SIZE]
    token = raw[len(MAGIC)+SALT_SIZE:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    try:
        data = fernet.decrypt(token)
    except InvalidToken:
        print(f"[fail] {path} - invalid password or corrupted file")
        return
    if path.name.endswith('.enc'):
        orig_name = path.with_name(path.name[:-4])
    else:
        orig_name = path.with_name(path.name + '.dec')
    orig_name.write_bytes(data)
    if remove_encrypted:
        path.unlink()
    print(f"[dec] {path} -> {orig_name}")

def walk_and_process(root: Path, func, password: str, remove_flag: bool, encrypt_mode: bool):
    for dirpath, dirnames, filenames in os.walk(root):
        for fname in filenames:
            p = Path(dirpath) / fname
            if encrypt_mode:
                if p.name.endswith('.enc'):
                    continue
                func(p, password, remove_flag)
            else:
                if not p.name.endswith('.enc'):
                    continue
                func(p, password, remove_flag)

def ask_password(confirm: bool = False) -> str:
    pwd = getpass.getpass("Password: ")
    if confirm:
        pwd2 = getpass.getpass("Confirm password: ")
        if not constant_time.bytes_eq(pwd.encode(), pwd2.encode()):
            print("Passwords do not match.")
            sys.exit(1)
    if len(pwd) == 0:
        print("Empty password not allowed.")
        sys.exit(1)
    return pwd

def main():
    parser = argparse.ArgumentParser(description="Encrypt/decrypt all files in a folder using a password.")
    sub = parser.add_subparsers(dest='cmd', required=True)

    enc = sub.add_parser('encrypt', help='Encrypt files')
    enc.add_argument('--dir', required=True, help='Target directory')
    enc.add_argument('--remove-original', action='store_true', help='Remove original files after encryption')

    dec = sub.add_parser('decrypt', help='Decrypt files')
    dec.add_argument('--dir', required=True, help='Target directory')
    dec.add_argument('--remove-encrypted', action='store_true', help='Remove encrypted files after successful decryption')

    args = parser.parse_args()
    root = Path(args.dir)
    if not root.exists():
        print("Directory not found.")
        sys.exit(1)

    if args.cmd == 'encrypt':
        password = ask_password(confirm=True)
        walk_and_process(root, encrypt_file, password, args.remove_original, encrypt_mode=True)
    elif args.cmd == 'decrypt':
        password = ask_password(confirm=False)
        walk_and_process(root, decrypt_file, password, args.remove_encrypted, encrypt_mode=False)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
