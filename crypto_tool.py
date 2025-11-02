#!/usr/bin/env python3
# crypto_tool.py
#
# A compact, quick, agile CLI for encryption/decryption:
#   - AES-GCM, ChaCha20-Poly1305 (AEAD)
#   - Fernet (AES-CBC + HMAC, packaged)
#   - RSA-OAEP (SHA-256)
#   - Base64 (encode/decode utility)
#
# Uses scrypt for password KDF; JSON envelopes include salt/nonce where applicable.

import argparse
import base64
import json
import os
import sys
from getpass import getpass
from typing import Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# ------------- IO helpers ------------- #

def read_bytes(path: Optional[str]) -> bytes:
    if not path or path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as f:
        return f.read()


def write_bytes(path: Optional[str], data: bytes) -> None:
    if not path or path == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return
    with open(path, "wb") as f:
        f.write(data)


def to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def from_b64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# ------------- KDF / keys ------------- #

def kdf_scrypt(password: bytes, salt: bytes, length: int = 32) -> bytes:
    # Parameters: N=2**14, r=8, p=1 — good defaults for CLI use
    kdf = Scrypt(salt=salt, length=length, n=2 ** 14, r=8, p=1)
    return kdf.derive(password)


def password_bytes(pw_opt: Optional[str]) -> bytes:
    pw = pw_opt if pw_opt is not None else getpass("Password: ")
    return pw.encode("utf-8")


# ------------- Symmetric: AES-GCM / ChaCha20-Poly1305 ------------- #

def enc_aead(alg: str, plaintext: bytes, password: str, aad: Optional[str]) -> bytes:
    salt = os.urandom(16)
    key = kdf_scrypt(password_bytes(password), salt, 32)

    if alg == "aesgcm":
        aead = AESGCM(key)
    elif alg == "chacha20":
        aead = ChaCha20Poly1305(key)
    else:
        raise ValueError("Unsupported AEAD algorithm")

    nonce = os.urandom(12)  # 96-bit nonce recommended
    associated = aad.encode("utf-8") if aad else None
    ct = aead.encrypt(nonce, plaintext, associated)

    env = {
        "v": 1,
        "alg": alg,
        "salt": to_b64(salt),
        "nonce": to_b64(nonce),
        "aad": to_b64(associated) if associated else None,
        "ct": to_b64(ct),
    }
    return json.dumps(env, separators=(",", ":")).encode("utf-8")


def dec_aead(blob: bytes, password: str) -> bytes:
    env = json.loads(blob.decode("utf-8"))
    alg = env["alg"]
    salt = from_b64(env["salt"])
    nonce = from_b64(env["nonce"])
    ct = from_b64(env["ct"])
    associated = from_b64(env["aad"]) if env.get("aad") else None

    key = kdf_scrypt(password_bytes(password), salt, 32)

    if alg == "aesgcm":
        aead = AESGCM(key)
    elif alg == "chacha20":
        aead = ChaCha20Poly1305(key)
    else:
        raise ValueError("Unsupported AEAD algorithm")

    return aead.decrypt(nonce, ct, associated)


# ------------- Symmetric: Fernet ------------- #

def fernet_key_from_password(password: str, salt: bytes) -> bytes:
    raw = kdf_scrypt(password_bytes(password), salt, 32)
    return base64.urlsafe_b64encode(raw)  # Fernet expects urlsafe base64 key


def enc_fernet(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = fernet_key_from_password(password, salt)
    token = Fernet(key).encrypt(plaintext)
    env = {"v": 1, "alg": "fernet", "salt": to_b64(salt), "token": token.decode("ascii")}
    return json.dumps(env, separators=(",", ":")).encode("utf-8")


def dec_fernet(blob: bytes, password: str) -> bytes:
    env = json.loads(blob.decode("utf-8"))
    salt = from_b64(env["salt"])
    token = env["token"].encode("ascii")
    key = fernet_key_from_password(password, salt)
    return Fernet(key).decrypt(token)


# ------------- Asymmetric: RSA-OAEP (SHA-256) ------------- #

def rsa_encrypt(plaintext: bytes, pub_pem_path: str) -> bytes:
    with open(pub_pem_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    ct = pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    # return as base64 text to make piping easy
    return base64.b64encode(ct)


def rsa_decrypt(cipher_b64: bytes, priv_pem_path: str, passphrase: Optional[str]) -> bytes:
    with open(priv_pem_path, "rb") as f:
        priv = serialization.load_pem_private_key(
            f.read(),
            password=(passphrase.encode("utf-8") if passphrase else None),
        )
    ct = base64.b64decode(cipher_b64)
    return priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_generate(priv_out: str, pub_out: str, bits: int = 4096, passphrase: Optional[str] = None) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    enc = serialization.BestAvailableEncryption(passphrase.encode("utf-8")) if passphrase else serialization.NoEncryption()

    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc,
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(priv_out, "wb") as f:
        f.write(priv_pem)
    with open(pub_out, "wb") as f:
        f.write(pub_pem)


# ------------- Base64 utility ------------- #

def b64_encode(data: bytes) -> bytes:
    return base64.b64encode(data)


def b64_decode(data: bytes) -> bytes:
    return base64.b64decode(data)


# ------------- CLI ------------- #

def add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-i", "--in", dest="inp", default="-", help="Input file (default: stdin)")
    p.add_argument("-o", "--out", dest="out", default="-", help="Output file (default: stdout)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Encrypt/decrypt data using AES-GCM, ChaCha20, Fernet, RSA-OAEP, or Base64."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Encrypt
    enc = sub.add_parser("encrypt", help="Encrypt data")
    add_common_args(enc)
    enc.add_argument("-a", "--alg", choices=["aesgcm", "chacha20", "fernet", "rsa", "base64"], required=True)
    enc.add_argument("--password", help="Password (if omitted, prompted)")
    enc.add_argument("--aad", help="AEAD associated data (optional; aesgcm/chacha20)")
    enc.add_argument("--rsa-pub", help="RSA public key PEM for alg=rsa")

    # Decrypt
    dec = sub.add_parser("decrypt", help="Decrypt data")
    add_common_args(dec)
    dec.add_argument("-a", "--alg", choices=["aesgcm", "chacha20", "fernet", "rsa", "base64"], required=True)
    dec.add_argument("--password", help="Password (if omitted, prompted)")
    dec.add_argument("--rsa-priv", help="RSA private key PEM for alg=rsa")
    dec.add_argument("--rsa-pass", help="RSA private key passphrase (optional)")

    # RSA keygen
    gen = sub.add_parser("gen-rsa", help="Generate RSA keypair")
    gen.add_argument("--bits", type=int, default=4096, help="Key size (default 4096)")
    gen.add_argument("--priv-out", default="rsa_private.pem", help="Private key path")
    gen.add_argument("--pub-out", default="rsa_public.pem", help="Public key path")
    gen.add_argument("--passphrase", help="Encrypt private key with this passphrase")

    args = parser.parse_args()

    if args.cmd == "gen-rsa":
        rsa_generate(args.priv_out, args.pub_out, bits=args.bits, passphrase=args.passphrase)
        print(f"Generated RSA keys → {args.priv_out}, {args.pub_out}")
        return

    data = read_bytes(args.inp)

    if args.cmd == "encrypt":
        if args.alg in ("aesgcm", "chacha20"):
            if args.password is None:
                # will prompt
                pass
            out = enc_aead(args.alg, data, args.password or "", args.aad)
            write_bytes(args.out, out)
        elif args.alg == "fernet":
            out = enc_fernet(data, args.password or "")
            write_bytes(args.out, out)
        elif args.alg == "rsa":
            if not args.rsa_pub:
                parser.error("--rsa-pub is required for alg=rsa")
            out = rsa_encrypt(data, args.rsa_pub)
            write_bytes(args.out, out)
        elif args.alg == "base64":
            write_bytes(args.out, b64_encode(data))
        else:
            parser.error("Unsupported algorithm")

    elif args.cmd == "decrypt":
        if args.alg in ("aesgcm", "chacha20"):
            out = dec_aead(data, args.password or "")
            write_bytes(args.out, out)
        elif args.alg == "fernet":
            out = dec_fernet(data, args.password or "")
            write_bytes(args.out, out)
        elif args.alg == "rsa":
            if not args.rsa_priv:
                parser.error("--rsa-priv is required for alg=rsa")
            out = rsa_decrypt(data, args.rsa_priv, args.rsa_pass)
            write_bytes(args.out, out)
        elif args.alg == "base64":
            write_bytes(args.out, b64_decode(data))
        else:
            parser.error("Unsupported algorithm")


if __name__ == "__main__":
    main()
