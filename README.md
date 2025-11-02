# 🔐 Crypto Tool — Compact

<div align="center">

A **compact** CLI for **encryption & decryption** with modern, secure defaults.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python\&logoColor=white)](#-requirements)
[![cryptography](https://img.shields.io/badge/lib-cryptography-003B57.svg)](https://cryptography.io)
[![Algorithms](https://img.shields.io/badge/AES--GCM%20|%20ChaCha20--Poly1305%20|%20Fernet%20|%20RSA--OAEP%20|%20Base64-6f42c1)](#-algorithms)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#-license)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#-contributing)

</div>

> Password KDF: **scrypt** (N=2¹⁴, r=8, p=1) • AEAD JSON envelopes include **salt**/**nonce** (and **AAD** when used).
> This tool reads from **stdin** or files and writes to **stdout** or files—perfect for pipes & CI.

---

## ✨ Features

* **Modern algorithms**: AES-GCM, ChaCha20-Poly1305, Fernet, RSA-OAEP (SHA-256), plus Base64 utility.
* **Flexible I/O**: `-i`/`-o` for files, or stream via stdin/stdout (`-`).
* **Secure defaults**: unique salt/nonce per operation, authenticated encryption for AEAD, scrypt KDF.
* **Subcommands**: `encrypt`, `decrypt`, `gen-rsa`.
* **Flags** to customize: algorithm, password, AAD, timeouts not needed, etc.
* **Works cross-platform** (Linux/macOS/Windows/WSL/PowerShell).

---

## 📚 Table of Contents

* [Requirements](#-requirements)
* [Installation](#-installation)
* [Algorithms](#-algorithms)
* [Quickstart](#-quickstart)
* [Usage & Flags](#-usage--flags)
* [Examples](#-examples)
* [Envelope Formats (what gets written)](#-envelope-formats-what-gets-written)
* [Security Notes](#-security-notes)
* [Contributing](#-contributing)
* [License](#-license)

---

## 🔧 Requirements

* **Python**: 3.10+
* **Package**: `cryptography`

```bash
pip install -U cryptography
```

---

## 📦 Installation

Place the script at your project root as **`crypto_tool.py`** (or anywhere on your PATH).

Optional virtualenv:

```bash
python -m venv venv
source venv/bin/activate         # PowerShell: .\venv\Scripts\Activate.ps1
pip install -U cryptography
```

---

## 🔒 Algorithms

* **AES-GCM** (AEAD, 96-bit nonce) — fast, widely supported.
* **ChaCha20-Poly1305** (AEAD) — great on low-power/handheld devices.
* **Fernet** (AES-128-CBC + HMAC) — batteries-included token, URL-safe.
* **RSA-OAEP (SHA-256)** — asymmetric; use for small payloads or hybrid.
* **Base64** — encoding/decoding utility (not encryption).

Passwords are converted to keys via **scrypt**, with fresh **16-byte salt** per operation.

---

## 🚀 Quickstart

**Encrypt with AES-GCM** (password prompted, stdin→stdout):

```bash
cat secret.txt | python crypto_tool.py encrypt -a aesgcm > secret.aesgcm
```

**Decrypt**:

```bash
cat secret.aesgcm | python crypto_tool.py decrypt -a aesgcm > secret.txt
```

> [!TIP]
> Replace `aesgcm` with `chacha20`, `fernet`, `rsa`, or `base64` as needed.

---

## 🛠 Usage & Flags

```text
python crypto_tool.py <command> [options]

Commands:
  encrypt      Encrypt data
  decrypt      Decrypt data
  gen-rsa      Generate RSA keypair

Common I/O:
  -i, --in     Input file path (default: "-" = stdin)
  -o, --out    Output file path (default: "-" = stdout)

encrypt/decrypt:
  -a, --alg            aesgcm | chacha20 | fernet | rsa | base64
  --password           Password (omit to be prompted; not used for RSA/base64)
  --aad                Associated data for AEAD (aesgcm/chacha20)

RSA options:
  encrypt  --rsa-pub   RSA public key (PEM) for alg=rsa
  decrypt  --rsa-priv  RSA private key (PEM) for alg=rsa
           --rsa-pass  Private key passphrase (optional)

gen-rsa:
  --bits               Key size (default 4096)
  --priv-out           Private key path (default rsa_private.pem)
  --pub-out            Public key path  (default rsa_public.pem)
  --passphrase         Protect private key with this passphrase
```

---

## 🧪 Examples

### AES-GCM / ChaCha20-Poly1305 with AAD

```bash
python crypto_tool.py encrypt -a aesgcm -i report.pdf -o report.pdf.aead --aad "report:2025"
python crypto_tool.py decrypt -a aesgcm -i report.pdf.aead -o report.pdf
```

```bash
python crypto_tool.py encrypt -a chacha20 -i img.png -o img.png.c20 --password "S3cr3t!"
python crypto_tool.py decrypt -a chacha20 -i img.png.c20 -o img.png --password "S3cr3t!"
```

### Fernet (token format)

```bash
python crypto_tool.py encrypt -a fernet -i notes.txt -o notes.token --password "my pass"
python crypto_tool.py decrypt -a fernet -i notes.token -o notes.txt --password "my pass"
```

### RSA-OAEP (SHA-256)

```bash
# Generate keys (with passphrase)
python crypto_tool.py gen-rsa --bits 4096 --passphrase "k3y!" \
  --priv-out rsa_private.pem --pub-out rsa_public.pem

# Encrypt with public key (produces base64)
python crypto_tool.py encrypt -a rsa -i doc.pdf -o doc.pdf.rsa --rsa-pub rsa_public.pem

# Decrypt with private key
python crypto_tool.py decrypt -a rsa -i doc.pdf.rsa -o doc.pdf --rsa-priv rsa_private.pem --rsa-pass "k3y!"
```

### Base64 utility

```bash
python crypto_tool.py encrypt -a base64 -i logo.jpg -o logo.jpg.b64
python crypto_tool.py decrypt -a base64 -i logo.jpg.b64 -o logo.jpg
```

---

## 📦 Envelope Formats (what gets written)

**AEAD (AES-GCM / ChaCha20-Poly1305)** → JSON (UTF-8 bytes)

```json
{
  "v": 1,
  "alg": "aesgcm",
  "salt": "<base64>",
  "nonce": "<base64>",
  "aad": "<base64 or null>",
  "ct": "<base64>"
}
```

**Fernet** → JSON (token is URL-safe base64)

```json
{
  "v": 1,
  "alg": "fernet",
  "salt": "<base64>",
  "token": "<string>"
}
```

**RSA** → raw **base64** of the ciphertext (no JSON).

> [!NOTE]
> The tool auto-derives keys via scrypt using the stored salt. Keep the entire output blob intact to decrypt later.

---

## 🔐 Security Notes

* **Base64 isn’t encryption**—use AES-GCM/ChaCha20/Fernet/RSA for confidentiality.
* **AEAD** provides integrity; if decryption fails, data or key is wrong (or tampered).
* **Unique nonce/salt per encryption** is critical; this tool generates fresh values.
* **RSA** is best for small payloads or hybrid schemes. For large files, encrypt with symmetric AEAD, then encrypt the symmetric key with RSA.
* Store keys and passphrases securely (e.g., password manager, OS keychain, secret manager).

> [!WARNING]
> Losing your password or RSA private key means **permanent data loss**. There’s no backdoor.

---

## 🤝 Contributing

Ideas welcome: XChaCha20-Poly1305, AES-GCM-SIV, JSON Web Encryption (JWE) mode, streaming/chunked AEAD, and deterministic test vectors. Keep PRs small and add tests for new flags/formats.

---

## 📄 License

Released under the **MIT License**. See `LICENSE` for details.
