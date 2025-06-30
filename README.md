# 🔐 CryptexGCM

CryptexGCM is a Python-based AES-GCM file encryption tool that provides secure, fast, and authenticated encryption for files. It's designed with simplicity and reliability in mind — ideal for personal or professional data protection.

---

## ✨ Features

- ✅ **AES-GCM encryption** with 256-bit keys
- ✅ **One-line usage** for encrypt/decrypt
- ✅ **Custom exception handling** (`CryptexGCMException`)
- ✅ **File-safe output (nonce + ciphertext)**
- ✅ **Lightweight, no external dependencies except `cryptography`**

---

## 🚀 Getting Started

### 1. Installation

Install the required dependency:

```bash
pip install cryptography
```

### 2. Usage

```python
from CryptexGCM import CryptexGCM, CryptexGCMException

cryptex = CryptexGCM("my_secure_password")

# Encrypt a file
try:
    cryptex.encrypt("secret.txt", "secret.cry")
    print("[✓] Encryption successful.")
except CryptexGCMException as e:
    print("[✗] Error during encryption:", e)

# Decrypt a file
try:
    cryptex.decrypt("secret.cry", "recovered.txt")
    print("[✓] Decryption successful.")
except CryptexGCMException as e:
    print("[✗] Error during decryption:", e)

```

## ❗Notes

> CryptexGCM is not intended to replace enterprise-grade encryption, but is excellent for learning, personal data protection, and quick offline file encryption.
Make sure to remember your password — AES-GCM encryption is secure by design and cannot be reversed without the exact key.
