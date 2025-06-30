import os
import hashlib
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptexGCMException(Exception):
    """Exception for CryptexGCM-related errors."""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

    def __str__(self):
        return f"CryptexGCMException: {self.message}"

    def __repr__(self):
        return self.__str__()

class CryptexGCM:
    """
    CryptexGCM - Secure file encryption/decryption using AES-GCM.
    Now with custom exception handling for clear error reporting.
    """

    def __init__(self, password: str):
        self.key = self._derive_key(password)
        self.aesgcm = AESGCM(self.key)

    def _derive_key(self, password: str) -> bytes:
        """Derives a 256-bit AES key using SHA-256 from the given password."""
        return hashlib.sha256(password.encode()).digest()

    def encrypt(self, input_path: str, output_path: str) -> None:
        """Encrypts a file using AES-GCM and saves it with nonce + ciphertext."""
        try:
            nonce = os.urandom(12)

            with open(input_path, 'rb') as file:
                plaintext = file.read()

            ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)

            with open(output_path, 'wb') as file:
                file.write(nonce + ciphertext)

        except Exception as e:
            raise CryptexGCMException(f"Encryption failed: {str(e)}")

    def decrypt(self, input_path: str, output_path: str) -> None:
        """Decrypts a file encrypted with AES-GCM."""
        try:
            with open(input_path, 'rb') as file:
                nonce = file.read(12)
                ciphertext = file.read()

            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)

            with open(output_path, 'wb') as file:
                file.write(plaintext)
        except Exception as e:
            if isinstance(e, InvalidTag):
                raise CryptexGCMException("Invalid password or corrupted file.")
            else:
                raise CryptexGCMException(f"{type(e).__name__}: {str(e)}")
