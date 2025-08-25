"""
Cryptographic operations for Event Horizon SDK
"""

import os
import base64
from typing import Dict, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from exceptions import CryptoError


class CryptoManager:
    """Manages cryptographic operations for the SDK"""
    
    def __init__(self, key_size: int = 2048):
        """
        Initialize crypto manager
        
        :param key_size: RSA key size (1024, 2048, or 4096)
        """
        if key_size not in [1024, 2048, 4096]:
            raise ValueError("Key size must be 1024, 2048, or 4096")
        
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """
        Generate new RSA key pair
        
        :return: Tuple of (private_key_pem, public_key_pem)
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            self.private_key = private_key
            self.public_key = public_key
            
            return private_pem, public_pem
            
        except Exception as e:
            raise CryptoError(f"Failed to generate key pair: {str(e)}")
    
    def load_private_key(self, private_key_pem: bytes) -> None:
        """
        Load private key from PEM format
        
        :param private_key_pem: Private key in PEM format
        """
        try:
            self.private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            raise CryptoError(f"Failed to load private key: {str(e)}")
    
    def load_public_key(self, public_key_pem: bytes) -> None:
        """
        Load public key from PEM format
        
        :param public_key_pem: Public key in PEM format
        """
        try:
            self.public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
        except Exception as e:
            raise CryptoError(f"Failed to load public key: {str(e)}")
    
    def encrypt_message(self, message: str, recipient_public_key_pem: bytes) -> Dict[str, str]:
        """
        Encrypt message using hybrid encryption (RSA + AES)
        
        :param message: Plaintext message to encrypt
        :param recipient_public_key_pem: Recipient's public key in PEM format
        :return: Dictionary with encrypted data
        """
        try:
            # Load recipient's public key
            recipient_public_key = serialization.load_pem_public_key(
                recipient_public_key_pem,
                backend=default_backend()
            )
            
            # Generate random session key and IV
            session_key = os.urandom(32)  # AES-256
            iv = os.urandom(16)           # AES block size
            
            # Encrypt message with AES
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(message.encode()) + padder.finalize()
            
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), 
                           backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Encrypt session key with RSA
            encrypted_key = recipient_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return {
                "encrypted_key": base64.b64encode(encrypted_key).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "iv": base64.b64encode(iv).decode()
            }
            
        except Exception as e:
            raise CryptoError(f"Encryption failed: {str(e)}")
    
    def decrypt_message(self, encrypted_key_b64: str, iv_b64: str, ciphertext_b64: str) -> str:
        """
        Decrypt message using private key
        
        :param encrypted_key_b64: Base64 encoded encrypted session key
        :param iv_b64: Base64 encoded initialization vector
        :param ciphertext_b64: Base64 encoded encrypted message
        :return: Decrypted plaintext message
        """
        if not self.private_key:
            raise CryptoError("Private key not loaded")
        
        try:
            # Decode base64 data
            encrypted_key = base64.b64decode(encrypted_key_b64)
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            
            # Decrypt session key with RSA
            session_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message with AES
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), 
                           backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode()
            
        except Exception as e:
            raise CryptoError(f"Decryption failed: {str(e)}")
    
    def sign_message(self, message: str) -> str:
        """
        Sign message with private key
        
        :param message: Message to sign
        :return: Base64 encoded signature
        """
        if not self.private_key:
            raise CryptoError("Private key not loaded")
        
        try:
            signature = self.private_key.sign(
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode()
            
        except Exception as e:
            raise CryptoError(f"Signing failed: {str(e)}")
    
    def verify_signature(self, message: str, signature_b64: str, public_key_pem: bytes) -> bool:
        """
        Verify message signature
        
        :param message: Original message
        :param signature_b64: Base64 encoded signature
        :param public_key_pem: Public key in PEM format
        :return: True if signature is valid
        """
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            signature = base64.b64decode(signature_b64)
            
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception:
            return False
    
    def get_public_key_pem(self) -> Optional[bytes]:
        """
        Get public key in PEM format
        
        :return: Public key in PEM format or None if not loaded
        """
        if self.public_key:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return None
    
    def get_private_key_pem(self) -> Optional[bytes]:
        """
        Get private key in PEM format
        
        :return: Private key in PEM format or None if not loaded
        """
        if self.private_key:
            return self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        return None
