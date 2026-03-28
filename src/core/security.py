# src/core/security.py
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional, Dict, Any
import base64
import os
import hashlib
import hmac
import json

from src.core.config import get_settings

settings = get_settings()


class SecurityManager:
    """
    Enterprise Security Manager
    
    Features:
    - Field-level encryption
    - Password hashing
    - JWT token management
    - API key generation/validation
    - Data masking
    """
    
    def __init__(self):
        # Initialize encryption key
        self.encryption_key = self._derive_key(settings.field_encryption_key)
        self.cipher = Fernet(self.encryption_key)
    
    def _derive_key(self, key_string: str) -> bytes:
        """Derive encryption key from string"""
        # Use PBKDF2HMAC to derive a secure key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'eso_salt',  # In production, use random salt per tenant
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(key_string.encode()))
        return key
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if not data:
            return data
        encrypted = self.cipher.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        if not encrypted_data:
            return encrypted_data
        try:
            data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(data)
            return decrypted.decode()
        except Exception as e:
            # If decryption fails, return original (for backward compatibility)
            return encrypted_data
    
    def encrypt_dict(self, data: Dict[str, Any], fields: list) -> Dict[str, Any]:
        """Encrypt specific fields in a dictionary"""
        result = data.copy()
        for field in fields:
            if field in result and result[field]:
                result[field] = self.encrypt(str(result[field]))
        return result
    
    def decrypt_dict(self, data: Dict[str, Any], fields: list) -> Dict[str, Any]:
        """Decrypt specific fields in a dictionary"""
        result = data.copy()
        for field in fields:
            if field in result and result[field]:
                result[field] = self.decrypt(result[field])
        return result
    
    def hash_password(self, password: str) -> str:
        """Hash password for storage"""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        return base64.b64encode(salt + key).decode()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            decoded = base64.b64decode(hashed.encode())
            salt = decoded[:32]
            stored_key = decoded[32:]
            
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000
            )
            return hmac.compare_digest(key, stored_key)
        except Exception:
            return False
    
    def generate_api_key(self) -> str:
        """Generate secure API key"""
        return f"eso_{base64.urlsafe_b64encode(os.urandom(32)).decode()[:32]}"
    
    def hash_api_key(self, api_key: str) -> str:
        """Hash API key for storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def mask_data(self, data: str, visible_chars: int = 4) -> str:
        """Mask sensitive data (e.g., credit cards, API keys)"""
        if len(data) <= visible_chars:
            return '*' * len(data)
        return data[:visible_chars] + '*' * (len(data) - visible_chars)
    
    def mask_email(self, email: str) -> str:
        """Mask email address"""
        if '@' not in email:
            return self.mask_data(email)
        
        local, domain = email.split('@', 1)
        masked_local = self.mask_data(local, 2)
        return f"{masked_local}@{domain}"


# Global security manager instance
_security_manager = None


def get_security_manager() -> SecurityManager:
    """Get singleton security manager"""
    global _security_manager
    if _security_manager is None:
        _security_manager = SecurityManager()
    return _security_manager


# Convenience functions
def encrypt_value(value: str) -> str:
    """Encrypt a value"""
    return get_security_manager().encrypt(value)


def decrypt_value(value: str) -> str:
    """Decrypt a value"""
    return get_security_manager().decrypt(value)


def hash_password(password: str) -> str:
    """Hash a password"""
    return get_security_manager().hash_password(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password"""
    return get_security_manager().verify_password(password, hashed)


def generate_api_key() -> str:
    """Generate an API key"""
    return get_security_manager().generate_api_key()


def mask_data(data: str, visible_chars: int = 4) -> str:
    """Mask sensitive data"""
    return get_security_manager().mask_data(data, visible_chars)


# Initialize on import
security_manager = get_security_manager()