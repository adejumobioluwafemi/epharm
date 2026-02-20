import base64
from datetime import datetime, timedelta
import hashlib
import secrets
from typing import Dict, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext

from src.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    """Hash password using bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash"""
    return pwd_context.verify(plain_password, hashed_password)

def md5_hash(text: str) -> str:
    """MD5 hash (legacy - for C# compatibility during migration)"""
    return hashlib.md5(text.encode()).hexdigest()

def encrypt_password_legacy(password: str, salt: str) -> str:
    """
    Encrypt password using C# legacy method (MD5 + Salt)
    WARNING: This is for backward compatibility only!
    New passwords should use bcrypt (get_password_hash)
    """
    md5_password = md5_hash(password)
    encrypted = md5_hash(f"{md5_password.lower()}{salt}")
    return encrypted.lower()

def verify_password_legacy(plain_password: str, encrypted_password: str, salt: str) -> bool:
    """Verify password against legacy C# encryption"""
    return encrypt_password_legacy(plain_password, salt) == encrypted_password

def simple_encrypt(plain_text: str, key: str) -> str:
    """
    Simple XOR encryption (matches C# EncryptionHelper.Encrypt)
    For compatibility with existing encrypted passwords in DB
    """
    result = []
    for i, char in enumerate(plain_text):
        key_char = key[i % len(key)]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        result.append(encrypted_char)
    encrypted = ''.join(result)
    return base64.b64encode(encrypted.encode()).decode()

def simple_decrypt(encrypted_text: str, key: str) -> str:
    """
    Simple XOR decryption (matches C# EncryptionHelper.Decrypt)
    For compatibility with existing encrypted passwords in DB
    """
    try:
        encrypted = base64.b64decode(encrypted_text.encode()).decode()
        result = []
        for i, char in enumerate(encrypted):
            key_char = key[i % len(key)]
            decrypted_char = chr(ord(char) ^ ord(key_char))
            result.append(decrypted_char)
        return ''.join(result)
    except Exception:
        return ""
    

# JWT token management
def create_access_token(data: Dict, expires_delta: Optional[timedelta]= None) -> str: # type: ignore
    """
    create JWT access token
    
    Args:
    :param data: Dictionary with claims to encode (e.g., {"UserId": 123, "UserName": "john})
    :param expires_delta: Optional expiration time override
    :return: Encode JWT tokeb string
    """
    to_encode = data.copy()
   
    if expires_delta:
        expire = datetime.utcnow() + expires_delta 
    else: 
        expire = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": datetime.utcnow()
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY, # type: ignore
        algorithm=settings.JWT_ALGORITHM # type: ignore
    )
    return encoded_jwt
       
def decode_access_token(token: str) -> Optional[Dict]:
    """
        Decode and validate JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            Dictionary with token claims or None if invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY, # type: ignore
            algorithms=[settings.JWT_ALGORITHM], # type: ignore
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER
        )
        return payload
    except JWTError as e:
        return None
    
# password reset tokens
def generate_reset_token() -> str:
    """Generate secure random token for password reset"""
    return secrets.token_urlsafe(64)

def generate_salt() -> str:
    """Generate random salt for password hashing"""
    return str(secrets.randbelow(100000))

def generate_default_password() -> str:
    """Generate random default password for new users"""
    return str(secrets.randbelow(100000))