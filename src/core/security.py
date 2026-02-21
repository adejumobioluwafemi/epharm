"""
FILE: src/core/security.py
Security utilities — bcrypt hashing with salt, JWT with tenant context
"""

import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import UUID

from jose import JWTError, jwt  
from passlib.context import CryptContext  

from src.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Password Hashing 

def generate_salt() -> str:
    """Generate a cryptographically secure random salt (hex string)."""
    return secrets.token_hex(32)  # 64-char hex string


def hash_password(plain_password: str, salt: str) -> str:
    """
    Hash password using bcrypt after salting.
    We prepend the salt to the password before hashing so that
    even if two users share a password the hashes differ.
    """
    salted = f"{salt}{plain_password}"
    return pwd_context.hash(salted)


def verify_password(plain_password: str, salt: str, hashed_password: str) -> bool:
    """Verify a plain password against its stored salt + bcrypt hash."""
    salted = f"{salt}{plain_password}"
    return pwd_context.verify(salted, hashed_password)


def generate_temp_password(length: int = 12) -> str:
    """Generate a secure temporary password."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# Token Generation

def generate_reset_token() -> str:
    """Generate a URL-safe secure random token for password reset."""
    return secrets.token_urlsafe(64)


def generate_refresh_token() -> str:
    """Generate a secure refresh token."""
    return secrets.token_urlsafe(64)


# JWT

def create_access_token(
    *,
    user_id: UUID,
    email: str,
    user_type: str,
    tenant_id: Optional[UUID] = None,
    store_ids: Optional[List[UUID]] = None,
    roles: Optional[List[str]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create JWT access token with full tenant/store/role context.

    Payload structure:
    {
      "sub":       "<user_id>",          # standard JWT subject
      "email":     "...",
      "user_type": "STAFF|PATIENT|...",
      "tenant_id": "<uuid>",             # nullable for SUPER_ADMIN
      "store_ids": ["<uuid>", ...],      # stores user has access to
      "roles":     ["SUPER_ADMIN", ...],
      "iss":       "epharm-api",
      "aud":       "epharm-frontend",
      "iat":       <timestamp>,
      "exp":       <timestamp>,
    }
    """
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta
        else timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    payload: Dict = {
        "sub": str(user_id),
        "email": email,
        "user_type": user_type,
        "tenant_id": str(tenant_id) if tenant_id else None,
        "store_ids": [str(s) for s in (store_ids or [])],
        "roles": roles or [],
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": now,
        "exp": expire,
    }

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM) # type: ignore


def create_refresh_token_jwt(
    *,
    user_id: UUID,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a minimal JWT for refresh (subject + expiry only)."""
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta
        else timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS) # type: ignore
    )
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM) # type: ignore


def decode_access_token(token: str) -> Optional[Dict]:
    """
    Decode and validate a JWT access token.
    Returns the payload dict or None if invalid/expired.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY, # type: ignore
            algorithms=[settings.JWT_ALGORITHM], # type: ignore
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )
        return payload
    except JWTError:
        return None


def decode_refresh_token(token: str) -> Optional[str]:
    """
    Decode and validate a JWT refresh token.
    Returns the user_id (sub) or None if invalid.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY, # type: ignore
            algorithms=[settings.JWT_ALGORITHM], # type: ignore
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )
        if payload.get("type") != "refresh":
            return None
        return payload.get("sub")
    except JWTError:
        return None