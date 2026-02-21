"""
FILE: src/email/schemas.py
Email data schemas — pharmacy-aligned
"""

from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class WelcomeEmailData(BaseModel):
    """Welcome email for newly registered pharmacy staff."""
    email: EmailStr
    first_name: str
    last_name: str
    temp_password: str
    pharmacy_name: Optional[str] = None  # tenant/store name


class PasswordResetEmailData(BaseModel):
    email: EmailStr
    first_name: str
    reset_token: str
    expires_at: datetime


class PasswordChangedEmailData(BaseModel):
    email: EmailStr
    first_name: str
    changed_at: datetime


class AccountLockedEmailData(BaseModel):
    email: EmailStr
    first_name: str
    locked_at: datetime
    reason: str = "Multiple failed login attempts"


class EmailResponse(BaseModel):
    success: bool
    message: str
    email_id: Optional[str] = None
    error: Optional[str] = None