"""
FILE: src/auth/schemas.py
Auth request and response schemas
"""

from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from src.shared.models import UserType


# Requests

class LoginRequest(BaseModel):
    """Login with email or phone."""
    identifier: str = Field(..., description="Email or phone number")
    password: str = Field(..., min_length=6)


class RegisterStaffRequest(BaseModel):
    """Admin registers a new staff member at a store."""
    email: EmailStr
    phone: str = Field(..., min_length=10, max_length=20)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    middle_name: Optional[str] = Field(default=None, max_length=100)
    user_type: UserType = Field(default=UserType.STAFF)
    store_id: UUID = Field(..., description="Pharmacy store to assign the staff to")
    role_name: str = Field(..., description="Role to assign (e.g. PHARMACIST, CASHIER)")
    license_number: Optional[str] = Field(default=None, max_length=100)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=1)

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, info):
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, info):
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v


class RefreshTokenRequest(BaseModel):
    refresh_token: str


# Responses

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class UserBasicInfo(BaseModel):
    id: UUID
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    user_type: str
    tenant_id: Optional[UUID]
    store_ids: List[UUID]
    roles: List[str]

    model_config = {"from_attributes": True}


class LoginResponse(BaseModel):
    token: TokenResponse
    user: UserBasicInfo


class AssignRoleRequest(BaseModel):
    user_id: UUID
    role_name: str
    store_id: Optional[UUID] = Field(
        default=None,
        description="Leave null for tenant-wide role assignment"
    )