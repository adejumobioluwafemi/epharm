"""
FILE: src/users/schemas.py
User management schemas — tenant-aware
"""

from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from src.shared.models import UserType


class UserOut(BaseModel):
    id: UUID
    email: str
    phone: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    middle_name: Optional[str]
    user_type: UserType
    is_active: bool
    is_locked: bool
    login_count: int
    last_login_at: Optional[datetime]
    created_at: Optional[datetime]

    model_config = {"from_attributes": True}


class UserWithRoles(UserOut):
    roles: List[str] = []
    store_ids: List[UUID] = []


class UpdateUserRequest(BaseModel):
    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    middle_name: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=20)


class TenantOut(BaseModel):
    id: UUID
    name: str
    slug: str
    registration_number: Optional[str]
    email: Optional[str]
    phone: Optional[str]
    is_active: bool
    created_at: Optional[datetime]

    model_config = {"from_attributes": True}


class CreateTenantRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-z0-9\-]+$")
    registration_number: Optional[str] = Field(default=None, max_length=100)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(default=None, max_length=20)
    address: Optional[str] = None


class StoreOut(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    address: str
    city: Optional[str]
    state: Optional[str]
    is_active: bool
    created_at: Optional[datetime]

    model_config = {"from_attributes": True}


class CreateStoreRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    address: str = Field(..., min_length=5)
    city: Optional[str] = Field(default=None, max_length=100)
    state: Optional[str] = Field(default=None, max_length=100)
    postal_code: Optional[str] = Field(default=None, max_length=20)
    phone: Optional[str] = Field(default=None, max_length=20)
    email: Optional[EmailStr] = None
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)