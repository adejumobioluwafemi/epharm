"""
FILE: src/shared/models.py
SQLModel ORM models — E-Pharmacy Multi-Tenant Domain
All business tables include tenant_id; store-specific tables also include store_id.
"""

from sqlmodel import SQLModel, Field, Relationship
from typing import List, Optional
from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID, uuid4
import enum


# Enums 

class UserType(str, enum.Enum):
    PATIENT = "PATIENT"
    STAFF = "STAFF"
    RIDER = "RIDER"
    SUPER_ADMIN = "SUPER_ADMIN"


class RoleName(str, enum.Enum):
    SUPER_ADMIN = "SUPER_ADMIN"       # Platform-wide admin 
    TENANT_ADMIN = "TENANT_ADMIN"     # Pharmacy company admin (super-admin within tenant)
    STORE_MANAGER = "STORE_MANAGER"   # Branch manager
    PHARMACIST = "PHARMACIST"
    CASHIER = "CASHIER"
    INVENTORY_CLERK = "INVENTORY_CLERK"
    RIDER = "RIDER"                   # Delivery
    PATIENT = "PATIENT"               # Customer


# Base mixins 

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TimestampMixin(SQLModel):
    created_at: Optional[datetime] = Field(default_factory=utcnow, nullable=True)
    updated_at: Optional[datetime] = Field(default=None, nullable=True)
    deleted_at: Optional[datetime] = Field(default=None, nullable=True)


# Tenants

class Tenant(TimestampMixin, table=True):
    """Represents a pharmacy company (the top-level tenant)."""
    __tablename__ = "tenants"  # type: ignore

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str = Field(..., max_length=255, index=True)
    slug: str = Field(..., max_length=100, unique=True, index=True)
    registration_number: Optional[str] = Field(default=None, max_length=100)
    email: Optional[str] = Field(default=None, max_length=255)
    phone: Optional[str] = Field(default=None, max_length=20)
    address: Optional[str] = Field(default=None)
    logo_url: Optional[str] = Field(default=None)
    is_active: bool = Field(default=True)

    # Relationships
    stores: List["PharmacyStore"] = Relationship(back_populates="tenant")
    user_roles: List["UserRole"] = Relationship(back_populates="tenant")


# Pharmacy Stores

class PharmacyStore(TimestampMixin, table=True):
    """Physical branch / location of a pharmacy."""
    __tablename__ = "pharmacy_stores"  # type: ignore

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID = Field(..., foreign_key="tenants.id", index=True)
    name: str = Field(..., max_length=255)
    address: str = Field(...)
    city: Optional[str] = Field(default=None, max_length=100)
    state: Optional[str] = Field(default=None, max_length=100)
    postal_code: Optional[str] = Field(default=None, max_length=20)
    latitude: Optional[Decimal] = Field(default=None, decimal_places=8, max_digits=11)
    longitude: Optional[Decimal] = Field(default=None, decimal_places=8, max_digits=11)
    phone: Optional[str] = Field(default=None, max_length=20)
    email: Optional[str] = Field(default=None, max_length=255)
    is_active: bool = Field(default=True)

    # Relationships
    tenant: Optional[Tenant] = Relationship(back_populates="stores")
    user_roles: List["UserRole"] = Relationship(back_populates="store")
    staff_profiles: List["StaffProfile"] = Relationship(back_populates="store")


# Users 

class User(TimestampMixin, table=True):
    """
    Core user identity — tenant-agnostic.
    A user can belong to multiple tenants via UserRole.
    """
    __tablename__ = "users"  # type: ignore

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(..., max_length=255, unique=True, index=True)
    phone: Optional[str] = Field(default=None, max_length=20, unique=True, index=True)

    # Salted bcrypt hash
    password_hash: str = Field(...)
    salt: str = Field(...)

    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    middle_name: Optional[str] = Field(default=None, max_length=100)
    avatar_url: Optional[str] = Field(default=None)

    user_type: UserType = Field(default=UserType.STAFF)
    is_active: bool = Field(default=True)
    is_locked: bool = Field(default=False)

    # Auth tracking
    api_token: Optional[str] = Field(default=None)  # current access token (revocation)
    refresh_token_hash: Optional[str] = Field(default=None)
    login_count: int = Field(default=0)
    last_login_at: Optional[datetime] = Field(default=None)
    failed_login_attempts: int = Field(default=0)

    # Password reset
    password_reset_token: Optional[str] = Field(default=None)
    password_reset_expires: Optional[datetime] = Field(default=None)
    last_password_change: Optional[datetime] = Field(default=None)

    # Relationships
    user_roles: List["UserRole"] = Relationship(back_populates="user")
    staff_profile: Optional["StaffProfile"] = Relationship(back_populates="user")
    password_reset_tokens: List["PasswordResetToken"] = Relationship(back_populates="user")

    @property
    def full_name(self) -> str:
        parts = [self.first_name, self.middle_name, self.last_name]
        return " ".join(p for p in parts if p)


# Roles

class Role(SQLModel, table=True):
    """System-defined roles. Seeded at startup."""
    __tablename__ = "roles"  # type: ignore

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str = Field(..., max_length=50, unique=True, index=True)
    description: Optional[str] = Field(default=None)

    # Relationships
    user_roles: List["UserRole"] = Relationship(back_populates="role")


# User Roles (junction — scoped per tenant + optional store) 

class UserRole(TimestampMixin, table=True):
    """
    M:N between User and Role, scoped by tenant and (optionally) store.
    PK: (user_id, role_id, tenant_id, store_id)
    store_id = NULL means role applies to the whole tenant.
    """
    __tablename__ = "user_roles"  # type: ignore

    user_id: UUID = Field(..., foreign_key="users.id", primary_key=True)
    role_id: UUID = Field(..., foreign_key="roles.id", primary_key=True)
    tenant_id: UUID = Field(..., foreign_key="tenants.id", primary_key=True)
    # nullable — NULL means tenant-wide scope
    store_id: Optional[UUID] = Field(default=None, foreign_key="pharmacy_stores.id", primary_key=True)
    assigned_by: Optional[UUID] = Field(default=None, foreign_key="users.id")
    assigned_at: datetime = Field(default_factory=utcnow)

    # Relationships
    user: Optional[User] = Relationship(
        back_populates="user_roles",
        sa_relationship_kwargs={"foreign_keys": "[UserRole.user_id]"},
    )
    role: Optional[Role] = Relationship(back_populates="user_roles")
    tenant: Optional[Tenant] = Relationship(back_populates="user_roles")
    store: Optional[PharmacyStore] = Relationship(back_populates="user_roles")


# Staff Profiles

class StaffProfile(TimestampMixin, table=True):
    """Additional profile data for pharmacy staff."""
    __tablename__ = "staff_profiles"  # type: ignore

    user_id: UUID = Field(..., foreign_key="users.id", primary_key=True)
    tenant_id: UUID = Field(..., foreign_key="tenants.id", index=True)
    store_id: UUID = Field(..., foreign_key="pharmacy_stores.id", index=True)

    license_number: Optional[str] = Field(default=None, max_length=100)
    license_expiry: Optional[datetime] = Field(default=None)
    verified: bool = Field(default=False)
    verified_at: Optional[datetime] = Field(default=None)
    verified_by: Optional[UUID] = Field(default=None, foreign_key="users.id")

    # Relationships
    user: Optional[User] = Relationship(back_populates="staff_profile")
    store: Optional[PharmacyStore] = Relationship(back_populates="staff_profiles")


# Password Reset Tokens 

class PasswordResetToken(TimestampMixin, table=True):
    __tablename__ = "password_reset_tokens"  # type: ignore

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(..., foreign_key="users.id", index=True)
    token: str = Field(..., index=True)  # store as-is (urlsafe random — not a hash)
    expires_at: datetime = Field(...)
    is_used: bool = Field(default=False)
    used_at: Optional[datetime] = Field(default=None)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    user_agent: Optional[str] = Field(default=None, max_length=500)

    # Relationships
    user: Optional[User] = Relationship(back_populates="password_reset_tokens")


# Refresh Tokens

class RefreshToken(TimestampMixin, table=True):
    __tablename__ = "refresh_tokens"  # type: ignore

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(..., foreign_key="users.id", index=True)
    token_hash: str = Field(..., index=True)   # sha256 hash of the raw token
    expires_at: datetime = Field(...)
    is_revoked: bool = Field(default=False)
    revoked_at: Optional[datetime] = Field(default=None)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    user_agent: Optional[str] = Field(default=None, max_length=500)