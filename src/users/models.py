# src/users/models.py

from sqlmodel import SQLModel, Field, Relationship
from uuid import UUID, uuid4
from datetime import datetime
from typing import Optional, List


class User(SQLModel, table=True):
    __tablename__ = "users" # type: ignore

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(index=True, unique=True)
    phone: Optional[str] = Field(index=True)
    password_hash: str
    user_type: str  # PATIENT | STAFF | RIDER | SUPER_ADMIN
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None

    roles: List["UserRole"] = Relationship(back_populates="user")


class Role(SQLModel, table=True):
    __tablename__ = "roles" # type: ignore

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str = Field(unique=True)
    description: Optional[str]

    users: List["UserRole"] = Relationship(back_populates="role")


class UserRole(SQLModel, table=True):
    __tablename__ = "user_roles" # type: ignore

    user_id: UUID = Field(foreign_key="users.id", primary_key=True)
    role_id: UUID = Field(foreign_key="roles.id", primary_key=True)
    tenant_id: UUID = Field(foreign_key="tenants.id", primary_key=True)
    store_id: Optional[UUID] = Field(default=None, foreign_key="pharmacy_stores.id")
    assigned_at: datetime = Field(default_factory=datetime.utcnow)

    user: User = Relationship(back_populates="roles")
    role: Role = Relationship(back_populates="users")