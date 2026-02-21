"""
FILE: src/core/dependencies.py
FastAPI dependencies — tenant-aware authentication & RBAC
"""

from fastapi import Depends, HTTPException, status, Header, Request
from sqlmodel import Session, select
from typing import List, Optional
from uuid import UUID

from src.core.database import get_session
from src.core.security import decode_access_token
from src.shared.models import User, UserRole, Role
import logging

logger = logging.getLogger(__name__)


# Token extraction 

def _extract_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
        )
    return parts[1]


# Current user 

async def get_current_user(
    authorization: Optional[str] = Header(None),
    session: Session = Depends(get_session),
) -> User:
    """
    Validate Bearer token and return the authenticated User.
    Raises 401 on invalid token, 403 on locked/inactive account.
    """
    token = _extract_token(authorization)
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    try:
        user_id = UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    if user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is locked. Contact your administrator.",
        )

    # Token revocation check — stored token must match
    if user.api_token != token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please log in again.",
        )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive account",
        )
    return current_user


async def get_optional_current_user(
    authorization: Optional[str] = Header(None),
    session: Session = Depends(get_session),
) -> Optional[User]:
    """Returns the current user or None (for public+auth endpoints)."""
    try:
        if not authorization:
            return None
        token = _extract_token(authorization)
        payload = decode_access_token(token)
        if not payload:
            return None
        user_id = UUID(payload.get("sub", ""))
        user = session.get(User, user_id)
        if not user or not user.is_active or user.is_locked:
            return None
        return user
    except Exception:
        return None


# Tenant context 

class TenantContext:
    """
    Extracts tenant_id and store_ids from the JWT payload and
    exposes them for downstream use. Enforces that tenant-scoped
    endpoints are accessed only by users belonging to that tenant.
    """

    def __init__(
        self,
        authorization: Optional[str] = Header(None),
        current_user: User = Depends(get_current_user),
    ):
        self.user = current_user
        payload = decode_access_token(_extract_token(authorization)) or {}
        tenant_id_str = payload.get("tenant_id")
        store_ids_str: List[str] = payload.get("store_ids", [])
        self.roles: List[str] = payload.get("roles", [])
        self.tenant_id: Optional[UUID] = UUID(tenant_id_str) if tenant_id_str else None
        self.store_ids: List[UUID] = [UUID(s) for s in store_ids_str if s]

    def require_tenant(self) -> UUID:
        """Raises 403 if the user has no tenant context (e.g. unauthenticated SUPER_ADMIN path)."""
        if not self.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant context required",
            )
        return self.tenant_id

    def has_role(self, role_name: str) -> bool:
        return role_name in self.roles

    def is_super_admin(self) -> bool:
        return "SUPER_ADMIN" in self.roles

    def can_access_store(self, store_id: UUID) -> bool:
        if self.is_super_admin():
            return True
        return store_id in self.store_ids


# RBAC dependency factories 

def require_roles(*role_names: str):
    """
    Dependency factory: user must have at least one of the given role names.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_roles("SUPER_ADMIN", "STORE_MANAGER"))])
    """
    async def checker(
        authorization: Optional[str] = Header(None),
        current_user: User = Depends(get_current_user),
        session: Session = Depends(get_session),
    ) -> User:
        payload = decode_access_token(_extract_token(authorization)) or {}
        user_roles: List[str] = payload.get("roles", [])
        if not any(r in user_roles for r in role_names):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {list(role_names)}",
            )
        return current_user

    return checker


def require_super_admin():
    return require_roles("SUPER_ADMIN")


def require_tenant_admin():
    return require_roles("SUPER_ADMIN", "TENANT_ADMIN")


def require_store_manager():
    return require_roles("SUPER_ADMIN", "TENANT_ADMIN", "STORE_MANAGER")


def require_staff():
    return require_roles("SUPER_ADMIN", "TENANT_ADMIN", "STORE_MANAGER", "PHARMACIST", "CASHIER")


# Pagination 

def pagination_params(page: int = 1, page_size: int = 20) -> dict:
    """
    Standard pagination parameters.
    Returns {skip, limit, page, page_size}.
    """
    if page < 1:
        raise HTTPException(status_code=400, detail="page must be >= 1")
    if page_size < 1 or page_size > 200:
        raise HTTPException(status_code=400, detail="page_size must be between 1 and 200")
    skip = (page - 1) * page_size
    return {"skip": skip, "limit": page_size, "page": page, "page_size": page_size}