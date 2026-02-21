"""
FILE: src/users/services.py
User & tenant management — tenant-isolated CRUD with pagination
"""

from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import func
from sqlmodel import Session, select

from src.shared.models import (
    PharmacyStore,
    Role,
    Tenant,
    User,
    UserRole,
    utcnow,
)
from src.users.schemas import (
    CreateStoreRequest,
    CreateTenantRequest,
    StoreOut,
    TenantOut,
    UpdateUserRequest,
    UserOut,
    UserWithRoles,
)
import logging

logger = logging.getLogger(__name__)


class UserService:
    """User management — tenant-scoped."""

    @staticmethod
    def _user_roles(user_id: UUID, tenant_id: UUID, session: Session) -> Tuple[List[str], List[UUID]]:
        """Returns (role_names, store_ids) for a user within a tenant."""
        user_role_rows = session.exec(
            select(UserRole).where(
                UserRole.user_id == user_id,  # type: ignore
                UserRole.tenant_id == tenant_id,  # type: ignore
            )
        ).all()
        role_ids = [ur.role_id for ur in user_role_rows]
        store_ids = [ur.store_id for ur in user_role_rows if ur.store_id]
        roles: List[str] = []
        if role_ids:
            db_roles = session.exec(select(Role).where(Role.id.in_(role_ids))).all()  # type: ignore
            roles = [r.name for r in db_roles]
        return roles, store_ids

    @staticmethod
    async def get_users_in_tenant(
        tenant_id: UUID,
        session: Session,
        skip: int = 0,
        limit: int = 20,
    ) -> Tuple[List[UserWithRoles], int]:
        """
        List all users within a tenant (those with at least one UserRole in the tenant).
        Returns (items, total_count).
        """
        # Get user_ids in tenant
        user_role_rows = session.exec(
            select(UserRole.user_id).where(
                UserRole.tenant_id == tenant_id  # type: ignore
            ).distinct()
        ).all()

        all_user_ids = list(set(user_role_rows))
        total = len(all_user_ids)
        page_ids = all_user_ids[skip: skip + limit]

        users = session.exec(
            select(User).where(User.id.in_(page_ids))  # type: ignore
        ).all()

        result = []
        for user in users:
            roles, store_ids = UserService._user_roles(user.id, tenant_id, session)
            user_out = UserWithRoles.model_validate(user)
            user_out.roles = roles
            user_out.store_ids = store_ids
            result.append(user_out)

        return result, total

    @staticmethod
    async def get_user_by_id(
        user_id: UUID,
        tenant_id: UUID,
        session: Session,
    ) -> UserWithRoles:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Verify user belongs to tenant
        membership = session.exec(
            select(UserRole).where(
                UserRole.user_id == user_id,  # type: ignore
                UserRole.tenant_id == tenant_id,  # type: ignore
            )
        ).first()
        if not membership:
            raise HTTPException(status_code=403, detail="User does not belong to your tenant")

        roles, store_ids = UserService._user_roles(user_id, tenant_id, session)
        user_out = UserWithRoles.model_validate(user)
        user_out.roles = roles
        user_out.store_ids = store_ids
        return user_out

    @staticmethod
    async def update_user(
        user_id: UUID,
        req: UpdateUserRequest,
        tenant_id: UUID,
        session: Session,
    ) -> UserWithRoles:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Validate tenant membership
        membership = session.exec(
            select(UserRole).where(
                UserRole.user_id == user_id,  # type: ignore
                UserRole.tenant_id == tenant_id,  # type: ignore
            )
        ).first()
        if not membership:
            raise HTTPException(status_code=403, detail="User does not belong to your tenant")

        update_data = req.model_dump(exclude_none=True)
        for field, value in update_data.items():
            setattr(user, field, value)
        user.updated_at = utcnow()
        session.add(user)
        session.commit()
        session.refresh(user)

        roles, store_ids = UserService._user_roles(user_id, tenant_id, session)
        user_out = UserWithRoles.model_validate(user)
        user_out.roles = roles
        user_out.store_ids = store_ids
        return user_out

    @staticmethod
    async def deactivate_user(user_id: UUID, tenant_id: UUID, session: Session) -> None:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        membership = session.exec(
            select(UserRole).where(
                UserRole.user_id == user_id,  # type: ignore
                UserRole.tenant_id == tenant_id,  # type: ignore
            )
        ).first()
        if not membership:
            raise HTTPException(status_code=403, detail="User does not belong to your tenant")

        user.is_active = False
        user.updated_at = utcnow()
        session.add(user)
        session.commit()
        logger.info(f"User deactivated: {user_id} in tenant {tenant_id}")

    @staticmethod
    async def lock_user(user_id: UUID, tenant_id: UUID, session: Session) -> None:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.is_locked = True
        user.api_token = None  # revoke active sessions
        user.updated_at = utcnow()
        session.add(user)
        session.commit()

    @staticmethod
    async def unlock_user(user_id: UUID, tenant_id: UUID, session: Session) -> None:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.is_locked = False
        user.failed_login_attempts = 0
        user.updated_at = utcnow()
        session.add(user)
        session.commit()


class TenantService:
    """Tenant management — SUPER_ADMIN only."""

    @staticmethod
    async def create_tenant(req: CreateTenantRequest, session: Session) -> Tenant:
        # Slug uniqueness
        existing = session.exec(select(Tenant).where(Tenant.slug == req.slug)).first()
        if existing:
            raise HTTPException(status_code=400, detail="Tenant slug already exists")

        tenant = Tenant(
            name=req.name,
            slug=req.slug,
            registration_number=req.registration_number,
            email=req.email,
            phone=req.phone,
            address=req.address,
        )
        session.add(tenant)
        session.commit()
        session.refresh(tenant)
        logger.info(f"Tenant created: {tenant.slug}")
        return tenant

    @staticmethod
    async def list_tenants(
        session: Session, skip: int = 0, limit: int = 20
    ) -> Tuple[List[Tenant], int]:
        total = session.exec(select(func.count(Tenant.id))).one()  # type: ignore
        tenants = session.exec(
            select(Tenant).where(Tenant.deleted_at == None).offset(skip).limit(limit)  # type: ignore
        ).all()
        return list(tenants), total

    @staticmethod
    async def get_tenant(tenant_id: UUID, session: Session) -> Tenant:
        tenant = session.get(Tenant, tenant_id)
        if not tenant or tenant.deleted_at:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return tenant


class StoreService:
    """Pharmacy store (branch) management."""

    @staticmethod
    async def create_store(
        req: CreateStoreRequest, tenant_id: UUID, session: Session
    ) -> PharmacyStore:
        # Validate tenant exists
        tenant = session.get(Tenant, tenant_id)
        if not tenant or not tenant.is_active:
            raise HTTPException(status_code=404, detail="Tenant not found or inactive")

        store = PharmacyStore(
            tenant_id=tenant_id,
            name=req.name,
            address=req.address,
            city=req.city,
            state=req.state,
            postal_code=req.postal_code,
            phone=req.phone,
            email=req.email,
            latitude=req.latitude, # type: ignore
            longitude=req.longitude, # type: ignore
        )
        session.add(store)
        session.commit()
        session.refresh(store)
        logger.info(f"Store created: {store.name} in tenant {tenant_id}")
        return store

    @staticmethod
    async def list_stores(
        tenant_id: UUID, session: Session, skip: int = 0, limit: int = 20
    ) -> Tuple[List[PharmacyStore], int]:
        total = session.exec(
            select(func.count(PharmacyStore.id)).where( # type: ignore
                PharmacyStore.tenant_id == tenant_id  # type: ignore
            )
        ).one()
        stores = session.exec(
            select(PharmacyStore)
            .where(
                PharmacyStore.tenant_id == tenant_id,  # type: ignore
                PharmacyStore.deleted_at == None,  # type: ignore
            )
            .offset(skip)
            .limit(limit)
        ).all()
        return list(stores), total

    @staticmethod
    async def get_store(store_id: UUID, tenant_id: UUID, session: Session) -> PharmacyStore:
        store = session.get(PharmacyStore, store_id)
        if not store or store.tenant_id != tenant_id or store.deleted_at:
            raise HTTPException(status_code=404, detail="Store not found")
        return store

    @staticmethod
    async def deactivate_store(store_id: UUID, tenant_id: UUID, session: Session) -> None:
        store = session.get(PharmacyStore, store_id)
        if not store or store.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="Store not found")
        store.is_active = False
        store.updated_at = utcnow()
        session.add(store)
        session.commit()