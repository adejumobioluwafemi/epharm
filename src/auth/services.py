"""
FILE: src/auth/services.py
Authentication service — tenant-aware, RBAC, bcrypt+salt
"""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_
from sqlmodel import Session, select

from src.core.config import settings
from src.core.security import (
    create_access_token,
    create_refresh_token_jwt,
    decode_refresh_token,
    generate_reset_token,
    generate_salt,
    generate_temp_password,
    hash_password,
    verify_password,
)
from src.shared.models import (
    PasswordResetToken,
    PharmacyStore,
    RefreshToken,
    Role,
    StaffProfile,
    Tenant,
    User,
    UserRole,
    UserType,
    utcnow,
)
from src.auth.schemas import (
    AssignRoleRequest,
    LoginRequest,
    LoginResponse,
    RegisterStaffRequest,
    TokenResponse,
    UserBasicInfo,
)
import logging

logger = logging.getLogger(__name__)

MAX_FAILED_ATTEMPTS = 5
BCRYPT_REFRESH_HASH = hashlib.sha256  # used to hash raw refresh tokens before DB storage


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class AuthService:
    """All authentication and token business logic."""

    # User lookup helpers 

    @staticmethod
    def _find_user_by_identifier(identifier: str, session: Session) -> Optional[User]:
        """Find user by email or phone."""
        if "@" in identifier:
            return session.exec(select(User).where(User.email == identifier.lower().strip())).first()
        return session.exec(select(User).where(User.phone == identifier.strip())).first()

    @staticmethod
    def _build_jwt_context(user: User, session: Session) -> Dict[str, Any]:
        """Collect tenant_id, store_ids, and role names for JWT payload."""
        user_roles = session.exec(
            select(UserRole).where(UserRole.user_id == user.id)
        ).all()

        # Collect unique tenant ids (usually 1 for staff, none for SUPER_ADMIN)
        tenant_ids = list({ur.tenant_id for ur in user_roles if ur.tenant_id})
        store_ids = [ur.store_id for ur in user_roles if ur.store_id]

        # Collect role names
        role_ids = [ur.role_id for ur in user_roles]
        roles: List[str] = []
        if role_ids:
            db_roles = session.exec(select(Role).where(Role.id.in_(role_ids))).all()  # type: ignore
            roles = [r.name for r in db_roles]

        tenant_id = tenant_ids[0] if tenant_ids else None
        return {
            "tenant_id": tenant_id,
            "store_ids": store_ids,
            "roles": roles,
        }

    @staticmethod
    def _build_user_info(user: User, ctx: Dict) -> UserBasicInfo:
        return UserBasicInfo(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            user_type=user.user_type,
            tenant_id=ctx["tenant_id"],
            store_ids=ctx["store_ids"],
            roles=ctx["roles"],
        )

    # Login / Logout 

    @staticmethod
    async def login(req: LoginRequest, session: Session, request_meta: Dict) -> LoginResponse:
        """
        Authenticate user. Returns access + refresh tokens.
        Locks account after MAX_FAILED_ATTEMPTS failures.
        """
        user = AuthService._find_user_by_identifier(req.identifier, session)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        if user.is_locked:
            logger.warning(f"Login attempt on locked account: {req.identifier}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account locked. Contact your administrator.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated.",
            )

        # Verify password
        if not verify_password(req.password, user.salt, user.password_hash):
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.is_locked = True
                logger.warning(f"Account locked — too many failures: {req.identifier}")
            user.updated_at = utcnow()
            session.add(user)
            session.commit()

            detail = (
                "Account locked due to multiple failed login attempts"
                if user.is_locked
                else "Invalid credentials"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN if user.is_locked else status.HTTP_401_UNAUTHORIZED,
                detail=detail,
            )

        # Build token context
        ctx = AuthService._build_jwt_context(user, session)

        # Issue tokens
        access_token = create_access_token(
            user_id=user.id,
            email=user.email,
            user_type=user.user_type,
            tenant_id=ctx["tenant_id"],
            store_ids=ctx["store_ids"],
            roles=ctx["roles"],
        )
        raw_refresh = create_refresh_token_jwt(user_id=user.id)

        # Persist refresh token
        expires_at = utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS) # type: ignore
        refresh_record = RefreshToken(
            user_id=user.id,
            token_hash=_hash_token(raw_refresh),
            expires_at=expires_at,
            ip_address=request_meta.get("ip"),
            user_agent=request_meta.get("user_agent"),
        )
        session.add(refresh_record)

        # Update user
        user.api_token = access_token
        user.login_count = (user.login_count or 0) + 1
        user.last_login_at = utcnow()
        user.failed_login_attempts = 0
        user.updated_at = utcnow()
        session.add(user)
        session.commit()

        logger.info(f"Login successful: {user.email}")

        return LoginResponse(
            token=TokenResponse(
                access_token=access_token,
                refresh_token=raw_refresh,
                expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            ),
            user=AuthService._build_user_info(user, ctx),
        )

    @staticmethod
    async def logout(user: User, session: Session) -> None:
        """Revoke access token and all refresh tokens."""
        user.api_token = None
        user.updated_at = utcnow()
        session.add(user)

        # Revoke all refresh tokens
        refresh_tokens = session.exec(
            select(RefreshToken).where(
                and_(
                    RefreshToken.user_id == user.id,  # type: ignore
                    RefreshToken.is_revoked == False,  # type: ignore
                )
            )
        ).all()
        for rt in refresh_tokens:
            rt.is_revoked = True
            rt.revoked_at = utcnow()
            session.add(rt)

        session.commit()
        logger.info(f"User logged out: {user.email}")

    @staticmethod
    async def refresh_tokens(
        raw_refresh_token: str, session: Session, request_meta: Dict
    ) -> TokenResponse:
        """Rotate refresh token and issue new access token."""
        user_id_str = decode_refresh_token(raw_refresh_token)
        if not user_id_str:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        token_hash = _hash_token(raw_refresh_token)
        now = utcnow()

        stored = session.exec(
            select(RefreshToken).where(
                and_(
                    RefreshToken.token_hash == token_hash,  # type: ignore
                    RefreshToken.is_revoked == False,  # type: ignore
                    RefreshToken.expires_at > now,  # type: ignore
                )
            )
        ).first()

        if not stored:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired or revoked")

        user = session.get(User, UUID(user_id_str))
        if not user or not user.is_active or user.is_locked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not accessible")

        # Revoke old token (rotation)
        stored.is_revoked = True
        stored.revoked_at = now
        session.add(stored)

        ctx = AuthService._build_jwt_context(user, session)
        new_access = create_access_token(
            user_id=user.id,
            email=user.email,
            user_type=user.user_type,
            tenant_id=ctx["tenant_id"],
            store_ids=ctx["store_ids"],
            roles=ctx["roles"],
        )
        new_raw_refresh = create_refresh_token_jwt(user_id=user.id)

        expires_at = now + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS) # type: ignore
        new_stored = RefreshToken(
            user_id=user.id,
            token_hash=_hash_token(new_raw_refresh),
            expires_at=expires_at,
            ip_address=request_meta.get("ip"),
            user_agent=request_meta.get("user_agent"),
        )
        session.add(new_stored)

        user.api_token = new_access
        user.updated_at = now
        session.add(user)
        session.commit()

        return TokenResponse(
            access_token=new_access,
            refresh_token=new_raw_refresh,
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    # Password Reset

    @staticmethod
    async def request_password_reset(
        email: str, session: Session, request_meta: Dict
    ) -> Tuple[bool, Optional[Dict]]:
        """
        Initiate password reset flow.
        Returns (user_exists, email_data) — always returns success-shaped response to caller.
        """
        user = session.exec(select(User).where(User.email == email.lower().strip())).first()
        if not user or not user.is_active:
            return False, None

        # Invalidate old tokens
        old_tokens = session.exec(
            select(PasswordResetToken).where(
                and_(
                    PasswordResetToken.user_id == user.id,  # type: ignore
                    PasswordResetToken.is_used == False,  # type: ignore
                )
            )
        ).all()
        for ot in old_tokens:
            ot.is_used = True
            ot.updated_at = utcnow()
            session.add(ot)

        token = generate_reset_token()
        expires_at = utcnow() + timedelta(hours=settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS)

        reset_record = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=expires_at,
            ip_address=request_meta.get("ip"),
            user_agent=request_meta.get("user_agent"),
        )
        session.add(reset_record)
        session.commit()

        logger.info(f"Password reset token issued for: {email}")

        return True, {
            "email": user.email,
            "first_name": user.first_name or "User",
            "full_name": user.full_name,
            "reset_token": token,
            "expires_at": expires_at,
        }

    @staticmethod
    async def validate_reset_token(token: str, session: Session) -> bool:
        record = session.exec(
            select(PasswordResetToken).where(
                and_(
                    PasswordResetToken.token == token,  # type: ignore
                    PasswordResetToken.is_used == False,  # type: ignore
                    PasswordResetToken.expires_at > utcnow(),  # type: ignore
                )
            )
        ).first()
        return record is not None

    @staticmethod
    async def reset_password(token: str, new_password: str, session: Session) -> User:
        record = session.exec(
            select(PasswordResetToken).where(
                and_(
                    PasswordResetToken.token == token,  # type: ignore
                    PasswordResetToken.is_used == False,  # type: ignore
                    PasswordResetToken.expires_at > utcnow(),  # type: ignore
                )
            )
        ).first()

        if not record:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

        user = session.get(User, record.user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        salt = generate_salt()
        user.salt = salt
        user.password_hash = hash_password(new_password, salt)
        user.last_password_change = utcnow()
        user.failed_login_attempts = 0
        user.is_locked = False
        user.api_token = None  # force re-login
        user.updated_at = utcnow()

        record.is_used = True
        record.used_at = utcnow()

        session.add(user)
        session.add(record)
        session.commit()
        logger.info(f"Password reset successful: {user.email}")
        return user

    @staticmethod
    async def change_password(
        user: User, current_password: str, new_password: str, session: Session
    ) -> None:
        if not verify_password(current_password, user.salt, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect",
            )
        salt = generate_salt()
        user.salt = salt
        user.password_hash = hash_password(new_password, salt)
        user.last_password_change = utcnow()
        user.api_token = None  # force re-login
        user.updated_at = utcnow()
        session.add(user)
        session.commit()
        logger.info(f"Password changed: {user.email}")

    # Staff Registration

    @staticmethod
    async def register_staff(
        req: RegisterStaffRequest,
        tenant_id: UUID,
        registering_user_id: UUID,
        session: Session,
    ) -> Tuple[User, str]:
        """
        Register a new staff member for a specific store within a tenant.
        Returns (user, temp_password).
        """
        # Validate email uniqueness
        if session.exec(select(User).where(User.email == req.email.lower())).first():
            raise HTTPException(status_code=400, detail="Email already registered")

        # Validate phone uniqueness
        if req.phone and session.exec(select(User).where(User.phone == req.phone)).first():
            raise HTTPException(status_code=400, detail="Phone number already registered")

        # Validate store belongs to tenant
        store = session.get(PharmacyStore, req.store_id)
        if not store or store.tenant_id != tenant_id or not store.is_active:
            raise HTTPException(status_code=404, detail="Store not found in your tenant")

        # Validate role exists
        role = session.exec(select(Role).where(Role.name == req.role_name)).first()
        if not role:
            raise HTTPException(status_code=404, detail=f"Role '{req.role_name}' not found")

        # Generate credentials
        temp_password = generate_temp_password()
        salt = generate_salt()
        password_hash = hash_password(temp_password, salt)

        user = User(
            email=req.email.lower(),
            phone=req.phone,
            first_name=req.first_name,
            last_name=req.last_name,
            middle_name=req.middle_name,
            password_hash=password_hash,
            salt=salt,
            user_type=req.user_type,
            is_active=True,
            is_locked=False,
        )
        session.add(user)
        session.flush()  # get user.id

        # Assign role scoped to tenant + store
        user_role = UserRole(
            user_id=user.id,
            role_id=role.id,
            tenant_id=tenant_id,
            store_id=req.store_id,
            assigned_by=registering_user_id,
        )
        session.add(user_role)

        # Create staff profile
        staff_profile = StaffProfile(
            user_id=user.id,
            tenant_id=tenant_id,
            store_id=req.store_id,
            license_number=req.license_number,
        )
        session.add(staff_profile)

        session.commit()
        session.refresh(user)

        logger.info(f"Staff registered: {user.email} at store {req.store_id} in tenant {tenant_id}")
        return user, temp_password

    # Role Assignment

    @staticmethod
    async def assign_role(
        req: AssignRoleRequest,
        tenant_id: UUID,
        assigning_user_id: UUID,
        session: Session,
    ) -> UserRole:
        user = session.get(User, req.user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        role = session.exec(select(Role).where(Role.name == req.role_name)).first()
        if not role:
            raise HTTPException(status_code=404, detail=f"Role '{req.role_name}' not found")

        if req.store_id:
            store = session.get(PharmacyStore, req.store_id)
            if not store or store.tenant_id != tenant_id:
                raise HTTPException(status_code=404, detail="Store not found in tenant")

        # Upsert: check if already exists
        existing = session.exec(
            select(UserRole).where(
                and_(
                    UserRole.user_id == req.user_id,  # type: ignore
                    UserRole.role_id == role.id,  # type: ignore
                    UserRole.tenant_id == tenant_id,  # type: ignore
                    UserRole.store_id == req.store_id,  # type: ignore
                )
            )
        ).first()

        if existing:
            return existing

        user_role = UserRole(
            user_id=req.user_id,
            role_id=role.id,
            tenant_id=tenant_id,
            store_id=req.store_id,
            assigned_by=assigning_user_id,
        )
        session.add(user_role)
        session.commit()
        session.refresh(user_role)

        logger.info(f"Role '{req.role_name}' assigned to user {req.user_id} in tenant {tenant_id}")
        return user_role

    @staticmethod
    async def revoke_role(
        user_id: UUID,
        role_name: str,
        tenant_id: UUID,
        store_id: Optional[UUID],
        session: Session,
    ) -> None:
        role = session.exec(select(Role).where(Role.name == role_name)).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        existing = session.exec(
            select(UserRole).where(
                and_(
                    UserRole.user_id == user_id,  # type: ignore
                    UserRole.role_id == role.id,  # type: ignore
                    UserRole.tenant_id == tenant_id,  # type: ignore
                    UserRole.store_id == store_id,  # type: ignore
                )
            )
        ).first()
        if not existing:
            raise HTTPException(status_code=404, detail="Role assignment not found")

        session.delete(existing)
        session.commit()
        logger.info(f"Role '{role_name}' revoked from user {user_id}")