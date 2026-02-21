"""
FILE: src/auth/router.py
Authentication endpoints — register, login, logout, refresh, password flow, RBAC
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session
from typing import Optional
from uuid import UUID

from src.core.database import get_session
from src.core.dependencies import (
    TenantContext,
    get_current_user,
    require_store_manager,
    require_tenant_admin,
) 
from src.core.config import settings
from src.shared.models import User
from src.shared.schemas import ResponseModel
from src.auth.schemas import (
    AssignRoleRequest,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    RegisterStaffRequest,
    ResetPasswordRequest,
    TokenResponse,
)
from src.auth.services import AuthService
from src.email.service import EmailService
from src.email.schemas import (
    AccountLockedEmailData,
    PasswordChangedEmailData,
    PasswordResetEmailData,
    WelcomeEmailData,
)
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _request_meta(request: Request) -> dict:
    return {
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
    }


# Login 

@router.post("/login", response_model=ResponseModel)
async def login(
    credentials: LoginRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Authenticate with email/phone + password.
    Returns JWT access token + refresh token.
    Locks account after 5 failed attempts and sends notification email.
    """
    try:
        result = await AuthService.login(credentials, session, _request_meta(request))
        return ResponseModel(success=True, message="Login successful", data=result.model_dump())
    except HTTPException as exc:
        # If account just got locked, send email notification
        if exc.status_code == status.HTTP_403_FORBIDDEN and "locked" in exc.detail.lower():
            from sqlmodel import select
            user = session.exec(
                select(User).where(
                    (User.email == credentials.identifier) | (User.phone == credentials.identifier)
                )
            ).first()
            if user and user.email and user.first_name:
                lock_data = AccountLockedEmailData(
                    email=user.email,
                    first_name=user.first_name or "User", # type: ignore
                    locked_at=datetime.utcnow(),
                    reason="Multiple failed login attempts",
                ) # type: ignore
                await EmailService.send_account_locked_email(lock_data)
        raise


# Logout 

@router.post("/logout", response_model=ResponseModel)
async def logout(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Revoke access token and all refresh tokens."""
    await AuthService.logout(current_user, session)
    return ResponseModel(success=True, message="Logged out successfully")


# Refresh 

@router.post("/refresh", response_model=ResponseModel)
async def refresh(
    req: RefreshTokenRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """Exchange a valid refresh token for a new access + refresh token pair."""
    tokens = await AuthService.refresh_tokens(req.refresh_token, session, _request_meta(request))
    return ResponseModel(success=True, message="Tokens refreshed", data=tokens.model_dump())


# Staff Registration (tenant-admin / store-manager only) 

@router.post(
    "/register",
    response_model=ResponseModel,
    dependencies=[Depends(require_store_manager())],
)
async def register_staff(
    req: RegisterStaffRequest,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    """
    Register a new staff member for a store within your tenant.
    Requires STORE_MANAGER, TENANT_ADMIN, or SUPER_ADMIN role.
    Sends welcome email with temporary credentials.
    """
    tenant_id = ctx.require_tenant()

    user, temp_password = await AuthService.register_staff(
        req, tenant_id, ctx.user.id, session
    )

    # Send welcome email
    if user.email:
        welcome_data = WelcomeEmailData(
            email=user.email,
            first_name=user.first_name or "", # type: ignore
            last_name=user.last_name or "", # type: ignore
            temp_password=temp_password,
        ) # type: ignore
        email_resp = await EmailService.send_welcome_email(welcome_data)
        if not email_resp.success:
            logger.error(f"Failed to send welcome email to {user.email}: {email_resp.error}")

    response_data: dict = {
        "user_id": str(user.id),
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "user_type": user.user_type,
    }
    if settings.ENVIRONMENT == "development":
        response_data["temp_password"] = temp_password

    return ResponseModel(
        success=True,
        message="Staff registered successfully. Login credentials sent to email.",
        data=response_data,
    )


# Password Reset Flow 

@router.post("/forgot-password", response_model=ResponseModel)
async def forgot_password(
    req: ForgotPasswordRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Request a password reset email. Always returns 200 (security — no user enumeration).
    Development: includes the reset token in the response.
    """
    user_exists, data = await AuthService.request_password_reset(
        req.email, session, _request_meta(request)
    )

    if user_exists and data:
        reset_email = PasswordResetEmailData(
            email=data["email"],
            first_name=data["first_name"], # type: ignore
            reset_token=data["reset_token"],
            expires_at=data["expires_at"],
        ) # type: ignore
        resp = await EmailService.send_password_reset_email(reset_email)
        if not resp.success:
            logger.error(f"Failed to send password reset email: {resp.error}")

    response_data = None
    if settings.ENVIRONMENT == "development" and user_exists and data:
        response_data = {"reset_token": data["reset_token"]}

    return ResponseModel(
        success=True,
        message="If that email is registered, a reset link has been sent.",
        data=response_data,
    )


@router.get("/validate-reset-token", response_model=ResponseModel)
async def validate_reset_token(
    token: str,
    session: Session = Depends(get_session),
):
    """Check if a password reset token is valid and not expired."""
    is_valid = await AuthService.validate_reset_token(token, session)
    return ResponseModel(
        success=is_valid,
        message="Token is valid" if is_valid else "Invalid or expired token",
        data={"valid": is_valid},
    )


@router.post("/reset-password", response_model=ResponseModel)
async def reset_password(
    req: ResetPasswordRequest,
    session: Session = Depends(get_session),
):
    """
    Reset password using the token received by email.
    Unlocks account, resets failed attempts, invalidates all existing tokens.
    """
    user = await AuthService.reset_password(req.token, req.new_password, session)

    # Send confirmation email
    if user.email and user.first_name:
        changed_data = PasswordChangedEmailData(
            email=user.email,
            first_name=user.first_name or "User", # type: ignore
            changed_at=datetime.utcnow(),
        ) # type: ignore 
        resp = await EmailService.send_password_changed_email(changed_data)
        if not resp.success:
            logger.error(f"Failed to send password changed email: {resp.error}")

    return ResponseModel(success=True, message="Password reset successfully. Please log in.")


# Change Password (authenticated) 

@router.post("/change-password", response_model=ResponseModel)
async def change_password(
    req: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Change password for the currently authenticated user."""
    await AuthService.change_password(
        current_user, req.current_password, req.new_password, session
    )

    # Send confirmation email
    if current_user.email and current_user.first_name:
        changed_data = PasswordChangedEmailData(
            email=current_user.email,
            first_name=current_user.first_name or "User", # type: ignore
            changed_at=datetime.utcnow(),
        ) # type: ignore
        await EmailService.send_password_changed_email(changed_data)

    return ResponseModel(success=True, message="Password changed. Please log in again.")


# Current user

@router.get("/me", response_model=ResponseModel)
async def me(
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    """Return current authenticated user info with tenant/store/role context."""
    from src.auth.services import AuthService
    jwt_ctx = AuthService._build_jwt_context(ctx.user, session)
    user_info = AuthService._build_user_info(ctx.user, jwt_ctx)
    return ResponseModel(success=True, data=user_info.model_dump())


# Role assignment (tenant-admin) 

@router.post(
    "/roles/assign",
    response_model=ResponseModel,
    dependencies=[Depends(require_tenant_admin())],
)
async def assign_role(
    req: AssignRoleRequest,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    """
    Assign a role to a user within the current tenant (and optionally a specific store).
    Requires TENANT_ADMIN or SUPER_ADMIN.
    """
    tenant_id = ctx.require_tenant()
    user_role = await AuthService.assign_role(req, tenant_id, ctx.user.id, session)
    return ResponseModel(
        success=True,
        message="Role assigned successfully",
        data={
            "user_id": str(user_role.user_id),
            "role_id": str(user_role.role_id),
            "tenant_id": str(user_role.tenant_id),
            "store_id": str(user_role.store_id) if user_role.store_id else None,
            "assigned_at": user_role.assigned_at.isoformat() if user_role.assigned_at else None,
        },
    )


@router.delete(
    "/roles/revoke",
    response_model=ResponseModel,
    dependencies=[Depends(require_tenant_admin())],
)
async def revoke_role(
    user_id: UUID,
    role_name: str,
    store_id: Optional[UUID] = None,
    ctx: TenantContext = Depends(),
    session: Session = Depends(get_session),
):
    """Revoke a role from a user within the current tenant."""
    tenant_id = ctx.require_tenant()
    await AuthService.revoke_role(user_id, role_name, tenant_id, store_id, session)
    return ResponseModel(success=True, message="Role revoked successfully")