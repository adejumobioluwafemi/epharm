"""
FILE: src/auth/router.py
Authentication endpoints with complete email service integration
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import Session, select
from datetime import datetime
from src.core.database import get_session
from src.core.dependencies import get_current_user
from src.shared.models import Useraccount
from src.shared.schemas import (
    LoginRequest, ResponseModel,
    ForgotPasswordRequest, ResetPasswordRequest,
    UserCreate, UserResponse, UserListResponse
)
from src.auth.services import AuthService
from src.core.config import settings
from src.email.service import EmailService
from src.email.schemas import (
    WelcomeEmailData,
    PasswordResetEmailData,
    PasswordChangedEmailData,
    AccountLockedEmailData
)
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])

class ChangePasswordRequest(BaseModel):
    """Schema for password change request"""
    currentPassword: str
    newPassword: str



@router.post("/login", response_model=ResponseModel)
async def login(
    credentials: LoginRequest,
    session: Session = Depends(get_session)
):
    """
    User login endpoint
    
    **Request Body:**
    - username: User's username
    - password: User's password
    
    **Returns:**
    - JWT token
    - User information
    
    **Security:**
    - Account locks after 5 failed attempts
    - Checks account status (active/locked/disabled)
    - Sends email notification on account lock
    """
    try:
        result = await AuthService.authenticate_user(credentials, session)
        
        return ResponseModel(
            success=True,
            message="Login successful",
            data=result,
            tag=1
        )
    except HTTPException as e:
        # Check if account was just locked (403 status with "locked" in message)
        if e.status_code == 403 and "locked" in e.detail.lower():
            # Get user to send lock notification
            user = session.exec(
                select(Useraccount).where(Useraccount.username == credentials.username)
            ).first()
            
            if user:
                from sqlmodel import select as sql_select
                from src.shared.models import Userprofile
                
                profile = session.exec(
                    sql_select(Userprofile).where(Userprofile.userid == user.userid)
                ).first()
                
                # Send account locked email
                if profile and user.email:
                    lock_email_data = AccountLockedEmailData(
                        email=user.email,
                        username=user.username or "User",
                        firstname=profile.firstname or "User",
                        locked_at=datetime.utcnow(),
                        reason="Multiple failed login attempts"
                    )
                    
                    email_response = await EmailService.send_account_locked_email(lock_email_data)
                    if not email_response.success:
                        logger.error(f"Failed to send account locked email: {email_response.error}")
        
        raise


@router.post("/logout", response_model=ResponseModel)
async def logout(
    current_user: Useraccount = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    User logout endpoint
    
    **Requires:** Valid JWT token in Authorization header
    
    **Action:**
    - Clears API token
    - Sets user as inactive
    """
    await AuthService.logout_user(current_user, session)
    
    return ResponseModel(
        success=True,
        message="Logged out successfully",
        tag=1
    )


# ============================================================================
# PASSWORD RESET ENDPOINTS
# ============================================================================

@router.post("/forgot-password", response_model=ResponseModel)
async def forgot_password(
    request: ForgotPasswordRequest,
    session: Session = Depends(get_session)
):
    """
    Request password reset with email notification
    
    **Request Body:**
    - email: User's email address
    
    **Returns:**
    - Success message (always returns success for security)
    - Reset token (only in development mode)
    
    **Security:**
    - Does not reveal if email exists
    - Generates secure reset token
    - Token expires in 24 hours
    - Email sent with reset link
    """
    user_exists, email_data = await AuthService.request_password_reset(
        request.email,
        session
    )
    
    # Send email if user exists
    if user_exists and email_data:
        reset_email_data = PasswordResetEmailData(
            email=email_data["email"],
            username=email_data["username"],
            firstname=email_data["firstname"],
            reset_token=email_data["reset_token"],
            expires_at=email_data["expires_at"]
        )
        
        # Send password reset email
        email_response = await EmailService.send_password_reset_email(reset_email_data)
        
        if not email_response.success:
            logger.error(f"Failed to send password reset email: {email_response.error}")
        else:
            logger.info(f"Password reset email sent to: {email_data['email']}")
    
    # Always return success (security best practice)
    response_data = None
    if user_exists and settings.ENVIRONMENT == "development" and email_data:
        # Only show token in development
        response_data = {"token": email_data["reset_token"]}
    
    return ResponseModel(
        success=True,
        message="If email exists, reset link has been sent",
        data=response_data,
        tag=1
    )


@router.post("/reset-password", response_model=ResponseModel)
async def reset_password(
    request: ResetPasswordRequest,
    session: Session = Depends(get_session)
):
    """
    Reset password using token with confirmation email
    
    **Request Body:**
    - token: Reset token from email
    - newPassword: New password (min 6 characters)
    - confirmPassword: Password confirmation
    
    **Validation:**
    - Token must be valid and not expired
    - Passwords must match
    - Password strength requirements
    
    **Action:**
    - Updates password
    - Unlocks account if locked
    - Resets failed login attempts
    - Invalidates reset token
    - Sends confirmation email
    """
    # Get user info before password reset
    from sqlmodel import select as sql_select
    from src.shared.models import PasswordResetToken, Userprofile
    
    # Find token to get user
    token_record = session.exec(
        sql_select(PasswordResetToken).where(
            PasswordResetToken.token == request.token,
            PasswordResetToken.isused == False,
            PasswordResetToken.expiresat > datetime.utcnow() # type: ignore
        )
    ).first()
    
    user_email = None
    user_username = None
    user_firstname = None
    
    if token_record:
        user = session.get(Useraccount, token_record.userid)
        if user:
            user_email = user.email
            user_username = user.username
            
            profile = session.exec(
                sql_select(Userprofile).where(Userprofile.userid == user.userid)
            ).first()
            if profile:
                user_firstname = profile.firstname
    
    # Reset password
    await AuthService.reset_password(
        request.token,
        request.newPassword,
        session
    )
    
    # Send password changed confirmation email
    if user_email and user_username and user_firstname:
        changed_email_data = PasswordChangedEmailData(
            email=user_email,
            username=user_username,
            firstname=user_firstname,
            changed_at=datetime.utcnow()
        )
        
        email_response = await EmailService.send_password_changed_email(changed_email_data)
        
        if not email_response.success:
            logger.error(f"Failed to send password changed email: {email_response.error}")
        else:
            logger.info(f"Password changed confirmation sent to: {user_email}")
    
    return ResponseModel(
        success=True,
        message="Password reset successfully",
        tag=1
    )


@router.get("/validate-reset-token", response_model=ResponseModel)
async def validate_reset_token(
    token: str,
    session: Session = Depends(get_session)
):
    """
    Validate password reset token
    
    **Query Parameter:**
    - token: Reset token to validate
    
    **Returns:**
    - valid: true/false
    """
    is_valid = await AuthService.validate_reset_token(token, session)
    
    return ResponseModel(
        success=is_valid,
        message="Token is valid" if is_valid else "Invalid or expired token",
        data={"valid": is_valid},
        tag=1 if is_valid else 0
    )


# USER REGISTRATION ENDPOINT (Admin only)
@router.post("/register", response_model=ResponseModel)
async def register_user(
    user_data: UserCreate,
    current_user: Useraccount = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Register new user (extension officer) with welcome email
    
    **Requires:** Admin authentication
    
    **Request Body:**
    - firstname, lastname, middlename
    - gender
    - emailAddress (used to generate username)
    - phonenumber (11 digits)
    - lgaid, regionid
    - streetaddress, town, postalcode
    - latitude, longitude (optional)
    
    **Action:**
    - Creates user account with temporary password
    - Creates user profile
    - Creates address record
    - Creates user-region association
    - Sends welcome email with credentials
    
    **Returns:**
    - User information
    - Temporary password (development only)
    """
    user_info, email_data = await AuthService.create_user(user_data, session)
    
    # Send welcome email
    welcome_email_data = WelcomeEmailData(
        email=email_data["email"],
        firstname=email_data["firstname"],
        lastname=email_data["lastname"],
        username=email_data["username"],
        temp_password=email_data["temp_password"],
        lga_name=email_data.get("lga_name")
    )
    
    email_response = await EmailService.send_welcome_email(welcome_email_data)
    
    if not email_response.success:
        logger.error(f"Failed to send welcome email: {email_response.error}")
    else:
        logger.info(f"Welcome email sent to: {email_data['email']}")
    
    # Prepare response
    response_data = user_info.copy()
    if settings.ENVIRONMENT == "development":
        response_data["temp_password"] = email_data["temp_password"]
        response_data["email_sent"] = email_response.success
    
    return ResponseModel(
        success=True,
        message="User registered successfully. Login credentials sent to email.",
        data=response_data,
        tag=1
    )


@router.get("/officers", response_model=UserListResponse)
async def get_officers(
    current_user: Useraccount = Depends(get_current_user),
    session: Session = Depends(get_session),
    skip: int = 0,
    limit: int = 100
):
    """
    Get list of all registered officers
    
    **Requires:** Authentication
    
    **Query Parameters:**
    - skip: Pagination offset (default: 0)
    - limit: Results limit (default: 100)
    
    **Returns:**
    - List of users with profiles
    - Farmer registration counts
    """
    users = await AuthService.get_all_users(session, skip=skip, limit=limit)
    
    return UserListResponse(
        success=True,
        message="Officers retrieved successfully",
        data=users,
        tag=1,
        total=len(users)
    )


@router.get("/officers/{user_id}", response_model=UserResponse)
async def get_officer(
    user_id: int,
    current_user: Useraccount = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Get specific officer details
    
    **Requires:** Authentication
    
    **Path Parameter:**
    - user_id: User ID to retrieve
    
    **Returns:**
    - Complete user information
    - Profile details
    - Address information
    - Statistics (farmers registered)
    """
    officer_data = await AuthService.get_user_by_id(user_id, session)
    
    return UserResponse(
        success=True,
        message="Officer retrieved successfully",
        data=officer_data,
        tag=1
    )


# ============================================================================
# ACCOUNT MANAGEMENT ENDPOINTS
# ============================================================================

@router.post("/change-password", response_model=ResponseModel)
async def change_password(
    request: ChangePasswordRequest,
    current_user: Useraccount = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Change password for authenticated user with confirmation email"""
    from src.core.security import simple_decrypt, simple_encrypt, generate_salt
    from sqlmodel import select as sql_select
    from src.shared.models import Userprofile
    
    # Verify current password
    if not current_user.passwordhash or not current_user.salt:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password not set"
        )
    
    try:
        decrypted = simple_decrypt(current_user.passwordhash, current_user.salt)
        if request.currentPassword != decrypted:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect"
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )
    
    # Update password
    salt = generate_salt()
    encrypted_password = simple_encrypt(request.newPassword, salt)
    
    current_user.salt = salt
    current_user.passwordhash = encrypted_password
    current_user.lastpasswordreset = datetime.utcnow()
    current_user.updatedat = datetime.utcnow()
    
    session.add(current_user)
    session.commit()
    
    logger.info(f"Password changed for user: {current_user.username}")
    
    # Send confirmation email
    if current_user.email and current_user.username:
        profile = session.exec(
            sql_select(Userprofile).where(Userprofile.userid == current_user.userid)
        ).first()
        
        if profile:
            changed_email_data = PasswordChangedEmailData(
                email=current_user.email,
                username=current_user.username,
                firstname=profile.firstname or "User",
                changed_at=datetime.utcnow()
            )
            
            email_response = await EmailService.send_password_changed_email(changed_email_data)
            
            if not email_response.success:
                logger.error(f"Failed to send password changed email: {email_response.error}")
            else:
                logger.info(f"Password changed confirmation sent to: {current_user.email}")
    
    return ResponseModel(
        success=True,
        message="Password changed successfully",
        tag=1
    )


@router.get("/me", response_model=ResponseModel)
async def get_current_user_info(
    current_user: Useraccount = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Get current authenticated user information
    
    **Requires:** Authentication
    
    **Returns:**
    - Current user profile
    - Statistics
    """
    user_data = await AuthService.get_user_by_id(current_user.userid, session) # type: ignore
    
    return ResponseModel(
        success=True,
        data=user_data,
        tag=1
    )


# ============================================================================
# ADMIN ENDPOINTS
# ============================================================================

@router.post("/lock-account/{user_id}", response_model=ResponseModel)
async def lock_account(
    user_id: int,
    current_user: Useraccount = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Lock user account (Admin only) with email notification
    
    **Requires:** Admin authentication
    
    **Path Parameter:**
    - user_id: User ID to lock
    
    **Action:**
    - Locks the account
    - Sends notification email to user
    """
    from sqlmodel import select as sql_select
    from src.shared.models import Userprofile
    
    # TODO: Add role-based authorization check
    
    user = session.get(Useraccount, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.islocked = True
    user.updatedat = datetime.utcnow()
    
    session.add(user)
    session.commit()
    
    logger.info(f"Account locked by admin - User ID: {user_id}")
    
    # Send account locked email
    if user.email and user.username:
        profile = session.exec(
            sql_select(Userprofile).where(Userprofile.userid == user_id)
        ).first()
        
        if profile:
            lock_email_data = AccountLockedEmailData(
                email=user.email,
                username=user.username,
                firstname=profile.firstname or "User",
                locked_at=datetime.utcnow(),
                reason="Account locked by administrator"
            )
            
            email_response = await EmailService.send_account_locked_email(lock_email_data)
            
            if not email_response.success:
                logger.error(f"Failed to send account locked email: {email_response.error}")
            else:
                logger.info(f"Account locked notification sent to: {user.email}")
    
    return ResponseModel(
        success=True,
        message="Account locked successfully",
        tag=1
    )


@router.post("/unlock-account/{user_id}", response_model=ResponseModel)
async def unlock_account(
    user_id: int,
    current_user: Useraccount = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Unlock user account (Admin only)
    
    **Requires:** Admin authentication
    
    **Path Parameter:**
    - user_id: User ID to unlock
    """
    # TODO: Add role-based authorization check
    
    user = session.get(Useraccount, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.islocked = False
    user.failedloginattempt = 0
    user.updatedat = datetime.utcnow()
    
    session.add(user)
    session.commit()
    
    logger.info(f"Account unlocked by admin - User ID: {user_id}")
    
    return ResponseModel(
        success=True,
        message="Account unlocked successfully",
        tag=1
    )