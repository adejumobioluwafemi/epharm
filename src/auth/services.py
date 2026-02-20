"""
FILE: src/auth/services.py
Authentication business logic - Updated to support email/username login
"""
from sqlmodel import Session, select, func, or_
from sqlalchemy import and_
from src.shared.models import (
    Useraccount, Userprofile, PasswordResetToken,
    Address, Userregion, Lga, Region
)
from src.shared.schemas import (
    LoginRequest, UserCreate,
    ForgotPasswordRequest, ResetPasswordRequest
)
from src.core.security import (
    simple_encrypt, simple_decrypt, generate_salt,
    create_access_token, generate_reset_token, generate_default_password
)
from src.core.config import settings
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from typing import Optional, List, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class AuthService:
    """Authentication service - handles all auth business logic"""
    
    # LOGIN & LOGOUT
    @staticmethod
    async def authenticate_user(
        credentials: LoginRequest,
        session: Session
    ) -> Dict[str, Any]:
        """
        Authenticate user and return token with user info
        
        Supports login with either username OR email
        
        Returns:
            Dict with token and user data
            
        Raises:
            HTTPException: On authentication failure
        """
        # Find user by username OR email
        # Check if input looks like an email (contains @)
        login_identifier = credentials.username
        is_email = '@' in login_identifier
        
        if is_email:
            # Search by email
            user = session.exec(
                select(Useraccount).where(Useraccount.email == login_identifier)
            ).first()
            logger.info(f"Login attempt with email: {login_identifier}")
        else:
            # Search by username
            user = session.exec(
                select(Useraccount).where(Useraccount.username == login_identifier)
            ).first()
            logger.info(f"Login attempt with username: {login_identifier}")
        
        if not user:
            logger.warning(f"Login attempt - invalid credential: {login_identifier}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username/email or password"
            )
        
        # Check account locked
        if user.islocked:
            logger.warning(f"Login attempt - locked account: {login_identifier}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is locked. Contact administrator."
            )
        
        # Check account status
        if user.status != 1:
            logger.warning(f"Login attempt - inactive account: {login_identifier}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is disabled"
            )
        
        # Verify password
        if not user.passwordhash or not user.salt:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username/email or password"
            )
        
        try:
            decrypted_password = simple_decrypt(user.passwordhash, user.salt)
            
            if credentials.password != decrypted_password:
                # Increment failed attempts
                user.failedloginattempt = (user.failedloginattempt or 0) + 1
                
                # Lock after 5 failed attempts
                if user.failedloginattempt >= 5:
                    user.islocked = True
                    session.add(user)
                    session.commit()
                    logger.warning(f"Account locked - too many failed attempts: {login_identifier}")
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Account locked due to multiple failed login attempts"
                    )
                
                session.add(user)
                session.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username/email or password"
                )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username/email or password"
            )
        
        # Get profile
        profile = session.exec(
            select(Userprofile).where(Userprofile.userid == user.userid)
        ).first()
        
        # Generate JWT
        token_data = {
            "UserId": user.userid,
            "UserName": user.username,
            "UserStatus": user.status,
            "Email": user.email
        }
        access_token = create_access_token(data=token_data)
        
        # Update login info
        user.logincount = (user.logincount or 0) + 1
        user.apitoken = access_token
        user.isactive = True
        user.lastlogindate = datetime.utcnow().date()
        user.failedloginattempt = 0
        user.updatedat = datetime.utcnow()
        
        session.add(user)
        session.commit()
        
        logger.info(f"Successful login: {user.username} (via {('email' if is_email else 'username')})")
        
        return {
            "token": access_token,
            "user": {
                "userid": user.userid,
                "username": user.username,
                "email": user.email,
                "firstname": profile.firstname if profile else None,
                "lastname": profile.lastname if profile else None,
                "roleid": profile.roleid if profile else None,
                "lgaid": user.lgaid
            }
        }
    
    @staticmethod
    async def logout_user(user: Useraccount, session: Session) -> None:
        """Logout user - clear token and set inactive"""
        user.apitoken = None
        user.isactive = False
        user.updatedat = datetime.utcnow()
        
        session.add(user)
        session.commit()
        
        logger.info(f"User logged out: {user.username}")
    
    # PASSWORD RESET
    @staticmethod
    async def request_password_reset(
        email: str,
        session: Session
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Request password reset
        
        Returns:
            (user_exists, email_data_if_exists)
        """
        user = session.exec(
            select(Useraccount).where(Useraccount.email == email)
        ).first()
        
        if not user or user.status != 1:
            logger.info(f"Password reset - non-existent/inactive email: {email}")
            return (False, None)
        
        # Get profile
        profile = session.exec(
            select(Userprofile).where(Userprofile.userid == user.userid)
        ).first()
        
        # Generate token
        reset_token = generate_reset_token()
        expires_at = datetime.utcnow() + timedelta(hours=settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS)
        
        # Invalidate old tokens
        old_tokens = session.exec(
            select(PasswordResetToken).where(
                and_(
                    PasswordResetToken.userid == user.userid, # type: ignore
                    PasswordResetToken.isused == False # type: ignore
                )
            )
        ).all()
        
        for old_token in old_tokens:
            old_token.isused = True
            old_token.updatedat = datetime.utcnow()
            session.add(old_token)
        
        # Create new token
        token_record = PasswordResetToken(
            userid=user.userid,
            token=reset_token,
            expiresat=expires_at,
            isused=False,
            createdat=datetime.utcnow()
        )
        session.add(token_record)
        
        # Update user
        user.passwordresettoken = reset_token
        user.passwordresettokenexpires = expires_at
        user.updatedat = datetime.utcnow()
        session.add(user)
        
        session.commit()
        
        logger.info(f"Password reset token generated for: {email}")
        
        # Return email data
        email_data = {
            "email": email,
            "username": user.username,
            "firstname": profile.firstname if profile else "User",
            "reset_token": reset_token,
            "expires_at": expires_at
        }
        
        return (True, email_data)
    
    @staticmethod
    async def reset_password(
        token: str,
        new_password: str,
        session: Session
    ) -> None:
        """Reset password using token"""
        # Find valid token
        token_record = session.exec(
            select(PasswordResetToken).where(
                and_(
                    PasswordResetToken.token == token, # type: ignore
                    PasswordResetToken.isused == False, # type: ignore
                    PasswordResetToken.expiresat > datetime.utcnow() # type: ignore
                )
            )
        ).first()
        
        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired token"
            )
        
        # Get user
        user = session.get(Useraccount, token_record.userid)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Update password
        salt = generate_salt()
        encrypted_password = simple_encrypt(new_password, salt)
        
        user.salt = salt
        user.passwordhash = encrypted_password
        user.lastpasswordreset = datetime.utcnow()
        user.passwordresettoken = None
        user.passwordresettokenexpires = None
        user.updatedat = datetime.utcnow()
        user.failedloginattempt = 0
        user.islocked = False
        
        # Mark token used
        token_record.isused = True
        token_record.usedat = datetime.utcnow()
        token_record.updatedat = datetime.utcnow()
        
        session.add(user)
        session.add(token_record)
        session.commit()
        
        logger.info(f"Password reset successful for: {user.username}")
    
    @staticmethod
    async def validate_reset_token(token: str, session: Session) -> bool:
        """Check if reset token is valid"""
        token_record = session.exec(
            select(PasswordResetToken).where(
                and_(
                    PasswordResetToken.token == token, # type: ignore
                    PasswordResetToken.isused == False, # type: ignore
                    PasswordResetToken.expiresat > datetime.utcnow() # type: ignore
                )
            )
        ).first()
        
        return token_record is not None
    
    # USER MANAGEMENT (ADMIN)
    @staticmethod
    async def create_user(
        user_data: UserCreate,
        session: Session
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Create new user (extension officer)
        
        Returns:
            (user_info, email_data)
        """
        # Generate username from email
        username = user_data.emailAddress.split('@')[0]
        
        # Check username exists
        if session.exec(select(Useraccount).where(Useraccount.username == username)).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        
        # Check email exists
        if session.exec(select(Useraccount).where(Useraccount.email == user_data.emailAddress)).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already exists"
            )
        
        # Validate LGA
        lga = session.get(Lga, user_data.lgaid)
        if not lga or lga.deletedat:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"LGA with ID {user_data.lgaid} not found"
            )
        
        # Validate region
        region = session.get(Region, user_data.regionid)
        if not region or region.deletedat:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Region with ID {user_data.regionid} not found"
            )
        
        # Generate temp password
        temp_password = generate_default_password()
        salt = generate_salt()
        encrypted_password = simple_encrypt(temp_password, salt)
        
        # Create user account
        new_user = Useraccount(
            username=username,
            email=user_data.emailAddress,
            passwordhash=encrypted_password,
            salt=salt,
            status=1,
            isactive=False,
            islocked=False,
            logincount=0,
            failedloginattempt=0,
            lgaid=user_data.lgaid,
            createdat=datetime.utcnow()
        )
        session.add(new_user)
        session.flush()
        
        # Create profile
        new_profile = Userprofile(
            userid=new_user.userid,
            firstname=user_data.firstname,
            middlename=user_data.middlename,
            lastname=user_data.lastname,
            gender=user_data.gender,
            email=user_data.emailAddress,
            phonenumber=user_data.phonenumber,
            lgaid=user_data.lgaid,
            createdat=datetime.utcnow()
        )
        session.add(new_profile)
        
        # Create address
        new_address = Address(
            userid=new_user.userid,
            streetaddress=user_data.streetaddress,
            town=user_data.town,
            postalcode=user_data.postalcode,
            lgaid=user_data.lgaid,
            latitude=user_data.latitude,
            longitude=user_data.longitude,
            createdat=datetime.utcnow()
        )
        session.add(new_address)
        
        # Create user-region
        user_region = Userregion(
            userid=new_user.userid,
            regionid=user_data.regionid,
            createdat=datetime.utcnow()
        )
        session.add(user_region)
        
        session.commit()
        session.refresh(new_user)
        
        logger.info(f"New user created: {username}")
        
        # User info
        user_info = {
            "userid": new_user.userid,
            "username": username,
            "email": user_data.emailAddress
        }
        
        # Email data
        email_data = {
            "email": user_data.emailAddress,
            "firstname": user_data.firstname,
            "lastname": user_data.lastname,
            "username": username,
            "temp_password": temp_password,
            "lga_name": lga.lganame
        }
        
        return (user_info, email_data)
    
    @staticmethod
    async def get_all_users(
        session: Session,
        skip: int = 0,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get all users with profiles"""
        users = session.exec(
            select(Useraccount).where(Useraccount.deletedat == None).offset(skip).limit(limit)
        ).all()
        
        result = []
        for user in users:
            profile = session.exec(
                select(Userprofile).where(Userprofile.userid == user.userid)
            ).first()
            
            result.append({
                "userid": user.userid,
                "username": user.username,
                "email": user.email,
                "status": user.status,
                "isactive": user.isactive,
                "islocked": user.islocked,
                "firstname": profile.firstname if profile else None,
                "lastname": profile.lastname if profile else None,
                "phonenumber": profile.phonenumber if profile else None,
                "lgaid": user.lgaid,
                "logincount": user.logincount,
                "lastlogindate": user.lastlogindate
            })
        
        return result
    
    @staticmethod
    async def get_user_by_id(user_id: int, session: Session) -> Dict[str, Any]:
        """Get user details by ID"""
        user = session.get(Useraccount, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        profile = session.exec(
            select(Userprofile).where(Userprofile.userid == user_id)
        ).first()
        
        address = session.exec(
            select(Address).where(Address.userid == user_id)
        ).first()
        
        user_region = session.exec(
            select(Userregion).where(Userregion.userid == user_id)
        ).first()
        
        return {
            "userid": user.userid,
            "username": user.username,
            "email": user.email,
            "status": user.status,
            "isactive": user.isactive,
            "islocked": user.islocked,
            "firstname": profile.firstname if profile else None,
            "lastname": profile.lastname if profile else None,
            "middlename": profile.middlename if profile else None,
            "gender": profile.gender if profile else None,
            "phonenumber": profile.phonenumber if profile else None,
            "designation": profile.designation if profile else None,
            "lgaid": user.lgaid,
            "regionid": user_region.regionid if user_region else None,
            "streetaddress": address.streetaddress if address else None,
            "town": address.town if address else None,
            "postalcode": address.postalcode if address else None,
            "latitude": address.latitude if address else None,
            "longitude": address.longitude if address else None,
            "logincount": user.logincount,
            "lastlogindate": user.lastlogindate,
            "createdat": user.createdat
        }