"""
FILE: src/core/dependencies.py
FastAPI dependencies for authentication and authorization
"""
from fastapi import Depends, HTTPException, status, Header, Request
from sqlmodel import Session, select
from typing import Optional
from src.core.database import get_session
from src.core.security import decode_access_token
from src.shared.models import Useraccount, Userprofile
import logging

logger = logging.getLogger(__name__)


async def get_current_user(
    authorization: Optional[str] = Header(None),
    session: Session = Depends(get_session)
) -> Useraccount:
    """
    Get current authenticated user from JWT token
    
    Validates token and returns user object
    Raises 401 if token is invalid or user not found
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme"
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format"
        )
    
    token_data = decode_access_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    
    user_id = token_data.get("UserId")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    user = session.get(Useraccount, user_id)
    if not user or user.status != 1 or user.islocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not accessible"
        )
    
    if user.apitoken != token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked"
        )
    
    return user


async def get_current_active_user(
    current_user: Useraccount = Depends(get_current_user)
) -> Useraccount:
    """
    Get current active user
    
    Additional check for user activity status
    """
    if not current_user.isactive:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not active"
        )
    
    return current_user


async def get_current_user_profile(
    current_user: Useraccount = Depends(get_current_user),
    session: Session = Depends(get_session)
) -> Optional[Userprofile]:
    """
    Get current user's profile
    
    Returns user profile or None if not found
    """
    statement = select(Userprofile).where(Userprofile.userid == current_user.userid)
    profile = session.exec(statement).first()
    
    return profile


def require_role(required_role_id: int):
    """
    Dependency factory for role-based access control
    
    Usage:
        @router.get("/admin-only", dependencies=[Depends(require_role(1))])
    """
    async def role_checker(
        current_user: Useraccount = Depends(get_current_user),
        session: Session = Depends(get_session)
    ):
        # Get user profile to check role
        statement = select(Userprofile).where(Userprofile.userid == current_user.userid)
        profile = session.exec(statement).first()
        
        if not profile or profile.roleid != required_role_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        return current_user
    
    return role_checker


def require_admin():
    """
    Require admin role (roleid = 1)
    
    Usage:
        @router.post("/create", dependencies=[Depends(require_admin())])
    """
    return require_role(1)


def require_officer():
    """
    Require extension officer role (roleid = 2)
    
    Usage:
        @router.post("/farmer", dependencies=[Depends(require_officer())])
    """
    return require_role(2)


async def get_optional_current_user(
    authorization: Optional[str] = Header(None),
    session: Session = Depends(get_session)
) -> Optional[Useraccount]:
    """
    Get current user if authenticated, None otherwise
    
    Useful for endpoints that work both authenticated and unauthenticated
    """
    try:
        if not authorization:
            return None
        
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            return None
        
        token_data = decode_access_token(token)
        if not token_data:
            return None
        
        user_id = token_data.get("UserId")
        if not user_id:
            return None
        
        user = session.get(Useraccount, user_id)
        if not user or user.status != 1 or user.islocked:
            return None
        
        return user
    except Exception:
        return None


def pagination_params(
    skip: int = 0,
    limit: int = 100
) -> dict:
    """
    Common pagination parameters
    
    Usage:
        @router.get("/list")
        async def get_list(pagination: dict = Depends(pagination_params)):
            skip = pagination["skip"]
            limit = pagination["limit"]
    """
    if skip < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Skip must be >= 0"
        )
    
    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Limit must be between 1 and 1000"
        )
    
    return {"skip": skip, "limit": limit}


class CurrentUserInfo:
    """
    Helper class to get current user information
    
    Usage:
        @router.get("/me")
        async def get_me(user_info: CurrentUserInfo = Depends()):
            return {
                "user_id": user_info.user_id,
                "is_admin": user_info.is_admin()
            }
    """
    def __init__(
        self,
        current_user: Useraccount = Depends(get_current_user),
        session: Session = Depends(get_session)
    ):
        self.user = current_user
        self.session = session
        self._profile = None
    
    @property
    def user_id(self) -> int:
        """Get user ID"""
        return self.user.userid  # type: ignore
    
    @property
    def username(self) -> str:
        """Get username"""
        return self.user.username  # type: ignore
    
    @property
    def email(self) -> Optional[str]:
        """Get email"""
        return self.user.email
    
    @property
    def profile(self) -> Optional[Userprofile]:
        """Get user profile (cached)"""
        if self._profile is None:
            statement = select(Userprofile).where(
                Userprofile.userid == self.user.userid
            )
            self._profile = self.session.exec(statement).first()
        
        return self._profile
    
    @property
    def role_id(self) -> Optional[int]:
        """Get role ID from profile"""
        profile = self.profile
        return profile.roleid if profile else None
    
    @property
    def lga_id(self) -> Optional[int]:
        """Get LGA ID"""
        return self.user.lgaid
    
    @property
    def firstname(self) -> Optional[str]:
        """Get first name from profile"""
        profile = self.profile
        return profile.firstname if profile else None
    
    @property
    def lastname(self) -> Optional[str]:
        """Get last name from profile"""
        profile = self.profile
        return profile.lastname if profile else None
    
    @property
    def fullname(self) -> str:
        """Get full name"""
        profile = self.profile
        if profile:
            parts = []
            if profile.firstname:
                parts.append(profile.firstname)
            if profile.middlename:
                parts.append(profile.middlename)
            if profile.lastname:
                parts.append(profile.lastname)
            return " ".join(parts) if parts else self.username
        return self.username
    
    def is_admin(self) -> bool:
        """Check if user is admin (roleid = 1)"""
        return self.role_id == 1
    
    def is_officer(self) -> bool:
        """Check if user is extension officer (roleid = 2)"""
        return self.role_id == 2
    
    def has_role(self, role_id: int) -> bool:
        """Check if user has specific role"""
        return self.role_id == role_id
    
    def can_access_lga(self, lga_id: int) -> bool:
        """Check if user can access specific LGA"""
        # Admin can access all LGAs
        if self.is_admin():
            return True
        
        # Officers can only access their assigned LGA
        return self.lga_id == lga_id
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "fullname": self.fullname,
            "role_id": self.role_id,
            "lga_id": self.lga_id,
            "is_admin": self.is_admin(),
            "is_officer": self.is_officer()
        }


def get_user_from_request(request: Request) -> Optional[Useraccount]:
    """
    Extract user from request state (if set by middleware)
    
    Usage in middleware:
        request.state.user = current_user
    """
    return getattr(request.state, "user", None)


async def verify_resource_access(
    resource_lga_id: Optional[int],
    current_user: Useraccount = Depends(get_current_user),
    session: Session = Depends(get_session)
) -> bool:
    """
    Verify if user can access a resource based on LGA
    
    Args:
        resource_lga_id: LGA ID of the resource
        current_user: Current authenticated user
        session: Database session
        
    Returns:
        bool: True if access is allowed
        
    Raises:
        HTTPException: If access is denied
    """
    # Get user profile
    statement = select(Userprofile).where(Userprofile.userid == current_user.userid)
    profile = session.exec(statement).first()
    
    # Admin has access to all resources
    if profile and profile.roleid == 1:
        return True
    
    # Officers can only access resources in their LGA
    if resource_lga_id and current_user.lgaid != resource_lga_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to resources in this LGA"
        )
    
    return True