"""
FILE: src/shared/schemas.py
Pydantic schemas for requests/responses
"""
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, Any, List
from datetime import date, datetime
from decimal import Decimal

class ResponseModel(BaseModel):
    """Standard response wrapper"""
    success: bool
    message: Optional[str] = None
    data: Optional[Any] = None
    tag: int = 1
    total: Optional[int] = None


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=1)
    newPassword: str = Field(..., min_length=6)
    confirmPassword: str = Field(..., min_length=1)
    
    @validator('confirmPassword')
    def passwords_match(cls, v, values):
        if 'newPassword' in values and v != values['newPassword']:
            raise ValueError('Passwords do not match')
        return v

class UserCreate(BaseModel):
    """Schema for creating new user (officer registration)"""
    firstname: str = Field(..., min_length=2, max_length=100)
    lastname: str = Field(..., min_length=2, max_length=100)
    middlename: Optional[str] = Field(None, max_length=100)
    gender: Optional[str] = Field(None, pattern="^(Male|Female|Other)$")
    emailAddress: EmailStr
    phonenumber: str = Field(..., pattern="^[0-9]{11}$")
    lgaid: int = Field(..., gt=0)
    regionid: int = Field(..., gt=0)
    streetaddress: str = Field(..., min_length=5, max_length=500)
    town: str = Field(..., min_length=2, max_length=100)
    postalcode: str = Field(..., min_length=3, max_length=20)
    latitude: Optional[Decimal] = Field(None, ge=-90, le=90)
    longitude: Optional[Decimal] = Field(None, ge=-180, le=180)


class UserResponse(BaseModel):
    """Schema for user details response"""
    success: bool
    message: Optional[str] = None
    data: Optional[dict] = None
    tag: int = 1


class UserListResponse(BaseModel):
    """Schema for user list response"""
    success: bool
    message: Optional[str] = None
    data: Optional[List[dict]] = None
    tag: int = 1
    total: Optional[int] = None


class RegionCreate(BaseModel):
    """Schema for creating region"""
    regionname: str = Field(..., min_length=2, max_length=200)


class LgaCreate(BaseModel):
    """Schema for creating LGA"""
    lganame: str = Field(..., min_length=2, max_length=200)
    regionid: int = Field(..., gt=0)

