"""
FILE: src/email/config.py
Email service configuration for Resend API
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
import os
from dotenv import load_dotenv


class EmailSettings(BaseSettings):
    """Email service configuration settings for Resend"""
    
    # Resend Configuration
    RESEND_API_KEY: str = str(os.getenv("RESEND_API_KEY")) 

    # Email Sender
    MAIL_FROM: str = str(os.getenv("MAIL_FROM")) 
    MAIL_FROM_NAME: str = str(os.getenv("MAIL_FROM_NAME")) 
    
    # Email Features
    SEND_EMAILS: bool = bool(os.getenv("SEND_EMAILS", True))
    
    # Frontend URLs
    FRONTEND_URL: str = str(os.getenv("FRONTEND_URL")) 
    PASSWORD_RESET_URL: str = str(os.getenv("PASSWORD_RESET_URL")) 
    LOGIN_URL: str = str(os.getenv("LOGIN_URL")) 
    
    # Token Expiration
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = int(os.getenv("PASSWORD_RESET_TOKEN_EXPIRE_HOURS", 24)) 
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"  # Ignore extra fields from .env
    )


email_settings = EmailSettings()