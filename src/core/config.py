"""
FILE: src/core/config.py
Core configuration module for OyoAgro API
"""
from functools import lru_cache
from typing import List, Optional
import os
import logging
from urllib.parse import quote_plus
from dotenv import load_dotenv # type: ignore

# Load environment variables from .env file at module import
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_dburl():
    """Construct database URL from environment variables with error handling"""
    try:
        db_url = os.getenv("DATABASE_URL")
        
        if db_url:
            db_url = db_url.strip()
            if db_url:
                if db_url.startswith(('postgresql://', 'postgres://')):
                    return db_url
                else:
                    logger.warning(f"DATABASE_URL found but doesn't start with postgresql:// or postgres://: {db_url[:20]}...")
        
        logger.info("Constructing database URL from individual components")
        
        db_user = os.getenv("DB_USER", "postgres")
        db_password = os.getenv("DB_PASSWORD", "P%40ssword%40123")
        host = os.getenv("DB_HOST", "localhost")
        port = os.getenv("DB_PORT", "5432")
        db_name = os.getenv("DB_NAME", "epharm")

        if not db_user:
            raise ValueError("DB_USER environment variable is not set")
        if not host:
            raise ValueError("DB_HOST environment variable is not set")
        if not port:
            raise ValueError("DB_PORT environment variable is not set")
        if not db_name:
            raise ValueError("DB_NAME environment variable is not set")
        
        try:
            port_num = int(port)
            if port_num <= 0 or port_num > 65535:
                raise ValueError(f"Invalid port number: {port}")
        except ValueError:
            raise ValueError(f"DB_PORT must be a valid integer, got: {port}")
        
        encoded_password = quote_plus(db_password)
        
        constructed_url = f"postgresql://{db_user}:{encoded_password}@{host}:{port}/{db_name}"
        logger.info(f"Database URL constructed successfully (password hidden)")
        return constructed_url
        
    except ValueError as ve:
        logger.error(f"Configuration error: {ve}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error constructing database URL: {e}")
        raise


def get_bool_env(key: str, default: bool = False) -> bool:
    """Convert environment variable string to boolean"""
    value = os.getenv(key)
    if value is None:
        return default
    return value.lower() in ('true', '1', 't', 'yes', 'y', 'on')


def get_int_env(key: str, default: int) -> int:
    """Convert environment variable string to integer"""
    value = os.getenv(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning(f"Invalid integer value for {key}: {value}, using default: {default}")
        return default


def get_list_env(key: str, default: List[str] = None) -> List[str]: # type: ignore
    """Convert comma-separated environment variable string to list"""
    if default is None:
        default = []
    value = os.getenv(key)
    if not value:
        return default
    return [item.strip() for item in value.split(',') if item.strip()]


class Settings:
    """Application settings loaded from environment variables using os.getenv"""
    
    def __init__(self):
        """Initialize settings by loading from environment variables"""
        
        # Application
        self.APP_NAME = os.getenv("APP_NAME", "Ronaex API")
        self.APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
        self.ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
        self.DEBUG = get_bool_env("DEBUG", True)
        self.API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
        self.API_V1_PREFIX = os.getenv("API_V1_PREFIX", "/api/v1")
        
        # Server
        self.PORT = get_int_env("PORT", 8000)
        self.HOST = os.getenv("HOST", "0.0.0.0")
        self.RELOAD = get_bool_env("RELOAD", True)
        
        # Database
        self.DATABASE_URL = get_dburl() 
        self.DB_POOL_SIZE = get_int_env("DB_POOL_SIZE", 20)
        self.DB_MAX_OVERFLOW = get_int_env("DB_MAX_OVERFLOW", 0)
        self.DB_ECHO = get_bool_env("DB_ECHO", False)
        
        # JWT
        self.JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
        self.JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
        self.JWT_ACCESS_TOKEN_EXPIRE_MINUTES = get_int_env("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 10080)
        self.JWT_ISSUER = os.getenv("JWT_ISSUER", "ronaex-api")
        self.JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "ronaex-frontend")
        self.JWT_REFRESH_TOKEN_EXPIRE_DAYS = os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 1)
        
        # Password Reset
        self.PASSWORD_RESET_TOKEN_EXPIRE_HOURS = get_int_env("PASSWORD_RESET_TOKEN_EXPIRE_HOURS", 24)
        
        # CORS
        self.CORS_ORIGINS = get_list_env("CORS_ORIGINS", ["http://localhost:3000", "http://localhost:5173"])
        self.CORS_ALLOW_CREDENTIALS = get_bool_env("CORS_ALLOW_CREDENTIALS", True)
        self.CORS_ALLOW_METHODS = get_list_env("CORS_ALLOW_METHODS", ["*"])
        self.CORS_ALLOW_HEADERS = get_list_env("CORS_ALLOW_HEADERS", ["*"])
        
        # Company
        self.COMPANY_NAME = os.getenv("COMPANY_NAME", "Ronaex")
        
        self._log_configuration()
    
    def _log_configuration(self):
        """Log configuration summary (excluding sensitive data)"""
        logger.info(f"Configuration loaded for environment: {self.ENVIRONMENT}")
        logger.info(f"APP_NAME: {self.APP_NAME}")
        logger.info(f"APP_VERSION: {self.APP_VERSION}")
        logger.info(f"DEBUG: {self.DEBUG}")
        logger.info(f"API_BASE_URL: {self.API_BASE_URL}")
        logger.info(f"PORT: {self.PORT}")
        logger.info(f"Database: {self.DATABASE_URL.split('@')[0].split(':')[0]}@****/****")  
        logger.info(f"DB_POOL_SIZE: {self.DB_POOL_SIZE}")
        logger.info(f"CORS_ORIGINS: {self.CORS_ORIGINS}")
    
    def dict(self) -> dict:
        """Return settings as dictionary (excluding sensitive data)"""
        return {
            "APP_NAME": self.APP_NAME,
            "APP_VERSION": self.APP_VERSION,
            "ENVIRONMENT": self.ENVIRONMENT,
            "DEBUG": self.DEBUG,
            "API_BASE_URL": self.API_BASE_URL,
            "API_V1_PREFIX": self.API_V1_PREFIX,
            "PORT": self.PORT,
            "HOST": self.HOST,
            "RELOAD": self.RELOAD,
            "DB_POOL_SIZE": self.DB_POOL_SIZE,
            "DB_MAX_OVERFLOW": self.DB_MAX_OVERFLOW,
            "DB_ECHO": self.DB_ECHO,
            "JWT_ALGORITHM": self.JWT_ALGORITHM,
            "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": self.JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
            "JWT_ISSUER": self.JWT_ISSUER,
            "JWT_AUDIENCE": self.JWT_AUDIENCE,
            "PASSWORD_RESET_TOKEN_EXPIRE_HOURS": self.PASSWORD_RESET_TOKEN_EXPIRE_HOURS,
            "CORS_ORIGINS": self.CORS_ORIGINS,
            "CORS_ALLOW_CREDENTIALS": self.CORS_ALLOW_CREDENTIALS,
            "CORS_ALLOW_METHODS": self.CORS_ALLOW_METHODS,
            "CORS_ALLOW_HEADERS": self.CORS_ALLOW_HEADERS,
            "COMPANY_NAME": self.COMPANY_NAME,
        }


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()

settings = get_settings()

def reload_settings():
    """Reload settings from environment (useful for testing)"""
    global settings
    settings = get_settings.cache_clear()  # Clear the cache
    settings = get_settings()
    return settings