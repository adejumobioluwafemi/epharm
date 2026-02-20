"""
FILE: src/core/database.py
Database connection and session management
"""
from sqlmodel import create_engine, Session, SQLModel # type: ignore
from sqlalchemy import text # type: ignore
from typing import Generator
from src.core.config import settings
import logging

logger = logging.getLogger(__name__)

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DB_ECHO,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_pre_ping=True,
    pool_recycle=3600,
)


def get_session() -> Generator[Session, None, None]:
    """Get database session - use as FastAPI dependency"""
    with Session(engine) as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Database error: {e}")
            session.rollback()
            raise
        finally:
            session.close()

def create_db_and_tables():
    """
    Create all database tables if they don't exist.
    This is safe to run multiple times - it only creates missing tables.
    """
    try:
        logger.info("🔨 Creating database tables...")
        
        SQLModel.metadata.create_all(engine)
        
        logger.info("✅ Database tables created successfully")
        
        table_names = SQLModel.metadata.tables.keys()
        logger.info(f"📊 Available tables: {', '.join(table_names)}")
        
    except Exception as e:
        logger.error(f"❌ Error creating database tables: {e}")
        raise


def init_db():
    """
    Initialize database - create tables if needed.
    This function is called on application startup.
    """
    create_db_and_tables()


def init_db2():
    """Test database connection"""
    try:
        with Session(engine) as session:
            session.exec(text("SELECT 1")) # type: ignore
            logger.info("✅ Database connected")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        raise


def close_db():
    """Close database connections"""
    engine.dispose()

def check_database_connection():
    """
    Verify database connection is working.
    Returns True if connection is successful, False otherwise.
    """
    try:
        with Session(engine) as session:
            # Simple query to test connection
            session.exec(text("SELECT 1")) # type: ignore
        logger.info("✅ Database connection successful")
        return True
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        return False