"""
FILE: main.py
FastAPI application entry point
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from src.core.config import settings
from src.core.database import init_db, close_db
import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("=" * 60)
    logger.info("🚀 Ronaex API")
    logger.info("=" * 60)
    
    try:
        init_db()
        logger.info("✅ Database initialized")
    except Exception as e:
        logger.error(f"❌ Failed to initialize database: {e}")
        if settings.ENVIRONMENT == "development":
            raise
    logger.info("✅ Application ready!")
    yield
    
    logger.info("🛑 Shutting down")
    
    try:
        close_db()
        logger.info("✅ DB connections closed")
    except Exception as e:
        logger.error(f"❌ Error closing connections: {e}")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Ronaex E-Pharmacy API",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

@app.get("/")
async def root():
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "environment": settings.ENVIRONMENT
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": settings.APP_VERSION}


try:
    from src.auth.router import router as auth_router
    app.include_router(auth_router, prefix=settings.API_V1_PREFIX, tags=["Authentication"])
    logger.info("✅ Auth router registered")
except ImportError:
    logger.warning("⚠️  Auth router not found")



if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", settings.PORT))
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=port,
        reload=settings.RELOAD
    )