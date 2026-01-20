"""
Application configuration using environment variables.

This module loads all configuration from a .env file to keep secrets
and environment-specific settings separate from code.
"""

from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All API keys and secrets must be stored in .env file, never in code.
    Missing API keys will cause feeds to use fallback/mock data.
    """
    
    # Application
    APP_NAME: str = "Threat Radar"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8001
    RELOAD: bool = True
    
    # CORS - Allow frontend to connect
    CORS_ORIGINS: list = ["*"]
    
    # Database (SQLite for local storage)
    DATABASE_URL: str = "sqlite:///./threat_radar.db"
    
    # Cache settings
    CACHE_TTL: int = 300  # 5 minutes default cache
    ENABLE_REDIS: bool = False
    REDIS_URL: Optional[str] = None
    
    # Threat Intelligence Feed API Key
    # AlienVault OTX - Community-driven threat intelligence
    ALIENVAULT_OTX_API_KEY: Optional[str] = None
    
    # Feed configuration
    FEED_UPDATE_INTERVAL: int = 300  # Update feeds every 5 minutes
    MAX_IOCS_PER_FEED: int = 1000  # Limit IOCs per feed to prevent overload
    
    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Dependency for FastAPI to inject settings."""
    return settings
