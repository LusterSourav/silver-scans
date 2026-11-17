from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    redis_url: str = "redis://localhost:6379/0"
    mongo_url: str = "mongodb://localhost:27017"
    mongo_db: str = "forensics"
    vt_api_key: Optional[str] = None
    mobsf_url: str = "http://mobsf:8000"
    mobsf_api_key: Optional[str] = None
    secret_key: str = "dev-secret-change-in-production"
    upstash_redis_rest_url: Optional[str] = None
    upstash_redis_rest_token: Optional[str] = None
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()