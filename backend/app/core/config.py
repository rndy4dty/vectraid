"""Application configuration loaded from environment variables."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    app_name: str = "VECTRAID"
    app_version: str = "0.1.0"
    log_level: str = "INFO"
    api_v1_prefix: str = "/api/v1"

    database_url: str = "postgresql+asyncpg://vectraid:change_me@localhost:5432/vectraid"

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""

    ti_request_timeout: int = 15
    ti_request_max_retries: int = 2
    ti_rate_limit_per_minute: int = 60

    secret_key: str = "change_me_in_production"
    access_token_expire_minutes: int = 60
    max_upload_size_mb: int = 50

    storage_backend: str = "local"
    storage_local_path: str = "./data/storage"


@lru_cache
def get_settings() -> Settings:
    return Settings()
