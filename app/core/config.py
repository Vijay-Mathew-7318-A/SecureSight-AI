"""Application settings, loaded from environment variables or the .env file."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All configurable values for SecureSight AI.

    Each field matches an environment variable of the same name
    (case-insensitive). Example: request_timeout <- REQUEST_TIMEOUT.
    """

    app_name: str = "SecureSight AI"
    app_version: str = "0.1.0"

    # Claude API (optional). Empty means: use rule-based fallback.
    anthropic_api_key: str = ""
    anthropic_model: str = ""

    # Database
    database_url: str = "sqlite:///./securesight.db"

    # Scanning limits
    request_timeout: int = 10
    max_redirects: int = 5

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return one shared Settings object (cached after the first call)."""
    return Settings()