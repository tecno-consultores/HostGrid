"""Application configuration loaded exclusively from environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for HostGrid Control Plane."""

    model_config = SettingsConfigDict(
        env_prefix="",
        case_sensitive=False,
        extra="ignore",
    )

    hostgrid_env: Literal["development", "testing", "production"] = Field(
        default="development",
        alias="HOSTGRID_ENV",
    )
    hostgrid_jwt_secret: str = Field(
        default="",
        alias="HOSTGRID_JWT_SECRET",
    )
    hostgrid_jwt_expire_minutes: int = Field(
        default=480,
        alias="HOSTGRID_JWT_EXPIRE_MINUTES",
        ge=5,
        le=1440,
    )
    database_url: str = Field(
        default="sqlite+aiosqlite:///./hostgrid.db",
        alias="DATABASE_URL",
    )
    hostgrid_cors_origins: str = Field(
        default="http://127.0.0.1:8080,http://localhost:5173",
        alias="HOSTGRID_CORS_ORIGINS",
    )
    hostgrid_max_bundle_size_mb: int = Field(
        default=25,
        alias="HOSTGRID_MAX_BUNDLE_SIZE_MB",
        ge=1,
        le=100,
    )
    hostgrid_max_bundle_uncompressed_mb: int = Field(
        default=100,
        alias="HOSTGRID_MAX_BUNDLE_UNCOMPRESSED_MB",
        ge=1,
        le=500,
    )
    hostgrid_bundles_dir: str = Field(
        default="/var/lib/hostgrid/bundles",
        alias="HOSTGRID_BUNDLES_DIR",
    )
    hostgrid_bundle_signing_pubkey_b64: str = Field(
        default="",
        alias="HOSTGRID_BUNDLE_SIGNING_PUBKEY_B64",
    )
    hostgrid_bundle_signing_privkey_b64: str = Field(
        default="",
        alias="HOSTGRID_BUNDLE_SIGNING_PRIVKEY_B64",
    )
    hostgrid_bootstrap_admin_username: str = Field(
        default="",
        alias="HOSTGRID_BOOTSTRAP_ADMIN_USERNAME",
    )
    hostgrid_bootstrap_admin_email: str = Field(
        default="",
        alias="HOSTGRID_BOOTSTRAP_ADMIN_EMAIL",
    )
    hostgrid_bootstrap_admin_password: str = Field(
        default="",
        alias="HOSTGRID_BOOTSTRAP_ADMIN_PASSWORD",
    )

    @model_validator(mode="after")
    def _validate_secrets(self) -> Settings:
        if len(self.hostgrid_jwt_secret) < 32:
            raise ValueError(
                "HOSTGRID_JWT_SECRET must be set via environment and be at least 32 characters."
            )
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        """Return parsed non-empty CORS origins."""
        return [o.strip() for o in self.hostgrid_cors_origins.split(",") if o.strip()]

    @property
    def max_bundle_bytes(self) -> int:
        """Maximum compressed bundle upload size in bytes."""
        return self.hostgrid_max_bundle_size_mb * 1024 * 1024

    @property
    def max_bundle_uncompressed_bytes(self) -> int:
        """Maximum uncompressed total bundle payload size in bytes."""
        return self.hostgrid_max_bundle_uncompressed_mb * 1024 * 1024


@lru_cache(maxsize=4)
def get_settings() -> Settings:
    """Return cached runtime settings."""
    return Settings()
