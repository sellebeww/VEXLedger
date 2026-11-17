# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Pydantic settings. Every value has a safe local default; override via VEXLEDGER_* env vars."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VEXLEDGER_", env_file=".env", extra="ignore")

    env: Literal["dev", "test", "prod"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    database_url: str = "postgresql+asyncpg://vexledger:vexledger@localhost:5433/vexledger"
    redis_url: str = "redis://localhost:6380/0"
    # The only outbound host the server may call. Fixed by config, never taken from input.
    osv_base_url: str = "https://api.osv.dev"
    vex_base_url: str = "http://localhost:8000"
    max_upload_mb: int = Field(default=25, ge=1, le=100)
    osv_connect_timeout_s: float = Field(default=5.0, gt=0, le=60)
    osv_read_timeout_s: float = Field(default=30.0, gt=0, le=300)
    osv_max_retries: int = Field(default=5, ge=0, le=10)
    osv_concurrency: int = Field(default=8, ge=1, le=64)
    osv_http2: bool = True
    # Offline demo: serve SYNTHETIC OSV records in-process instead of calling osv_base_url.
    demo_osv_fixtures: bool = False
    osv_cache_ttl_hours: int = Field(default=6, ge=1, le=168)
    sbom_max_components: int = Field(default=50_000, ge=1)
    sbom_max_depth: int = Field(default=32, ge=1, le=256)
    match_max_tries: int = Field(default=5, ge=1, le=20)
    worker_job_timeout_s: int = Field(default=900, ge=30)
    readiness_timeout_s: float = Field(default=2.0, gt=0, le=30)
    evidence_dir: str = "./data/evidence"
    # Browser origins allowed to call the API with credentials; empty means none (same-origin only).
    cors_origins: list[str] = Field(default_factory=list)
    session_ttl_s: int = Field(default=8 * 3600, ge=60)
    login_window_s: int = Field(default=900, ge=1)
    login_max_per_account: int = Field(default=5, ge=1)
    login_max_per_ip: int = Field(default=20, ge=1)
    password_min_length: int = Field(default=12, ge=12)
    json_body_max_kb: int = Field(default=256, ge=1)

    @field_validator("cors_origins")
    @classmethod
    def _no_wildcard_origin(cls, value: list[str]) -> list[str]:
        if "*" in value:
            raise ValueError("cors_origins must list explicit origins, never '*'")
        return value

    @property
    def cookie_secure(self) -> bool:
        return self.env == "prod"


@lru_cache
def get_settings() -> Settings:
    return Settings()
