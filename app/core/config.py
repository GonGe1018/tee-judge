"""Application configuration via pydantic-settings."""

from __future__ import annotations

from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "TEE-Judge"
    VERSION: str = "0.4.0"

    # Secrets (required in production)
    TEE_JUDGE_SECRET: str = ""
    TEE_JUDGE_JUDGE_KEY: str = ""

    # Environment
    TEE_JUDGE_ENV: str = "production"
    TEE_JUDGE_TOKEN_EXPIRY: int = 86400

    # SGX / Attestation
    TEE_JUDGE_MRENCLAVE: str = ""
    TEE_JUDGE_ALLOW_MOCK: bool = False
    TEE_JUDGE_MAA_ENDPOINT: str = ""

    # Re-verification
    TEE_JUDGE_REVERIFY_MIN: int = 10
    TEE_JUDGE_REVERIFY_RATIO: float = 0.3

    # Database
    TEE_JUDGE_DB: str = ""

    # Server
    TEE_JUDGE_HOST: str = "0.0.0.0"
    TEE_JUDGE_PORT: int = 8000

    # CORS
    TEE_JUDGE_CORS_ORIGINS: str = ""

    # Limits
    MAX_CODE_LENGTH: int = 65536

    @property
    def BASE_DIR(self) -> Path:
        return Path(__file__).resolve().parent.parent.parent

    @property
    def DB_PATH(self) -> str:
        return self.TEE_JUDGE_DB or str(self.BASE_DIR / "data" / "judge.db")

    @property
    def DATA_DIR(self) -> Path:
        return self.BASE_DIR / "data"

    @property
    def PROBLEMS_DIR(self) -> Path:
        return self.DATA_DIR / "problems"

    @property
    def FRONTEND_DIR(self) -> Path:
        return self.BASE_DIR / "frontend"

    @property
    def is_dev(self) -> bool:
        return self.TEE_JUDGE_ENV == "dev"

    @property
    def allow_mock(self) -> bool:
        """Mock attestation only allowed in dev mode."""
        return self.TEE_JUDGE_ALLOW_MOCK and self.is_dev

    @property
    def cors_origins(self) -> list[str]:
        if not self.TEE_JUDGE_CORS_ORIGINS:
            return []
        return [o.strip() for o in self.TEE_JUDGE_CORS_ORIGINS.split(",") if o.strip()]

    @model_validator(mode="after")
    def validate_secrets(self) -> Settings:
        if not self.is_dev:
            if not self.TEE_JUDGE_SECRET:
                raise ValueError("TEE_JUDGE_SECRET must be set in production")
            if not self.TEE_JUDGE_JUDGE_KEY:
                raise ValueError("TEE_JUDGE_JUDGE_KEY must be set in production")
        return self

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    @classmethod
    def settings_customise_sources(cls, settings_cls, **kwargs):
        # env vars > .env file (default pydantic-settings v2 behavior)
        init = kwargs.get("init_settings")
        env = kwargs.get("env_settings")
        dotenv = kwargs.get("dotenv_settings")
        secrets = kwargs.get("secrets_settings")
        return tuple(s for s in [init, env, dotenv, secrets] if s is not None)


settings = Settings()
