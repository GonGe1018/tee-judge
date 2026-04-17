"""Application configuration loaded from environment variables."""

import os
from pathlib import Path


class Settings:
    PROJECT_NAME: str = "TEE-Judge"
    VERSION: str = "0.3.0"

    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    FRONTEND_DIR: Path = BASE_DIR / "frontend"
    PROBLEMS_DIR: Path = DATA_DIR / "problems"

    # Database
    DB_PATH: str = os.environ.get("TEE_JUDGE_DB", str(DATA_DIR / "judge.db"))

    # Server
    HOST: str = os.environ.get("TEE_JUDGE_HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("TEE_JUDGE_PORT", "8000"))

    # Limits
    MAX_CODE_LENGTH: int = 65536  # 64KB


settings = Settings()
