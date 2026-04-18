"""Application settings via pydantic-settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CIPHERWEAVE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Memgraph
    memgraph_host: str = "localhost"
    memgraph_port: int = 7687

    # AWS KMS
    aws_region: str = "us-east-1"
    kms_key_id: str = ""

    # Local dev: skip real KMS
    use_local_kms: bool = True

    # MCP server
    server_host: str = "0.0.0.0"
    server_port: int = 8000

    # Auth
    token_secret: str = "change-me-in-production-min-32-chars"

    # Drift detection
    drift_window_size: int = 100

    # Logging
    log_level: str = "INFO"


settings = Settings()
