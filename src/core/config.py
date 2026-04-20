# src/core/config.py

from typing import Optional, Dict, Any, List, Union
from pydantic_settings import BaseSettings
from pydantic import Field, validator, field_validator
from enum import Enum
import json
import secrets


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TEST = "test"


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"
    AZURE = "azure"
    VERTEX = "vertex"


class AgentBackend(str, Enum):
    HARDCODED = "hardcoded"
    LLM = "llm"
    API = "api"


class Settings(BaseSettings):
    # Environment
    environment: Environment = Field(default=Environment.DEVELOPMENT, validation_alias="ENVIRONMENT")
    debug: bool = Field(default=False, validation_alias="DEBUG")
    service_name: str = Field(default="enterprise-orchestrator", validation_alias="SERVICE_NAME")
    
    # API Configuration
    api_version: str = Field(default="v1", validation_alias="API_VERSION")
    api_prefix: str = Field(default="/api", validation_alias="API_PREFIX")
    api_host: str = Field(default="0.0.0.0", validation_alias="API_HOST")
    api_port: int = Field(default=8000, validation_alias="API_PORT")
    workers: int = Field(default=4, validation_alias="WORKERS")
    
    # Security
    jwt_secret_key: str = Field(default=secrets.token_urlsafe(32), validation_alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", validation_alias="JWT_ALGORITHM")
    jwt_access_token_expire_minutes: int = Field(default=30, validation_alias="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    jwt_refresh_token_expire_days: int = Field(default=7, validation_alias="JWT_REFRESH_TOKEN_EXPIRE_DAYS")
    
    api_key_header_name: str = Field(default="X-API-Key", validation_alias="API_KEY_HEADER_NAME")
    mfa_enabled: bool = Field(default=False, validation_alias="MFA_ENABLED")
    
    # CORS
    cors_origins: Union[str, List[str]] = Field(
        default="http://localhost:3000,http://localhost:8000", 
        validation_alias="CORS_ORIGINS"
    )
    cors_allow_credentials: bool = Field(default=True, validation_alias="CORS_ALLOW_CREDENTIALS")
    
    # Database
    postgres_dsn: str = Field(
        default="postgresql://postgres:postgres@localhost:5432/orchestrator", 
        validation_alias="POSTGRES_DSN"
    )
    redis_dsn: str = Field(default="redis://localhost:6379/0", validation_alias="REDIS_DSN")
    rabbitmq_dsn: str = Field(default="amqp://guest:guest@localhost:5672/", validation_alias="RABBITMQ_DSN")
    
    db_pool_min_size: int = Field(default=5, validation_alias="DB_POOL_MIN_SIZE")
    db_pool_max_size: int = Field(default=20, validation_alias="DB_POOL_MAX_SIZE")
    db_pool_timeout: int = Field(default=30, validation_alias="DB_POOL_TIMEOUT")
    
    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True, validation_alias="RATE_LIMIT_ENABLED")
    rate_limit_default: str = Field(default="100/minute", validation_alias="RATE_LIMIT_DEFAULT")
    rate_limit_strategy: str = Field(default="sliding-window", validation_alias="RATE_LIMIT_STRATEGY")
    
    # Encryption
    field_encryption_key: str = Field(default=secrets.token_urlsafe(32), validation_alias="FIELD_ENCRYPTION_KEY")
    tls_enabled: bool = Field(default=False, validation_alias="TLS_ENABLED")
    
    # Observability
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    log_format: str = Field(default="json", validation_alias="LOG_FORMAT")
    traces_enabled: bool = Field(default=False, validation_alias="TRACES_ENABLED")
    metrics_enabled: bool = Field(default=True, validation_alias="METRICS_ENABLED")
    metrics_port: int = Field(default=9090, validation_alias="METRICS_PORT")
    audit_log_enabled: bool = Field(default=True, validation_alias="AUDIT_LOG_ENABLED")
    
    # LLM Configuration
    llm_provider: LLMProvider = Field(default=LLMProvider.LOCAL, validation_alias="LLM_PROVIDER")
    openai_api_key: Optional[str] = Field(default=None, validation_alias="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(default=None, validation_alias="ANTHROPIC_API_KEY")
    local_llm_url: str = Field(default="http://localhost:11434", validation_alias="LOCAL_LLM_URL")
    local_llm_model: str = Field(default="qwen2.5:3b", validation_alias="LOCAL_LLM_MODEL")
    
    # Payments (Razorpay)
    razorpay_key_id:     str = Field(default="", validation_alias="RAZORPAY_KEY_ID")
    razorpay_key_secret: str = Field(default="", validation_alias="RAZORPAY_KEY_SECRET")

    # ── Email (Hostinger SMTP) ────────────────────────────────────
    smtp_host:     str = Field(default="smtp.hostinger.com", validation_alias="SMTP_HOST")
    smtp_port:     int = Field(default=465,                   validation_alias="SMTP_PORT")
    smtp_user:     str = Field(default="admin@xcloak.tech",  validation_alias="SMTP_USER")
    smtp_password: str = Field(default="",                    validation_alias="SMTP_PASSWORD")

    # Agent Configuration
    agent_backend: AgentBackend = Field(default=AgentBackend.HARDCODED, validation_alias="AGENT_BACKEND")
    
    # Worker Configuration
    min_workers_per_tool: int = Field(default=1, validation_alias="MIN_WORKERS_PER_TOOL")
    max_workers_per_tool: int = Field(default=5, validation_alias="MAX_WORKERS_PER_TOOL")
    scale_up_threshold: float = Field(default=0.7, validation_alias="SCALE_UP_THRESHOLD")
    scale_down_threshold: float = Field(default=0.2, validation_alias="SCALE_DOWN_THRESHOLD")
    
    # Feature Flags
    features_enabled: Dict[str, bool] = Field(
        default={
            "hybrid_execution": True,
            "audit_logging": True,
            "mfa": False,
            "webhooks": True,
            "scheduling": True
        },
        validation_alias="FEATURES_ENABLED"
    )
    
    @field_validator("cors_origins", mode="before")
    def parse_cors_origins(cls, v):
        """Parse CORS origins from string to list"""
        if isinstance(v, str):
            if not v or v.strip() == "":
                return []
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v
    
    @field_validator("features_enabled", mode="before")
    def parse_features(cls, v):
        """Parse features from JSON string to dict"""
        if isinstance(v, str):
            if not v or v.strip() == "":
                return {}
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return {}
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


# Global settings instance
_settings = None


def get_settings() -> Settings:
    """Get cached settings"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings