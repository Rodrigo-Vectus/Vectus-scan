from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración de la API leída desde variables de entorno / .env."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # App
    app_name: str = "Vectus SCAN API"
    environment: str = "development"

    # CORS
    # Orígenes permitidos, separados por coma, leídos de CORS_ORIGINS.
    # En prod el front y /api son MISMO origen (nginx en :8080), así que CORS
    # casi no interviene; la lista importa sobre todo en desarrollo, donde el
    # dev server de Vite corre en otro puerto. Ajustar en el .env del server.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Postgres
    postgres_user: str = "vectus"
    postgres_password: str = "vectus"
    postgres_db: str = "vectus_scan"
    postgres_host: str = "postgres"
    postgres_port: int = 5432

    # Redis / Celery
    redis_host: str = "redis"
    redis_port: int = 6379
    celery_broker_db: int = 0
    celery_result_db: int = 1

    @property
    def cors_origins_list(self) -> list[str]:
        """Orígenes CORS como lista, tolerante a espacios y comas colgantes."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def celery_broker_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.celery_broker_db}"

    @property
    def celery_result_backend(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.celery_result_db}"


settings = Settings()
