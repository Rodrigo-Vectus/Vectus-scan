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

    # ─── Autenticación (F7) ────────────────────────────────
    # Enforcement global. Con False, los endpoints de auth funcionan pero
    # scans/dashboard/informe NO exigen sesión (permite desplegar F7a sin
    # romper la app hasta que el login del front, F7b, esté arriba). Se pone
    # True como paso final del rollout.
    auth_required: bool = False

    # Pepper para hashear OTP y tokens de sesión (HMAC-SHA256). El valor real
    # va en el .env del server; este default es solo para desarrollo local.
    auth_pepper: str = "dev-insecure-pepper-change-me"

    # Sesión por cookie (httpOnly, SameSite=Lax). `secure` debe ser True
    # cuando haya HTTPS delante; hoy el deploy es HTTP en :8080, por eso el
    # default es False (con Secure=True el navegador no manda la cookie por
    # HTTP y la sesión "no funcionaría").
    session_cookie_name: str = "vectus_session"
    session_cookie_secure: bool = False
    session_ttl_hours: int = 12

    # OTP
    otp_ttl_minutes: int = 10
    otp_max_attempts: int = 5
    otp_resend_seconds: int = 60  # anti-spam: 1 código por email cada 60 s

    # SMTP (Gmail con app password). Credenciales SOLO en el .env del server.
    # Si smtp_user/app_password están vacíos → modo bootstrap: el código se
    # registra en el log del backend en vez de enviarse por correo.
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_app_password: str = ""
    smtp_from: str = ""  # remitente visible; si vacío, se usa smtp_user

    # Admin inicial sembrado al arrancar si la tabla users está vacía.
    admin_email: str = ""
    admin_name: str = "Administrador"

    @property
    def smtp_configured(self) -> bool:
        """True si hay credenciales para enviar correo de verdad."""
        return bool(self.smtp_user and self.smtp_app_password)

    @property
    def smtp_from_effective(self) -> str:
        """Remitente visible; cae al usuario SMTP si no se configuró uno."""
        return self.smtp_from or self.smtp_user

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
