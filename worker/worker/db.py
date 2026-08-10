import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


def _db_url() -> str:
    user = os.getenv("POSTGRES_USER", "vectus")
    pw = os.getenv("POSTGRES_PASSWORD", "vectus")
    db = os.getenv("POSTGRES_DB", "vectus_scan")
    host = os.getenv("POSTGRES_HOST", "postgres")
    port = os.getenv("POSTGRES_PORT", "5432")
    return f"postgresql+psycopg2://{user}:{pw}@{host}:{port}/{db}"


engine = create_engine(_db_url(), pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

# El esquema es propiedad del backend (Alembic). El worker solo lee/escribe;
# nunca crea tablas. Base existe únicamente para mapear los modelos espejo.
Base = declarative_base()
