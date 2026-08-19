"""Infra de tests de F7 (auth) sin Docker: SQLite en memoria + TestClient.

Se fija el pepper y se desactiva SMTP (modo bootstrap) ANTES de importar la
app, para que `settings` tome esos valores. Cada test corre sobre una base
limpia y `get_db` se sobreescribe para usar la sesión SQLite.
"""
import os

os.environ.setdefault("AUTH_PEPPER", "test-pepper")
os.environ.setdefault("SMTP_USER", "")
os.environ.setdefault("SMTP_APP_PASSWORD", "")
os.environ.setdefault("ADMIN_EMAIL", "")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app import models  # noqa: F401  (registra las tablas)
from app.main import app


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, future=True)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


@pytest.fixture()
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
