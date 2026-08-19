"""Sesiones por cookie httpOnly (F7).

- El token viaja en la cookie; en la DB se guarda su hash (HMAC con pepper).
- **Deslizante**: cada request autenticada renueva la expiración, pero solo
  se escribe en la DB cuando ya se consumió más de la mitad de la vida de la
  sesión (a lo sumo una escritura cada ~ttl/2 por sesión).
- `revoked_at` marca el logout o una revocación administrativa.

Las funciones reciben la `Session` de SQLAlchemy explícita.
"""
from datetime import datetime, timedelta, timezone

from fastapi import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuthSession
from app.security import generate_session_token, hash_secret


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ttl() -> timedelta:
    return timedelta(hours=settings.session_ttl_hours)


def create_session(db: Session, email: str) -> str:
    """Crea una sesión para `email` y devuelve el token en claro (para la
    cookie). El hash es lo único que queda en la DB."""
    token = generate_session_token()
    now = _now()
    db.add(
        AuthSession(
            token_hash=hash_secret(token),
            email=email,
            created_at=now,
            expires_at=now + _ttl(),
        )
    )
    db.commit()
    return token


def resolve_session(db: Session, token: str) -> AuthSession | None:
    """Devuelve la sesión válida (no vencida, no revocada) para el token, o
    None. Aplica el deslizamiento de expiración cuando corresponde."""
    if not token:
        return None
    sess = db.scalars(
        select(AuthSession).where(AuthSession.token_hash == hash_secret(token))
    ).first()
    if sess is None or sess.revoked_at is not None:
        return None

    now = _now()
    expires = sess.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now > expires:
        return None

    # Deslizar solo si ya pasó más de la mitad de la vida de la sesión.
    if (expires - now) < (_ttl() / 2):
        sess.expires_at = now + _ttl()
        db.commit()

    return sess


def revoke_session(db: Session, token: str) -> str | None:
    """Revoca la sesión del token (logout). Devuelve el email si existía."""
    if not token:
        return None
    sess = db.scalars(
        select(AuthSession).where(AuthSession.token_hash == hash_secret(token))
    ).first()
    if sess is None or sess.revoked_at is not None:
        return None
    sess.revoked_at = _now()
    db.commit()
    return sess.email


# ─── Helpers de cookie ──────────────────────────────────────────────

def set_session_cookie(response: Response, token: str) -> None:
    """Setea la cookie de sesión con los atributos de seguridad acordados."""
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    """Borra la cookie de sesión (logout)."""
    response.delete_cookie(
        key=settings.session_cookie_name,
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure,
        path="/",
    )
