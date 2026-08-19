"""Dependencias de autenticación para FastAPI.

- `current_user_optional`: resuelve la sesión desde la cookie; None si no hay
  sesión válida. Refresca la cookie (sesión deslizante) cuando hay usuario.
- `require_auth`: gate global que respeta `AUTH_REQUIRED`. Con False deja
  pasar (user puede ser None); con True exige sesión. Se cuelga del router de
  scans para no romper la app durante el rollout de F7.
- `require_user`: exige una sesión real (para `/auth/me` y listar usuarios).
- `require_admin`: exige rol administrador (gestión de usuarios, auditoría).
"""
from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import sessions as sessions_mod
from app.config import settings
from app.db import get_db
from app.models import ROL_ADMIN, User


def get_client_ip(request: Request) -> str | None:
    """IP del cliente respetando el proxy (nginx setea X-Forwarded-For)."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


def current_user_optional(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> User | None:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None
    sess = sessions_mod.resolve_session(db, token)
    if sess is None:
        return None
    user = db.scalars(select(User).where(User.email == sess.email)).first()
    if user is None or not user.activo:
        return None
    # Sesión deslizante: refrescar el Max-Age de la cookie en cada request
    # autenticada (la escritura en DB de expires_at ya viene throttleada en
    # resolve_session al medio ttl).
    sessions_mod.set_session_cookie(response, token)
    return user


def require_auth(user: User | None = Depends(current_user_optional)) -> User | None:
    """Gate que respeta AUTH_REQUIRED. Devuelve el usuario o None."""
    if settings.auth_required and user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado.",
        )
    return user


def require_user(user: User | None = Depends(current_user_optional)) -> User:
    """Exige una sesión válida (independiente de AUTH_REQUIRED)."""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado.",
        )
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    """Exige rol administrador."""
    if user.rol != ROL_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere rol administrador.",
        )
    return user
