"""Siembra del administrador inicial.

Al arrancar el backend, si la tabla `users` está **vacía** y hay `ADMIN_EMAIL`
configurado en el .env, crea ese usuario como `administrador` activo. Es
idempotente: si ya existe cualquier usuario, no hace nada (no pisa datos).

Resuelve el problema del huevo y la gallina: como el OTP solo se envía a
usuarios registrados, sin este primer admin nadie podría loguearse para crear
al resto.
"""
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ROL_ADMIN, User

logger = logging.getLogger("vectus.auth.seed")


def seed_admin(db: Session) -> None:
    existing = db.scalars(select(User.id)).first()
    if existing is not None:
        return  # ya hay usuarios: no hacer nada

    email = (settings.admin_email or "").strip().lower()
    if not email:
        logger.warning(
            "No hay usuarios y ADMIN_EMAIL no está configurado: no se sembró "
            "admin inicial. Cargá ADMIN_EMAIL/ADMIN_NAME en el .env para poder "
            "loguearte."
        )
        return

    db.add(
        User(
            email=email,
            nombre=settings.admin_name or "Administrador",
            rol=ROL_ADMIN,
            activo=True,
        )
    )
    db.commit()
    logger.info("Admin inicial sembrado: %s", email)
