"""Registro de eventos de auditoría de autenticación (AuthEvent).

Un helper único para no repetir el patrón en cada endpoint. No hace commit:
lo deja a cargo del llamador, que suele agrupar el evento con otros cambios
en la misma transacción.
"""
from sqlalchemy.orm import Session

from app.models import AuthEvent


def record_event(
    db: Session,
    email: str,
    kind: str,
    ip: str | None = None,
    detail: str | None = None,
) -> None:
    """Agrega un AuthEvent a la sesión (sin commitear)."""
    db.add(AuthEvent(email=email, kind=kind, ip=ip, detail=detail))
