"""Ciclo de vida del OTP: generación/envío y verificación.

Reglas (confirmadas en el cierre técnico de F7):
- Solo se envía a usuarios **registrados y activos**. La respuesta HTTP es
  siempre genérica (no revela si el email existe): eso lo maneja el router.
- Código de **6 dígitos**, **un solo uso**, **10 minutos**, guardado hasheado.
- **Límite de intentos** (default 5): al agotarlo, el código queda invalidado.
- **Rate limit de emisión**: 1 código por email cada `otp_resend_seconds`.
- Al pedir un código nuevo, se **invalidan** los códigos previos no usados de
  ese email (solo el último vale).

Todas las funciones reciben la `Session` explícita (testeable con SQLite).
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, emailer
from app.config import settings
from app.models import (
    AUTH_CODE_FAILED,
    AUTH_CODE_SENT,
    OtpCode,
    User,
)
from app.security import generate_otp_code, hash_secret, verify_secret


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _active_user(db: Session, email: str) -> User | None:
    user = db.scalars(select(User).where(User.email == email)).first()
    if user is None or not user.activo:
        return None
    return user


class OtpResendTooSoon(Exception):
    """Se pidió un código antes de que pasara la ventana anti-spam."""


def request_code(db: Session, email: str, ip: str | None = None) -> str | None:
    """Genera y envía un OTP si el email corresponde a un usuario activo.

    Devuelve el código en claro **solo para uso interno/tests**; el router
    NUNCA debe exponerlo. Devuelve None si el email no está registrado/activo
    (el router responde genérico igual). Lanza OtpResendTooSoon si se pide
    demasiado seguido.
    """
    email = email.strip().lower()
    user = _active_user(db, email)
    if user is None:
        # No se filtra la inexistencia: el router responde genérico.
        return None

    now = _now()

    # Rate limit: ¿hay un código reciente para este email?
    last = db.scalars(
        select(OtpCode)
        .where(OtpCode.email == email)
        .order_by(OtpCode.created_at.desc())
    ).first()
    if last is not None and last.created_at is not None:
        created = last.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if (now - created) < timedelta(seconds=settings.otp_resend_seconds):
            raise OtpResendTooSoon()

    # Invalidar códigos previos no usados (solo el último vale).
    previous = db.scalars(
        select(OtpCode).where(OtpCode.email == email, OtpCode.used_at.is_(None))
    ).all()
    for p in previous:
        p.used_at = now  # marcado como consumido → deja de ser válido

    code = generate_otp_code()
    otp = OtpCode(
        email=email,
        code_hash=hash_secret(code),
        expires_at=now + timedelta(minutes=settings.otp_ttl_minutes),
        attempts=0,
    )
    db.add(otp)
    audit.record_event(db, email, AUTH_CODE_SENT, ip=ip)
    db.commit()

    emailer.send_otp_email(email, code)
    return code


class OtpResult:
    """Resultado de verificar un código."""

    OK = "ok"
    NO_CODE = "no_code"          # no hay código vigente para el email
    EXPIRED = "expired"          # venció
    USED = "used"               # ya consumido
    LOCKED = "locked"           # se agotaron los intentos
    MISMATCH = "mismatch"       # código incorrecto (queda 1 intento menos)


def verify_code(db: Session, email: str, code: str, ip: str | None = None) -> str:
    """Valida el código para `email`. Devuelve uno de OtpResult.*.

    En caso OK marca el código como usado (un solo uso). En MISMATCH suma un
    intento y, si llega al tope, lo invalida (LOCKED en el siguiente intento).
    Registra `code_failed` en la auditoría ante cualquier fallo.
    """
    email = email.strip().lower()
    now = _now()

    otp = db.scalars(
        select(OtpCode)
        .where(OtpCode.email == email, OtpCode.used_at.is_(None))
        .order_by(OtpCode.created_at.desc())
    ).first()

    if otp is None:
        audit.record_event(db, email, AUTH_CODE_FAILED, ip=ip, detail="sin código")
        db.commit()
        return OtpResult.NO_CODE

    expires = otp.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now > expires:
        audit.record_event(db, email, AUTH_CODE_FAILED, ip=ip, detail="vencido")
        db.commit()
        return OtpResult.EXPIRED

    if otp.attempts >= settings.otp_max_attempts:
        otp.used_at = now  # invalidar
        audit.record_event(db, email, AUTH_CODE_FAILED, ip=ip, detail="bloqueado")
        db.commit()
        return OtpResult.LOCKED

    if not verify_secret(code, otp.code_hash):
        otp.attempts += 1
        detail = f"intento {otp.attempts}/{settings.otp_max_attempts}"
        if otp.attempts >= settings.otp_max_attempts:
            otp.used_at = now  # se agotó en este intento
            detail += " (agotado)"
        audit.record_event(db, email, AUTH_CODE_FAILED, ip=ip, detail=detail)
        db.commit()
        return OtpResult.MISMATCH

    otp.used_at = now  # un solo uso
    db.commit()
    return OtpResult.OK
