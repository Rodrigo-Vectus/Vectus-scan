"""Endpoints de autenticación (F7).

- `POST /auth/request-code`  — envía OTP si el email está registrado; respuesta
  **siempre genérica** (no revela si el email existe).
- `POST /auth/verify`        — valida el código, crea la sesión (cookie), `login`.
- `POST /auth/logout`        — revoca la sesión, borra la cookie, `logout`.
- `GET  /auth/me`            — usuario de la sesión actual (para el guard del front).
- `GET  /auth/events`        — auditoría de accesos (solo admin).

Públicos: request-code, verify, logout. Requieren sesión: me. Admin: events.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, otp as otp_mod, sessions as sessions_mod
from app.deps import get_client_ip, require_admin, require_user
from app.models import (
    AUTH_LOGIN,
    AUTH_LOGIN_FAILED,
    AUTH_LOGOUT,
    AuthEvent,
    User,
)
from app.db import get_db
from app.schemas import (
    AuthEventRead,
    MessageResponse,
    RequestCodeIn,
    UserRead,
    VerifyCodeIn,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# Respuesta genérica: idéntica exista o no el email (anti-enumeración).
_GENERIC = "Si el email está registrado, se envió un código de acceso."


@router.post("/request-code", response_model=MessageResponse)
def request_code(
    payload: RequestCodeIn, request: Request, db: Session = Depends(get_db)
):
    ip = get_client_ip(request)
    try:
        otp_mod.request_code(db, payload.email, ip=ip)
    except otp_mod.OtpResendTooSoon:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Esperá unos segundos antes de pedir otro código.",
        )
    # Siempre genérico (no se usa el valor devuelto por el servicio).
    return MessageResponse(message=_GENERIC)


@router.post("/verify", response_model=UserRead)
def verify(
    payload: VerifyCodeIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    ip = get_client_ip(request)
    result = otp_mod.verify_code(db, payload.email, payload.code, ip=ip)

    if result != otp_mod.OtpResult.OK:
        # El servicio ya registró code_failed; distinguimos solo el mensaje.
        msg = {
            otp_mod.OtpResult.NO_CODE: "No hay un código vigente. Pedí uno nuevo.",
            otp_mod.OtpResult.EXPIRED: "El código venció. Pedí uno nuevo.",
            otp_mod.OtpResult.USED: "El código ya fue usado. Pedí uno nuevo.",
            otp_mod.OtpResult.LOCKED: "Demasiados intentos. Pedí un código nuevo.",
            otp_mod.OtpResult.MISMATCH: "Código incorrecto.",
        }.get(result, "No se pudo verificar el código.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)

    user = db.scalars(
        select(User).where(User.email == payload.email)
    ).first()
    if user is None or not user.activo:
        # Salvaguarda: el usuario pudo desactivarse entre pedir y verificar.
        audit.record_event(db, payload.email, AUTH_LOGIN_FAILED, ip=ip, detail="inactivo")
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario inactivo.",
        )

    token = sessions_mod.create_session(db, user.email)
    sessions_mod.set_session_cookie(response, token)
    audit.record_event(db, user.email, AUTH_LOGIN, ip=ip)
    db.commit()
    return user


@router.post("/logout", response_model=MessageResponse)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    from app.config import settings

    token = request.cookies.get(settings.session_cookie_name)
    email = sessions_mod.revoke_session(db, token) if token else None
    if email:
        ip = get_client_ip(request)
        audit.record_event(db, email, AUTH_LOGOUT, ip=ip)
        db.commit()
    sessions_mod.clear_session_cookie(response)
    return MessageResponse(message="Sesión cerrada.")


@router.get("/me", response_model=UserRead)
def me(user: User = Depends(require_user)):
    return user


@router.get("/events", response_model=list[AuthEventRead])
def events(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
    email: str | None = None,
    limit: int = 100,
):
    """Accesos recientes (login/logout y fallos). Filtro opcional por email."""
    limit = max(1, min(limit, 500))
    q = select(AuthEvent).order_by(AuthEvent.at.desc()).limit(limit)
    if email:
        q = select(AuthEvent).where(
            AuthEvent.email == email.strip().lower()
        ).order_by(AuthEvent.at.desc()).limit(limit)
    return db.scalars(q).all()
