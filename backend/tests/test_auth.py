"""Tests de F7a (backend de auth). Cubren OTP, sesión por cookie, roles,
guardas de administrador, auditoría y el gate AUTH_REQUIRED."""
from datetime import datetime, timedelta, timezone

import app.config as config_mod
from app import otp as otp_mod
from app.models import (
    AUTH_LOGIN,
    AUTH_LOGOUT,
    AuthEvent,
    OtpCode,
    ROL_ADMIN,
    ROL_ANALISTA,
    User,
)


def _mk_user(db, email, rol=ROL_ANALISTA, activo=True, nombre="Test"):
    u = User(email=email, nombre=nombre, rol=rol, activo=activo)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _login(client, db, email):
    """Hace login completo (request-code + verify) y deja la cookie en client."""
    code = otp_mod.request_code(db, email)
    r = client.post("/auth/verify", json={"email": email, "code": code})
    assert r.status_code == 200, r.text
    return r


# ─── OTP ────────────────────────────────────────────────────────────

def test_request_code_only_for_registered(db_session):
    _mk_user(db_session, "reg@vectus.la")
    assert otp_mod.request_code(db_session, "reg@vectus.la") is not None
    # Email no registrado → None (y el router responde genérico igual).
    assert otp_mod.request_code(db_session, "nadie@vectus.la") is None


def test_request_code_generic_response(client, db_session):
    _mk_user(db_session, "reg@vectus.la")
    r1 = client.post("/auth/request-code", json={"email": "reg@vectus.la"})
    r2 = client.post("/auth/request-code", json={"email": "nadie@vectus.la"})
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json() == r2.json()  # idéntica respuesta (anti-enumeración)


def test_otp_hashed_at_rest(db_session):
    _mk_user(db_session, "reg@vectus.la")
    code = otp_mod.request_code(db_session, "reg@vectus.la")
    row = db_session.query(OtpCode).first()
    assert row.code_hash != code and len(row.code_hash) == 64  # sha256 hex


def test_otp_single_use(db_session):
    _mk_user(db_session, "reg@vectus.la")
    code = otp_mod.request_code(db_session, "reg@vectus.la")
    assert otp_mod.verify_code(db_session, "reg@vectus.la", code) == otp_mod.OtpResult.OK
    # Segundo intento con el mismo código: ya no hay código vigente.
    assert otp_mod.verify_code(db_session, "reg@vectus.la", code) == otp_mod.OtpResult.NO_CODE


def test_otp_expiry(db_session):
    _mk_user(db_session, "reg@vectus.la")
    code = otp_mod.request_code(db_session, "reg@vectus.la")
    row = db_session.query(OtpCode).first()
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()
    assert otp_mod.verify_code(db_session, "reg@vectus.la", code) == otp_mod.OtpResult.EXPIRED


def test_otp_attempt_limit(db_session, monkeypatch):
    monkeypatch.setattr(config_mod.settings, "otp_max_attempts", 3)
    _mk_user(db_session, "reg@vectus.la")
    otp_mod.request_code(db_session, "reg@vectus.la")
    for _ in range(3):
        assert otp_mod.verify_code(db_session, "reg@vectus.la", "000000") == otp_mod.OtpResult.MISMATCH
    # Agotados los intentos, el código quedó invalidado.
    assert otp_mod.verify_code(db_session, "reg@vectus.la", "000000") == otp_mod.OtpResult.NO_CODE


def test_otp_resend_rate_limit(db_session):
    _mk_user(db_session, "reg@vectus.la")
    otp_mod.request_code(db_session, "reg@vectus.la")
    try:
        otp_mod.request_code(db_session, "reg@vectus.la")
        assert False, "debió lanzar OtpResendTooSoon"
    except otp_mod.OtpResendTooSoon:
        pass


def test_new_code_invalidates_previous(db_session, monkeypatch):
    monkeypatch.setattr(config_mod.settings, "otp_resend_seconds", 0)
    _mk_user(db_session, "reg@vectus.la")
    old = otp_mod.request_code(db_session, "reg@vectus.la")
    new = otp_mod.request_code(db_session, "reg@vectus.la")
    assert otp_mod.verify_code(db_session, "reg@vectus.la", old) in (
        otp_mod.OtpResult.NO_CODE,
        otp_mod.OtpResult.MISMATCH,
    )
    assert otp_mod.verify_code(db_session, "reg@vectus.la", new) == otp_mod.OtpResult.OK


# ─── Sesión / cookie ────────────────────────────────────────────────

def test_login_sets_cookie_and_me(client, db_session):
    _mk_user(db_session, "reg@vectus.la", nombre="Regina")
    _login(client, db_session, "reg@vectus.la")
    assert client.cookies.get("vectus_session") is not None
    me = client.get("/auth/me")
    assert me.status_code == 200 and me.json()["email"] == "reg@vectus.la"


def test_me_requires_session(client, db_session):
    assert client.get("/auth/me").status_code == 401


def test_logout_revokes(client, db_session):
    _mk_user(db_session, "reg@vectus.la")
    _login(client, db_session, "reg@vectus.la")
    assert client.post("/auth/logout").status_code == 200
    # Tras logout la sesión queda revocada → /auth/me 401.
    assert client.get("/auth/me").status_code == 401


def test_verify_via_http_flow(client, db_session):
    _mk_user(db_session, "reg@vectus.la")
    code = otp_mod.request_code(db_session, "reg@vectus.la")
    bad = client.post("/auth/verify", json={"email": "reg@vectus.la", "code": "999999"})
    assert bad.status_code == 401
    ok = client.post("/auth/verify", json={"email": "reg@vectus.la", "code": code})
    assert ok.status_code == 200


# ─── Usuarios / roles ───────────────────────────────────────────────

def test_list_users_requires_login(client, db_session):
    assert client.get("/users").status_code == 401


def test_analista_cannot_create_user(client, db_session):
    _mk_user(db_session, "ana@vectus.la", rol=ROL_ANALISTA)
    _login(client, db_session, "ana@vectus.la")
    # Puede listar (cualquier logueado)...
    assert client.get("/users").status_code == 200
    # ...pero no crear (solo admin).
    r = client.post("/users", json={"email": "x@vectus.la", "nombre": "X", "rol": "analista"})
    assert r.status_code == 403


def test_admin_creates_user(client, db_session):
    _mk_user(db_session, "admin@vectus.la", rol=ROL_ADMIN)
    _login(client, db_session, "admin@vectus.la")
    r = client.post("/users", json={"email": "nuevo@vectus.la", "nombre": "Nuevo", "rol": "analista"})
    assert r.status_code == 201 and r.json()["email"] == "nuevo@vectus.la"
    # Duplicado → 409.
    r2 = client.post("/users", json={"email": "nuevo@vectus.la", "nombre": "Dup", "rol": "analista"})
    assert r2.status_code == 409


def test_cannot_remove_last_admin(client, db_session):
    admin = _mk_user(db_session, "admin@vectus.la", rol=ROL_ADMIN)
    _login(client, db_session, "admin@vectus.la")
    # Degradar al único admin → 409.
    r = client.patch(f"/users/{admin.id}", json={"rol": "analista"})
    assert r.status_code == 409
    # Desactivar al único admin → 409.
    r2 = client.patch(f"/users/{admin.id}", json={"activo": False})
    assert r2.status_code == 409


def test_can_remove_admin_when_another_exists(client, db_session):
    a1 = _mk_user(db_session, "admin1@vectus.la", rol=ROL_ADMIN)
    _mk_user(db_session, "admin2@vectus.la", rol=ROL_ADMIN)
    _login(client, db_session, "admin1@vectus.la")
    r = client.patch(f"/users/{a1.id}", json={"rol": "analista"})
    assert r.status_code == 200 and r.json()["rol"] == "analista"


def test_inactive_user_cannot_login(client, db_session):
    _mk_user(db_session, "off@vectus.la", activo=False)
    # request_code no genera para inactivo.
    assert otp_mod.request_code(db_session, "off@vectus.la") is None


# ─── Auditoría ──────────────────────────────────────────────────────

def test_audit_login_logout(client, db_session):
    _mk_user(db_session, "reg@vectus.la")
    _login(client, db_session, "reg@vectus.la")
    client.post("/auth/logout")
    kinds = [e.kind for e in db_session.query(AuthEvent).all()]
    assert AUTH_LOGIN in kinds and AUTH_LOGOUT in kinds


def test_events_admin_only(client, db_session):
    _mk_user(db_session, "ana@vectus.la", rol=ROL_ANALISTA)
    _login(client, db_session, "ana@vectus.la")
    assert client.get("/auth/events").status_code == 403


def test_events_visible_to_admin(client, db_session):
    _mk_user(db_session, "admin@vectus.la", rol=ROL_ADMIN)
    _login(client, db_session, "admin@vectus.la")
    r = client.get("/auth/events")
    assert r.status_code == 200 and isinstance(r.json(), list)


# ─── Gate AUTH_REQUIRED ─────────────────────────────────────────────

def test_scans_open_when_auth_not_required(client, db_session, monkeypatch):
    monkeypatch.setattr(config_mod.settings, "auth_required", False)
    # Sin sesión, con AUTH_REQUIRED=false, los scans responden (no 401).
    assert client.get("/scans").status_code == 200


def test_scans_protected_when_auth_required(client, db_session, monkeypatch):
    monkeypatch.setattr(config_mod.settings, "auth_required", True)
    assert client.get("/scans").status_code == 401
    # Con sesión válida, pasa.
    _mk_user(db_session, "reg@vectus.la")
    _login(client, db_session, "reg@vectus.la")
    assert client.get("/scans").status_code == 200
