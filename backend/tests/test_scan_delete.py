"""Tests de F9a: borrado de análisis desde Informes.

Cubren la guarda de rol, el 409 con un scan en curso, la cascada (etapas y
hallazgos se van con el scan) y que la autorización se conserve como rastro
del principio rector.
"""
from app import otp as otp_mod
from app.models import (
    Authorization,
    AuthEvent,
    EST_CONFIRMADO,
    Finding,
    Project,
    ROL_ADMIN,
    ROL_ANALISTA,
    SEV_ALTA,
    STAGE_PENDIENTE,
    Scan,
    ScanStage,
    ScanStatus,
    User,
)
from app.models import AnalysisType


def _mk_user(db, email, rol=ROL_ANALISTA):
    u = User(email=email, nombre="Test", rol=rol, activo=True)
    db.add(u)
    db.commit()
    return u


def _login(client, db, email):
    code = otp_mod.request_code(db, email)
    r = client.post("/auth/verify", json={"email": email, "code": code})
    assert r.status_code == 200, r.text


def _mk_scan(db, status=ScanStatus.completado):
    project = Project(name="p", client="Cliente")
    auth = Authorization(
        target="https://ejemplo.test", responsible_user="Rodrigo", authorized=True
    )
    db.add_all([project, auth])
    db.flush()
    scan = Scan(
        target="https://ejemplo.test",
        cliente="Cliente",
        analysis_type=AnalysisType.biec,
        status=status,
        project_id=project.id,
        authorization_id=auth.id,
    )
    db.add(scan)
    db.flush()
    db.add(
        ScanStage(
            scan_id=scan.id, order=1, key="reconocimiento",
            label="Reconocimiento", status=STAGE_PENDIENTE,
        )
    )
    db.add(
        Finding(
            scan_id=scan.id, titulo="x", severidad=SEV_ALTA,
            herramienta_origen="nmap", estado=EST_CONFIRMADO, dedup_key="k:1",
        )
    )
    db.commit()
    return scan.id, auth.id


def test_analista_no_puede_borrar(client, db_session):
    scan_id, _ = _mk_scan(db_session)
    _mk_user(db_session, "ana@vectus.la", rol=ROL_ANALISTA)
    _login(client, db_session, "ana@vectus.la")
    r = client.delete(f"/scans/{scan_id}")
    assert r.status_code == 403
    assert db_session.get(Scan, scan_id) is not None


def test_sin_sesion_no_puede_borrar(client, db_session):
    scan_id, _ = _mk_scan(db_session)
    r = client.delete(f"/scans/{scan_id}")
    assert r.status_code == 401
    assert db_session.get(Scan, scan_id) is not None


def test_admin_borra_con_cascada(client, db_session, monkeypatch):
    enviados = []
    monkeypatch.setattr(
        "app.routers.scans.celery_client.send_task",
        lambda name, args=None, **kw: enviados.append((name, args)),
    )
    scan_id, auth_id = _mk_scan(db_session)
    _mk_user(db_session, "admin@vectus.la", rol=ROL_ADMIN)
    _login(client, db_session, "admin@vectus.la")

    r = client.delete(f"/scans/{scan_id}")
    assert r.status_code == 204, r.text

    assert db_session.get(Scan, scan_id) is None
    assert db_session.query(ScanStage).filter_by(scan_id=scan_id).count() == 0
    assert db_session.query(Finding).filter_by(scan_id=scan_id).count() == 0
    # La autorización se conserva: rastro del principio rector.
    assert db_session.get(Authorization, auth_id) is not None
    # Se encoló el borrado de la evidencia en el worker.
    assert enviados == [("worker.tasks.delete_scan_data", [scan_id])]
    # Quedó auditado.
    ev = db_session.query(AuthEvent).filter_by(kind="scan_deleted").all()
    assert len(ev) == 1 and ev[0].email == "admin@vectus.la"


def test_no_se_puede_borrar_en_curso(client, db_session):
    scan_id, _ = _mk_scan(db_session, status=ScanStatus.corriendo)
    _mk_user(db_session, "admin@vectus.la", rol=ROL_ADMIN)
    _login(client, db_session, "admin@vectus.la")
    r = client.delete(f"/scans/{scan_id}")
    assert r.status_code == 409
    assert db_session.get(Scan, scan_id) is not None


def test_borrar_inexistente_da_404(client, db_session):
    _mk_user(db_session, "admin@vectus.la", rol=ROL_ADMIN)
    _login(client, db_session, "admin@vectus.la")
    assert client.delete("/scans/99999").status_code == 404
