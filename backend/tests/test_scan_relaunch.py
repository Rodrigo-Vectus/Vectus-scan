"""Tests de F11: relanzar el barrido sobre el mismo objetivo.

Lo que importa cubrir es que la barrera del principio rector no se saltee: el
análisis nuevo hereda la autorización del original (no una copia con fecha de
hoy) y se rechaza si esa autorización no está confirmada.
"""
from app import otp as otp_mod
from app.models import (
    AnalysisType,
    Authorization,
    Folder,
    Project,
    ROL_ANALISTA,
    Scan,
    ScanStage,
    ScanStatus,
    User,
)


def _login(client, db, email="ana@vectus.la"):
    db.add(User(email=email, nombre="Test", rol=ROL_ANALISTA, activo=True))
    db.commit()
    code = otp_mod.request_code(db, email)
    assert client.post("/auth/verify", json={"email": email, "code": code}).status_code == 200


def _mk_scan(db, autorizado=True, folder_id=None, status=ScanStatus.completado):
    project = Project(name="Proyecto", client="ACME")
    auth = Authorization(
        target="https://ejemplo.test", responsible_user="Rodrigo",
        authorized=autorizado, note="ok",
    )
    db.add_all([project, auth])
    db.flush()
    scan = Scan(
        target="https://ejemplo.test", cliente="ACME",
        analysis_type=AnalysisType.biec, status=status,
        project_id=project.id, authorization_id=auth.id, folder_id=folder_id,
    )
    db.add(scan)
    db.commit()
    return scan.id, auth.id


def test_relanzar_crea_uno_nuevo_y_conserva_el_original(client, db_session, monkeypatch):
    encolado = []
    monkeypatch.setattr(
        "app.routers.scans.celery_client.send_task",
        lambda name, args=None, **kw: encolado.append((name, args)),
    )
    _login(client, db_session)
    folder = Folder(nombre="Clientes")
    db_session.add(folder)
    db_session.commit()
    orig_id, auth_id = _mk_scan(db_session, folder_id=folder.id)

    r = client.post(f"/scans/{orig_id}/relaunch")
    assert r.status_code == 201, r.text
    nuevo = r.json()

    assert nuevo["id"] != orig_id
    assert nuevo["target"] == "https://ejemplo.test"
    assert nuevo["cliente"] == "ACME"
    assert nuevo["folder_id"] == folder.id          # hereda la carpeta
    # El original sigue existiendo con sus datos.
    assert db_session.get(Scan, orig_id) is not None

    # Quedó encolado en el worker y con las etapas creadas.
    assert encolado == [("worker.tasks.run_biec", [nuevo["id"]])]
    assert db_session.query(ScanStage).filter_by(scan_id=nuevo["id"]).count() > 0
    assert db_session.get(Scan, nuevo["id"]).status == ScanStatus.en_cola


def test_reusa_la_autorizacion_original_sin_duplicarla(client, db_session, monkeypatch):
    """No se crea una autorización nueva con fecha de hoy: eso simularía un
    consentimiento que nadie volvió a dar."""
    monkeypatch.setattr(
        "app.routers.scans.celery_client.send_task", lambda *a, **k: None
    )
    _login(client, db_session)
    orig_id, auth_id = _mk_scan(db_session)
    antes = db_session.query(Authorization).count()

    nuevo_id = client.post(f"/scans/{orig_id}/relaunch").json()["id"]

    assert db_session.query(Authorization).count() == antes  # no se duplicó
    assert db_session.get(Scan, nuevo_id).authorization_id == auth_id


def test_no_relanza_sin_autorizacion_confirmada(client, db_session, monkeypatch):
    """La barrera del principio rector se re-verifica server-side."""
    monkeypatch.setattr(
        "app.routers.scans.celery_client.send_task", lambda *a, **k: None
    )
    _login(client, db_session)
    orig_id, _ = _mk_scan(db_session, autorizado=False)

    r = client.post(f"/scans/{orig_id}/relaunch")
    assert r.status_code == 403
    # No quedó ningún scan nuevo colgado.
    assert db_session.query(Scan).count() == 1


def test_relanzar_inexistente_da_404(client, db_session):
    _login(client, db_session)
    assert client.post("/scans/9999/relaunch").status_code == 404
