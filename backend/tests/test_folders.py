"""Tests de F10a: carpetas de análisis.

Lo que más importa cubrir es la guarda de borrado (no se puede borrar una
carpeta con scans adentro) y que mover un scan no toque nada más.
"""
from app import otp as otp_mod
from app.models import (
    AnalysisType,
    Authorization,
    Folder,
    Project,
    ROL_ANALISTA,
    Scan,
    ScanStatus,
    User,
)


def _login(client, db, email="ana@vectus.la"):
    db.add(User(email=email, nombre="Test", rol=ROL_ANALISTA, activo=True))
    db.commit()
    code = otp_mod.request_code(db, email)
    r = client.post("/auth/verify", json={"email": email, "code": code})
    assert r.status_code == 200, r.text


def _mk_scan(db, folder_id=None):
    project = Project(name="p", client="c")
    auth = Authorization(target="https://x.test", responsible_user="R", authorized=True)
    db.add_all([project, auth])
    db.flush()
    scan = Scan(
        target="https://x.test", cliente="c", analysis_type=AnalysisType.biec,
        status=ScanStatus.completado, project_id=project.id,
        authorization_id=auth.id, folder_id=folder_id,
    )
    db.add(scan)
    db.commit()
    return scan.id


# ─── CRUD ────────────────────────────────────────────────────────────

def test_crear_listar_y_contar(client, db_session):
    _login(client, db_session)
    r = client.post("/folders", json={"nombre": "Gobierno"})
    assert r.status_code == 201
    fid = r.json()["id"]
    assert r.json()["scans"] == 0

    _mk_scan(db_session, folder_id=fid)
    _mk_scan(db_session, folder_id=fid)
    _mk_scan(db_session)  # sin carpeta: no debe contarse

    carpetas = client.get("/folders").json()
    assert len(carpetas) == 1
    assert carpetas[0]["scans"] == 2


def test_nombre_duplicado_da_409(client, db_session):
    _login(client, db_session)
    assert client.post("/folders", json={"nombre": "Banca"}).status_code == 201
    r = client.post("/folders", json={"nombre": "Banca"})
    assert r.status_code == 409


def test_nombre_vacio_se_rechaza(client, db_session):
    _login(client, db_session)
    assert client.post("/folders", json={"nombre": "   "}).status_code == 422


def test_renombrar(client, db_session):
    _login(client, db_session)
    fid = client.post("/folders", json={"nombre": "Viejo"}).json()["id"]
    r = client.patch(f"/folders/{fid}", json={"nombre": "Nuevo"})
    assert r.status_code == 200 and r.json()["nombre"] == "Nuevo"


def test_carpetas_protegidas_con_auth_required(client, db_session, monkeypatch):
    """Igual que /scans: el router está detrás de `require_auth`, que solo
    exige sesión cuando AUTH_REQUIRED está activo (en el server lo está)."""
    from app import config as config_mod

    monkeypatch.setattr(config_mod.settings, "auth_required", True)
    assert client.get("/folders").status_code == 401
    assert client.post("/folders", json={"nombre": "X"}).status_code == 401


# ─── la guarda de borrado ────────────────────────────────────────────

def test_no_se_borra_carpeta_con_scans(client, db_session):
    _login(client, db_session)
    fid = client.post("/folders", json={"nombre": "Con scans"}).json()["id"]
    scan_id = _mk_scan(db_session, folder_id=fid)

    r = client.delete(f"/folders/{fid}")
    assert r.status_code == 409
    assert "1 análisis" in r.json()["detail"]
    # Ni la carpeta ni el scan se tocaron.
    assert db_session.get(Folder, fid) is not None
    assert db_session.get(Scan, scan_id) is not None


def test_se_borra_carpeta_vacia(client, db_session):
    _login(client, db_session)
    fid = client.post("/folders", json={"nombre": "Vacía"}).json()["id"]
    assert client.delete(f"/folders/{fid}").status_code == 204
    assert db_session.get(Folder, fid) is None


def test_borrar_carpeta_inexistente_da_404(client, db_session):
    _login(client, db_session)
    assert client.delete("/folders/9999").status_code == 404


# ─── mover scans ─────────────────────────────────────────────────────

def test_mover_scan_a_carpeta_y_sacarlo(client, db_session):
    _login(client, db_session)
    fid = client.post("/folders", json={"nombre": "Destino"}).json()["id"]
    scan_id = _mk_scan(db_session)

    r = client.patch(f"/scans/{scan_id}/folder", json={"folder_id": fid})
    assert r.status_code == 200 and r.json()["folder_id"] == fid

    # null lo devuelve a "Sin carpeta"
    r = client.patch(f"/scans/{scan_id}/folder", json={"folder_id": None})
    assert r.status_code == 200 and r.json()["folder_id"] is None

    # y ahora la carpeta se puede borrar
    assert client.delete(f"/folders/{fid}").status_code == 204


def test_mover_a_carpeta_inexistente_da_404(client, db_session):
    _login(client, db_session)
    scan_id = _mk_scan(db_session)
    r = client.patch(f"/scans/{scan_id}/folder", json={"folder_id": 9999})
    assert r.status_code == 404
    assert db_session.get(Scan, scan_id).folder_id is None


def test_dashboard_expone_la_carpeta(client, db_session):
    _login(client, db_session)
    fid = client.post("/folders", json={"nombre": "Telco"}).json()["id"]
    _mk_scan(db_session, folder_id=fid)
    _mk_scan(db_session)

    filas = client.get("/scans/dashboard").json()["scans"]
    conc = {f["id"]: (f["folder_id"], f["folder_nombre"]) for f in filas}
    assert (fid, "Telco") in conc.values()
    assert (None, None) in conc.values()


def test_crear_scan_dentro_de_una_carpeta(client, db_session):
    _login(client, db_session)
    fid = client.post("/folders", json={"nombre": "Nueva"}).json()["id"]
    r = client.post("/scans", json={
        "project_name": "p", "client": "c", "target": "https://ejemplo.test",
        "responsible_user": "Rodrigo", "authorized": True, "folder_id": fid,
    })
    assert r.status_code == 201, r.text
    assert r.json()["folder_id"] == fid
