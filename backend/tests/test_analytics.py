"""Tests de F12: agregados del dashboard.

Cubren el criterio de conteo (mismo que el informe), el desglose de
`herramienta_origen` cuando el hallazgo se fusionó en la de-duplicación, y
los filtros por período y carpeta.
"""
from datetime import datetime, timedelta, timezone

from app import otp as otp_mod
from app.models import (
    AnalysisType,
    Authorization,
    EST_A_VALIDAR,
    EST_CONFIRMADO,
    EST_POSITIVO,
    Finding,
    Folder,
    Project,
    ROL_ANALISTA,
    SEV_ALTA,
    SEV_BAJA,
    SEV_CRITICA,
    SEV_INFO,
    SEV_MEDIA,
    Scan,
    ScanStatus,
    User,
)


def _login(client, db, email="ana@vectus.la"):
    db.add(User(email=email, nombre="T", rol=ROL_ANALISTA, activo=True))
    db.commit()
    code = otp_mod.request_code(db, email)
    assert client.post("/auth/verify", json={"email": email, "code": code}).status_code == 200


def _scan(db, dias_atras=0, folder_id=None):
    p = Project(name="p", client="c")
    a = Authorization(target="https://x.test", responsible_user="R", authorized=True)
    db.add_all([p, a])
    db.flush()
    s = Scan(target="https://x.test", cliente="c", analysis_type=AnalysisType.biec,
             status=ScanStatus.completado, project_id=p.id, authorization_id=a.id,
             folder_id=folder_id)
    db.add(s)
    db.flush()
    if dias_atras:
        s.created_at = datetime.now(timezone.utc) - timedelta(days=dias_atras)
    db.commit()
    return s.id


def _find(db, scan_id, titulo, sev, estado, herr="nmap", occ=1):
    db.add(Finding(scan_id=scan_id, titulo=titulo, severidad=sev, estado=estado,
                   herramienta_origen=herr, ocurrencias=occ, dedup_key=f"{titulo}:{scan_id}"))
    db.commit()


def test_solo_cuenta_lo_reportable(client, db_session):
    """`positivo` e `info` no son vulnerabilidades; `a_validar` va aparte."""
    _login(client, db_session)
    sid = _scan(db_session)
    _find(db_session, sid, "Crítica real", SEV_CRITICA, EST_CONFIRMADO)
    _find(db_session, sid, "Hipótesis", SEV_ALTA, EST_A_VALIDAR)
    _find(db_session, sid, "Buena postura", SEV_INFO, EST_POSITIVO)
    _find(db_session, sid, "Informativo", SEV_INFO, EST_CONFIRMADO)

    a = client.get("/scans/analytics").json()
    tool = {t["herramienta"]: t for t in a["por_herramienta"]}["nmap"]
    assert tool["critica"] == 1
    assert tool["a_validar"] == 1
    assert tool["total"] == 2          # ni el positivo ni el info suman
    # `por_estado` sí cuenta todo, para poder mostrar el reparto completo.
    assert a["por_estado"][EST_POSITIVO] == 1


def test_herramienta_unida_cuenta_para_cada_una(client, db_session):
    """Tras la de-duplicación un hallazgo puede venir de varias herramientas."""
    _login(client, db_session)
    sid = _scan(db_session)
    _find(db_session, sid, "jQuery vulnerable", SEV_MEDIA, EST_CONFIRMADO,
          herr="retire.js, whatweb")

    a = client.get("/scans/analytics").json()
    nombres = {t["herramienta"] for t in a["por_herramienta"]}
    assert nombres == {"retire.js", "whatweb"}
    for t in a["por_herramienta"]:
        assert t["media"] == 1


def test_top_hallazgos_cuenta_analisis_distintos(client, db_session):
    _login(client, db_session)
    s1, s2 = _scan(db_session), _scan(db_session)
    _find(db_session, s1, "X-Frame-Options ausente", SEV_BAJA, EST_CONFIRMADO, occ=2)
    _find(db_session, s2, "X-Frame-Options ausente", SEV_BAJA, EST_CONFIRMADO, occ=3)
    _find(db_session, s1, "Otro", SEV_BAJA, EST_CONFIRMADO)

    a = client.get("/scans/analytics").json()
    top = a["top_hallazgos"][0]
    assert top["titulo"] == "X-Frame-Options ausente"
    assert top["scans"] == 2
    assert top["ocurrencias"] == 5


def test_filtro_por_dias(client, db_session):
    _login(client, db_session)
    reciente = _scan(db_session, dias_atras=2)
    viejo = _scan(db_session, dias_atras=60)
    _find(db_session, reciente, "Nueva", SEV_ALTA, EST_CONFIRMADO)
    _find(db_session, viejo, "Vieja", SEV_ALTA, EST_CONFIRMADO)

    todo = client.get("/scans/analytics").json()
    assert todo["total_findings"] == 2

    ultimos30 = client.get("/scans/analytics?dias=30").json()
    assert ultimos30["total_findings"] == 1
    assert ultimos30["top_hallazgos"][0]["titulo"] == "Nueva"


def test_filtro_por_carpeta(client, db_session):
    _login(client, db_session)
    f = Folder(nombre="Banca")
    db_session.add(f)
    db_session.commit()
    dentro = _scan(db_session, folder_id=f.id)
    fuera = _scan(db_session)
    _find(db_session, dentro, "Dentro", SEV_ALTA, EST_CONFIRMADO)
    _find(db_session, fuera, "Fuera", SEV_ALTA, EST_CONFIRMADO)

    a = client.get(f"/scans/analytics?folder_id={f.id}").json()
    assert a["total_findings"] == 1
    assert a["top_hallazgos"][0]["titulo"] == "Dentro"


def test_sin_datos_no_rompe(client, db_session):
    _login(client, db_session)
    a = client.get("/scans/analytics?dias=7").json()
    assert a["por_herramienta"] == []
    assert a["top_hallazgos"] == []
    assert a["total_findings"] == 0


# ─── el endpoint de hallazgos del detalle ────────────────────────────
# Nadie lo cubría, y un NameError introducido al refactorizar lo dejó
# devolviendo 500 sin que ningún test se enterara: el front simplemente
# escondía toda la sección de hallazgos.

def test_findings_del_detalle_responde_y_ordena(client, db_session):
    _login(client, db_session)
    sid = _scan(db_session)
    _find(db_session, sid, "Baja", SEV_BAJA, EST_CONFIRMADO)
    _find(db_session, sid, "Crítica", SEV_CRITICA, EST_CONFIRMADO)
    _find(db_session, sid, "Media", SEV_MEDIA, EST_CONFIRMADO)
    _find(db_session, sid, "Hipótesis", SEV_ALTA, EST_A_VALIDAR)
    _find(db_session, sid, "Buena postura", SEV_INFO, EST_POSITIVO)

    r = client.get(f"/scans/{sid}/findings")
    assert r.status_code == 200, r.text
    d = r.json()

    # Ordenado por severidad (D8), sin importar el estado: los `a_validar`
    # aparecen intercalados según su gravedad.
    assert [f["titulo"] for f in d["findings"]] == [
        "Crítica", "Hipótesis", "Media", "Baja", "Buena postura",
    ]

    # El resumen respeta la regla de oro.
    assert d["summary"]["critica"] == 1
    assert d["summary"]["a_validar"] == 1
    assert d["summary"]["positivos"] == 1


def test_findings_de_scan_inexistente(client, db_session):
    _login(client, db_session)
    assert client.get("/scans/9999/findings").status_code == 404
