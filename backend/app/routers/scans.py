from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.biec import ESTIMATED_TOTAL_SECONDS, STAGES
from app import report as report_mod
from app.celery_client import celery_client
from app.db import get_db
from app.models import (
    Authorization,
    Finding,
    Project,
    Scan,
    ScanStage,
    ScanStatus,
    STAGE_PENDIENTE,
    EST_CONFIRMADO,
    EST_POSITIVO,
    EST_A_VALIDAR,
    EST_FALSO_POSITIVO,
    SEV_CRITICA,
    SEV_ALTA,
    SEV_MEDIA,
    SEV_BAJA,
    SEV_INFO,
)
from app.schemas import (
    DashboardResponse,
    ScanHistoryRow,
    FindingsResponse,
    ScanCreate,
    ScanProgress,
    ScanRead,
    SeveritySummary,
)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)):
    """Crea proyecto + autorización + scan de forma atómica.

    La validación del principio rector (autorización confirmada, solo BIEC)
    ya ocurrió en el schema; si el payload llegó hasta acá, es válido.
    El scan nace en estado `creado`: en la Fase 1 no se ejecuta nada.
    """
    project = Project(name=payload.project_name, client=payload.client)
    authorization = Authorization(
        target=payload.target,
        responsible_user=payload.responsible_user,
        authorized=payload.authorized,
        note=payload.note,
    )
    db.add(project)
    db.add(authorization)
    db.flush()  # asigna ids sin cerrar la transacción

    scan = Scan(
        target=payload.target,
        cliente=payload.client,
        analysis_type=payload.analysis_type,
        project_id=project.id,
        authorization_id=authorization.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=list[ScanRead])
def list_scans(db: Session = Depends(get_db)):
    """Lista los scans, del más reciente al más antiguo."""
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc())).all()
    return scans


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard(db: Session = Depends(get_db)):
    """Indicadores agregados + historial de barridos (F5).

    Un solo query agrupado calcula los conteos de vulnerabilidades confirmadas
    por scan; el resumen global es la suma. Solo cuentan como vulnerabilidad los
    hallazgos confirmados de severidad crítica/alta/media/baja (igual que el
    informe); positivo/info/a_validar no suman a esas columnas.
    """
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc())).all()

    # conteos por scan en una sola consulta
    sev_field = {SEV_CRITICA: "critica", SEV_ALTA: "alta", SEV_MEDIA: "media", SEV_BAJA: "baja"}
    counts: dict[int, dict] = {}
    rows = (
        db.query(Finding.scan_id, Finding.severidad, Finding.estado, func.count())
        .filter(Finding.estado.in_([EST_CONFIRMADO, EST_A_VALIDAR]))
        .group_by(Finding.scan_id, Finding.severidad, Finding.estado)
        .all()
    )
    for sid, sev, estado, n in rows:
        c = counts.setdefault(
            sid, {"critica": 0, "alta": 0, "media": 0, "baja": 0, "vulnerabilidades": 0, "a_validar": 0}
        )
        if estado == EST_A_VALIDAR:
            c["a_validar"] += n
        elif estado == EST_CONFIRMADO and sev in sev_field:
            c[sev_field[sev]] += n
            c["vulnerabilidades"] += n

    history: list[ScanHistoryRow] = []
    tot = {"critica": 0, "alta": 0, "media": 0, "baja": 0, "total": 0}
    st = {"completado": 0, "en_curso": 0, "error": 0}
    for s in scans:
        c = counts.get(s.id, {})
        history.append(
            ScanHistoryRow(
                id=s.id, target=s.target, cliente=s.cliente, status=s.status,
                created_at=s.created_at, finished_at=s.finished_at,
                critica=c.get("critica", 0), alta=c.get("alta", 0),
                media=c.get("media", 0), baja=c.get("baja", 0),
                vulnerabilidades=c.get("vulnerabilidades", 0),
                a_validar=c.get("a_validar", 0),
            )
        )
        for k in ("critica", "alta", "media", "baja"):
            tot[k] += c.get(k, 0)
        tot["total"] += c.get("vulnerabilidades", 0)
        if s.status == ScanStatus.completado:
            st["completado"] += 1
        elif s.status == ScanStatus.error:
            st["error"] += 1
        elif s.status in (ScanStatus.en_cola, ScanStatus.corriendo):
            st["en_curso"] += 1

    return DashboardResponse(
        total_scans=len(scans),
        completados=st["completado"],
        en_curso=st["en_curso"],
        con_error=st["error"],
        vuln_critica=tot["critica"], vuln_alta=tot["alta"],
        vuln_media=tot["media"], vuln_baja=tot["baja"], vuln_total=tot["total"],
        scans=history,
    )


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return scan


@router.post("/{scan_id}/launch", response_model=ScanProgress)
def launch_scan(scan_id: int, db: Session = Depends(get_db)):
    """Encola la ejecución del BIEC.

    Barrera del principio rector: se RE-VERIFICA que la autorización esté
    confirmada acá, en el servidor, antes de encolar. No alcanza con que el
    scan exista. Solo se lanza desde estado `creado`.
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan no encontrado")

    auth = db.get(Authorization, scan.authorization_id)
    if auth is None or not auth.authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="El objetivo no tiene autorización confirmada. No se puede lanzar.",
        )

    if scan.status != ScanStatus.creado:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"El scan ya fue lanzado (estado actual: {scan.status.value}).",
        )

    # Crear las 5 etapas en estado pendiente y estimar duración.
    for s in STAGES:
        db.add(
            ScanStage(
                scan_id=scan.id,
                order=s["order"],
                key=s["key"],
                label=s["label"],
                status=STAGE_PENDIENTE,
            )
        )
    scan.estimated_seconds = ESTIMATED_TOTAL_SECONDS
    scan.status = ScanStatus.en_cola
    db.commit()
    db.refresh(scan)

    # Encolar en el worker (por nombre; el backend no importa el motor).
    celery_client.send_task("worker.tasks.run_biec", args=[scan.id])

    return scan


@router.get("/{scan_id}/progress", response_model=ScanProgress)
def scan_progress(scan_id: int, db: Session = Depends(get_db)):
    """Estado de ejecución para el cronómetro y las etapas en vivo (polling)."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return scan


@router.post("/{scan_id}/analyze", status_code=status.HTTP_202_ACCEPTED)
def analyze_scan(scan_id: int, db: Session = Depends(get_db)):
    """Re-procesa el raw guardado y reconstruye los hallazgos (F3).

    Útil para reprocesar sin re-escanear (p. ej. tras mejorar los parsers).
    El scan tuvo que haber corrido (hay salidas crudas en el volumen).
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    if scan.status not in (ScanStatus.completado, ScanStatus.error):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El scan todavía no terminó; no hay salidas para analizar.",
        )
    celery_client.send_task("worker.tasks.consolidate_findings", args=[scan.id])
    return {"scan_id": scan.id, "queued": True}


_SEV_FIELD = {
    SEV_CRITICA: "critica",
    SEV_ALTA: "alta",
    SEV_MEDIA: "media",
    SEV_BAJA: "baja",
    SEV_INFO: "info",
}
_SEV_ORDER = {SEV_CRITICA: 0, SEV_ALTA: 1, SEV_MEDIA: 2, SEV_BAJA: 3, SEV_INFO: 4}


@router.get("/{scan_id}/findings", response_model=FindingsResponse)
def scan_findings(scan_id: int, db: Session = Depends(get_db)):
    """Hallazgos consolidados + resumen por severidad (B.11).

    El resumen cuenta solo hallazgos reportables: los `positivo` (buena
    postura) y `falso_positivo` se excluyen de la tabla de severidad.
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan no encontrado")

    findings = (
        db.query(Finding).filter(Finding.scan_id == scan_id).all()
    )
    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severidad, 9), f.id))

    summary = SeveritySummary()
    for f in findings:
        if f.estado == EST_POSITIVO:
            summary.positivos += 1
            continue
        if f.estado == EST_FALSO_POSITIVO:
            continue
        field = _SEV_FIELD.get(f.severidad)
        if field:
            setattr(summary, field, getattr(summary, field) + 1)
        summary.total += 1
        if f.estado == EST_A_VALIDAR:
            summary.a_validar += 1

    return FindingsResponse(
        scan_id=scan_id, status=scan.status, summary=summary, findings=findings
    )


_DOCX_MIME = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
)


@router.get("/{scan_id}/report.docx")
def scan_report(scan_id: int, db: Session = Depends(get_db)):
    """Genera el informe .docx a pedido (botón) y lo devuelve para descargar.

    No se guarda ni se dispara solo. Solo disponible cuando el scan terminó.
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    if scan.status not in (ScanStatus.completado, ScanStatus.error):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El scan todavía no terminó; no hay informe para generar.",
        )
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    data = report_mod.generate_for_scan(scan, findings)

    host = (scan.target or "scan").replace("https://", "").replace("http://", "")
    host = host.split("/")[0].replace(":", "_") or "scan"
    filename = f"informe-BIEC-{host}-{scan_id}.docx"
    return Response(
        content=data,
        media_type=_DOCX_MIME,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
