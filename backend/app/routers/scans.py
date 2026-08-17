from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.biec import ESTIMATED_TOTAL_SECONDS, STAGES
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
