from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.biec import ESTIMATED_TOTAL_SECONDS, STAGES
from app.celery_client import celery_client
from app.db import get_db
from app.models import (
    Authorization,
    Project,
    Scan,
    ScanStage,
    ScanStatus,
    STAGE_PENDIENTE,
)
from app.schemas import ScanCreate, ScanProgress, ScanRead

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
