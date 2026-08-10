from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Authorization, Project, Scan
from app.schemas import ScanCreate, ScanRead

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
