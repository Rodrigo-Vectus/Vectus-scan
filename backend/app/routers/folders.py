"""Carpetas de análisis (F10).

Agrupan scans para separarlos por cliente o por tipo de cliente. Sin
anidamiento: una sola capa, como las carpetas de Nessus.

Reglas de diseño:

- **No se borra una carpeta que tenga scans** (409). El borrado nunca debe
  arrastrar análisis por accidente; primero hay que mover o eliminar los que
  estén adentro.
- **`folder_id` es opcional en el scan.** Los análisis previos a la migración
  y los que se creen sin elegir carpeta viven en "Sin carpeta", que no es una
  fila de la tabla sino la ausencia de valor.
- **Cualquier usuario con sesión puede crear y renombrar carpetas.** Es
  organización del trabajo, no una acción destructiva: el borrado ya está
  protegido por la guarda de scans. (Distinto del borrado de análisis, que sí
  es solo de administradores.)
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Folder, Scan
from app.schemas import FolderCreate, FolderRead, FolderUpdate

router = APIRouter(prefix="/folders", tags=["folders"])


def _con_conteo(db: Session, folders: list[Folder]) -> list[dict]:
    """Adjunta a cada carpeta cuántos scans tiene, en una sola consulta."""
    conteos = dict(
        db.execute(
            select(Scan.folder_id, func.count(Scan.id))
            .where(Scan.folder_id.is_not(None))
            .group_by(Scan.folder_id)
        ).all()
    )
    return [
        {
            "id": f.id,
            "nombre": f.nombre,
            "descripcion": f.descripcion,
            "created_at": f.created_at,
            "scans": conteos.get(f.id, 0),
        }
        for f in folders
    ]


@router.get("", response_model=list[FolderRead])
def list_folders(db: Session = Depends(get_db)):
    folders = db.scalars(select(Folder).order_by(Folder.nombre)).all()
    return _con_conteo(db, list(folders))


@router.post("", response_model=FolderRead, status_code=status.HTTP_201_CREATED)
def create_folder(payload: FolderCreate, db: Session = Depends(get_db)):
    folder = Folder(nombre=payload.nombre, descripcion=payload.descripcion)
    db.add(folder)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Ya existe una carpeta llamada «{payload.nombre}».",
        )
    db.refresh(folder)
    return _con_conteo(db, [folder])[0]


@router.patch("/{folder_id}", response_model=FolderRead)
def update_folder(folder_id: int, payload: FolderUpdate, db: Session = Depends(get_db)):
    folder = db.get(Folder, folder_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Carpeta no encontrada")

    if payload.nombre is not None:
        folder.nombre = payload.nombre
    if payload.descripcion is not None:
        folder.descripcion = payload.descripcion or None

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Ya existe una carpeta llamada «{payload.nombre}».",
        )
    db.refresh(folder)
    return _con_conteo(db, [folder])[0]


@router.delete("/{folder_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_folder(folder_id: int, db: Session = Depends(get_db)):
    folder = db.get(Folder, folder_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Carpeta no encontrada")

    dentro = db.scalar(
        select(func.count(Scan.id)).where(Scan.folder_id == folder_id)
    )
    if dentro:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"La carpeta tiene {dentro} análisis. Movelos a otra carpeta "
                "o eliminalos antes de borrarla."
            ),
        )

    db.delete(folder)
    db.commit()
