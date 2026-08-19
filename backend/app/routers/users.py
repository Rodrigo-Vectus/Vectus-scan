"""Gestión de usuarios (F7).

- `GET  /users`         — listar (cualquier usuario logueado).
- `POST /users`         — crear (solo admin).
- `PATCH /users/{id}`   — editar nombre/rol/activo (solo admin).

Guarda anti-bloqueo: no se puede desactivar ni degradar al **último
administrador activo** (evita quedarse sin ningún admin).
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import require_admin, require_user
from app.models import ROL_ADMIN, User
from app.schemas import UserCreate, UserRead, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])


def _active_admin_count(db: Session, exclude_id: int | None = None) -> int:
    q = select(func.count(User.id)).where(
        User.rol == ROL_ADMIN, User.activo.is_(True)
    )
    if exclude_id is not None:
        q = q.where(User.id != exclude_id)
    return db.scalar(q) or 0


@router.get("", response_model=list[UserRead])
def list_users(_user: User = Depends(require_user), db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.created_at.desc())).all()


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    exists = db.scalars(select(User).where(User.email == payload.email)).first()
    if exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ya existe un usuario con ese email.",
        )
    user = User(
        email=payload.email,
        nombre=payload.nombre,
        rol=payload.rol,
        activo=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    payload: UserUpdate,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    # ¿La edición degrada o desactiva a un admin activo?
    quita_admin = payload.rol is not None and payload.rol != ROL_ADMIN
    desactiva = payload.activo is False
    if user.rol == ROL_ADMIN and user.activo and (quita_admin or desactiva):
        if _active_admin_count(db, exclude_id=user.id) == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="No se puede dejar la plataforma sin ningún "
                "administrador activo.",
            )

    if payload.nombre is not None:
        user.nombre = payload.nombre
    if payload.rol is not None:
        user.rol = payload.rol
    if payload.activo is not None:
        user.activo = payload.activo

    db.commit()
    db.refresh(user)
    return user
