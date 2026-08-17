"""Motor de ejecución del BIEC.

Recorre las etapas en orden y, dentro de cada una, las herramientas.
Actualiza `ScanStage`/`ToolRun` en la DB y publica eventos de progreso en
Redis (consumidos por el WebSocket en F2b; el polling lee la DB).

En F2a NO se interpreta ninguna salida: solo se ejecuta y se guarda el raw.
Todo el parseo/normalización a hallazgos es F3.

Principio rector: antes de ejecutar nada se RE-VERIFICA la autorización, y
el barrido corre solo contra el target autorizado (subfinder es pasivo y no
dispara herramientas contra los subdominios; ver commands.py).
"""
import json
import os
from datetime import datetime, timezone

from sqlalchemy import select

from worker.commands import build_stage_specs
from worker.db import SessionLocal
from worker.models import Authorization, Scan, ScanStage, ToolRun
from worker.runner import real_runner
from worker.target import parse_target

DATA_ROOT = os.getenv("SCAN_DATA_ROOT", "/data/scans")


def _now():
    return datetime.now(timezone.utc)


def _has_output(path) -> bool:
    """True si la herramienta dejó un archivo de salida no vacío."""
    try:
        return bool(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _publish(scan_id: int, payload: dict) -> None:
    """Publica un evento de progreso en Redis. No es crítico: si falla, se
    ignora (el polling sobre la DB sigue siendo la fuente de verdad)."""
    try:
        import redis

        host = os.getenv("REDIS_HOST", "redis")
        port = int(os.getenv("REDIS_PORT", "6379"))
        client = redis.Redis(host=host, port=port, socket_connect_timeout=2)
        client.publish(f"scan:{scan_id}", json.dumps(payload))
    except Exception:
        pass


def run_biec(scan_id: int, runner=real_runner, publish=_publish, data_root=DATA_ROOT):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return

        # ── Barrera del principio rector ──
        auth = db.get(Authorization, scan.authorization_id)
        if auth is None or not auth.authorized:
            scan.status = "error"
            scan.finished_at = _now()
            db.commit()
            publish(scan_id, {"type": "scan", "status": "error",
                              "reason": "autorización no confirmada"})
            return

        try:
            tgt = parse_target(scan.target)
        except ValueError as e:
            scan.status = "error"
            scan.finished_at = _now()
            db.commit()
            publish(scan_id, {"type": "scan", "status": "error", "reason": str(e)})
            return

        scan.status = "corriendo"
        scan.started_at = _now()
        db.commit()
        publish(scan_id, {"type": "scan", "status": "corriendo"})

        stages = db.scalars(
            select(ScanStage).where(ScanStage.scan_id == scan_id).order_by(ScanStage.order)
        ).all()

        for stage in stages:
            _run_stage(db, scan_id, stage, tgt, runner, publish, data_root)

        # F3: consolidar hallazgos a partir del raw recién guardado. Si falla,
        # no invalida el scan (se puede reprocesar con POST /scans/{id}/analyze).
        try:
            from worker.consolidate import run as consolidate_run

            consolidate_run(scan_id, data_root=data_root)
            publish(scan_id, {"type": "findings", "status": "listo"})
        except Exception as e:
            publish(scan_id, {"type": "findings", "status": "error", "reason": str(e)})

        scan.status = "completado"
        scan.finished_at = _now()
        db.commit()
        publish(scan_id, {"type": "scan", "status": "completado"})
    finally:
        db.close()


def _run_stage(db, scan_id, stage, tgt, runner, publish, data_root):
    stage.status = "corriendo"
    stage.started_at = _now()
    db.commit()
    publish(scan_id, {"type": "stage", "key": stage.key, "status": "corriendo"})

    out_dir = os.path.join(data_root, str(scan_id), f"{stage.order}_{stage.key}")

    try:
        specs = build_stage_specs(stage.key, tgt, out_dir)
        for spec in specs:
            tr = ToolRun(
                stage_id=stage.id,
                tool=spec.name,
                command=" ".join(spec.argv),
                status="corriendo",
                started_at=_now(),
            )
            db.add(tr)
            db.commit()
            publish(scan_id, {"type": "tool", "stage": stage.key,
                              "tool": spec.name, "status": "corriendo"})

            try:
                result = runner(spec, out_dir)
                tr.exit_code = result.exit_code
                tr.raw_path = result.raw_path
                # Una tool es "completada" si terminó bien (exit 0) o si dejó
                # salida cruda no vacía aunque el exit sea != 0. Caso típico:
                # nikto reporta hallazgos y escribe su .txt, pero corta por
                # `maxtime` con exit != 0 (B.8). El exit_code se guarda igual.
                tr.status = (
                    "completada"
                    if result.exit_code == 0 or _has_output(result.raw_path)
                    else "error"
                )
            except Exception as e:  # falla inesperada del runner
                tr.status = "error"
                tr.error = str(e)

            tr.finished_at = _now()
            db.commit()
            publish(scan_id, {"type": "tool", "stage": stage.key,
                              "tool": spec.name, "status": tr.status})

        stage.status = "completada"
    except Exception as e:
        # Falla dura de la etapa: se marca error pero el barrido continúa.
        stage.status = "error"
        publish(scan_id, {"type": "stage", "key": stage.key,
                          "status": "error", "reason": str(e)})

    stage.finished_at = _now()
    db.commit()
    if stage.status == "completada":
        publish(scan_id, {"type": "stage", "key": stage.key, "status": "completada"})
