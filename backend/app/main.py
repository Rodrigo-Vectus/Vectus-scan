import redis
import redis.asyncio as aioredis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db import check_database
from app.routers import meta, scans

app = FastAPI(title=settings.app_name, version="0.1.0")

# CORS restringido a orígenes explícitos (CORS_ORIGINS en el .env).
# Con allow_credentials=True es obligatorio NO usar "*": los navegadores
# ignoran las cookies si el origen es comodín. Esto además deja preparado
# el terreno para la sesión por cookie de F7.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(meta.router)
app.include_router(scans.router)


def check_redis() -> bool:
    try:
        client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            socket_connect_timeout=2,
        )
        return bool(client.ping())
    except Exception:
        return False


@app.get("/")
def root():
    return {
        "service": settings.app_name,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health():
    """Smoke-test integral: reporta estado de Postgres y Redis."""
    db_ok = check_database()
    redis_ok = check_redis()
    status = "ok" if (db_ok and redis_ok) else "degraded"
    return {
        "status": status,
        "service": settings.app_name,
        "environment": settings.environment,
        "checks": {"database": db_ok, "redis": redis_ok},
    }


@app.websocket("/ws/scans/{scan_id}")
async def ws_scan_progress(websocket: WebSocket, scan_id: int):
    """Push en vivo del progreso de un scan (Fase 2b).

    Se suscribe al canal Redis `scan:<id>` que publica el motor del worker y
    reenvía cada evento al cliente. Los eventos son "avisos" de cambio: el
    front, al recibirlos, vuelve a pedir `/scans/{id}/progress` (la DB sigue
    siendo la fuente de verdad). Si el WebSocket falla, el front cae a polling.
    """
    await websocket.accept()
    client = aioredis.Redis(
        host=settings.redis_host, port=settings.redis_port
    )
    pubsub = client.pubsub()
    await pubsub.subscribe(f"scan:{scan_id}")
    try:
        await websocket.send_json({"type": "hello", "scan_id": scan_id})
        while True:
            msg = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=30
            )
            if msg is None:
                # Silencio: mandamos un ping para detectar sockets muertos y
                # evitar que proxies intermedios corten la conexión ociosa.
                await websocket.send_json({"type": "ping"})
                continue
            data = msg["data"]
            if isinstance(data, bytes):
                data = data.decode()
            await websocket.send_text(data)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        for close in (
            lambda: pubsub.unsubscribe(f"scan:{scan_id}"),
            lambda: pubsub.aclose(),
            lambda: client.aclose(),
        ):
            try:
                await close()
            except Exception:
                pass
