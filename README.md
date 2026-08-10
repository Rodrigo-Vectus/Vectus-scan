# Vectus SCAN

Plataforma web de **orquestación de análisis de vulnerabilidades** de Grupo VECTUS. Ejecuta y gestiona escaneos sobre activos web con autorización previa, parsea y consolida los hallazgos, y genera un informe corporativo descargable.

> **Principio rector (no negociable).** Vectus SCAN orquesta herramientas de escaneo sobre objetivos que tienen una **autorización asociada cargada en el sistema**. No es una herramienta de intrusión: no ejecuta explotación ni acciones ofensivas por su cuenta. Ningún scan puede lanzarse sin un objetivo cuya autorización (registro con fecha y usuario) esté previamente cargada.

---

## Estado del proyecto

Se construye **por fases**. Estado actual:

| Fase | Descripción | Estado |
|------|-------------|--------|
| **F0** | Scaffolding + Docker + repo | ✅ hecha |
| **F1** | UI base y selección de análisis (formulario + compuerta de autorización) | ✅ actual |
| F2 | Motor BIEC y ejecución por etapas | pendiente |
| F3 | Parseo y consolidación de hallazgos | pendiente |
| F4 | Informe `.docx` sobre plantilla VECTUS | pendiente |
| F5 | Historial y dashboard | pendiente |

De los tres tipos de análisis, en esta etapa solo se implementa el **BIEC** (Barrido Inicial de Exposición Crítica). Bajo Nivel y Alto Nivel quedan como placeholders.

---

## Arquitectura

Cinco servicios orquestados con Docker Compose:

| Servicio | Rol | Tecnología |
|----------|-----|------------|
| `frontend` | Dashboard SOC dark | React + Vite (nginx en prod) |
| `backend` | API + orquestación | FastAPI (Python) |
| `worker` | Ejecución asíncrona de scans | Celery |
| `redis` | Broker de Celery + canal de progreso | Redis |
| `postgres` | Persistencia | PostgreSQL |

El **worker** es la única imagen que cargará las herramientas de escaneo (a partir de la Fase 2) y la única con capacidades de red elevadas, de forma acotada.

---

## Requisitos

- **Ubuntu Server 22.04** (o compatible)
- **Docker Engine** + plugin **Docker Compose v2**

Instalación de Docker en Ubuntu 22.04 (si aún no está):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

---

## Estructura

```
vectus-scan/
├── docker-compose.yml            # base (servicios, healthchecks, red, volúmenes)
├── docker-compose.override.yml   # dev (hot-reload, puertos) — auto-aplicado
├── docker-compose.prod.yml       # prod (puertos, ENVIRONMENT=production)
├── .env.example                  # plantilla de configuración (copiar a .env)
├── backend/                      # API FastAPI
│   ├── Dockerfile
│   ├── entrypoint.sh             # corre migraciones y arranca la API
│   ├── alembic.ini               # config de migraciones
│   ├── alembic/                  # entorno + versiones de migración
│   ├── requirements.txt
│   └── app/
│       ├── main.py               # health + routers
│       ├── config.py             # settings (pydantic-settings)
│       ├── db.py                 # engine SQLAlchemy + get_db
│       ├── models.py             # Project, Authorization, Scan
│       ├── schemas.py            # validación (incl. autorización)
│       ├── celery_client.py      # despacho de tareas al worker
│       └── routers/              # meta (analysis-types) + scans
├── worker/                       # worker Celery
│   ├── Dockerfile
│   ├── requirements.txt
│   └── worker/
│       ├── celery_app.py
│       └── tasks.py              # tarea ping (F0)
└── frontend/                     # React + Vite
    ├── Dockerfile                # multi-stage: dev / build / prod
    ├── nginx.conf                # serve + proxy /api en prod
    ├── package.json
    └── src/
```

---

## Configuración

Copiar la plantilla de entorno y ajustar credenciales:

```bash
cp .env.example .env
# editar .env — cambiar POSTGRES_PASSWORD antes de producción
```

El archivo `.env` **no se versiona** (está en `.gitignore`). Nunca subir secretos al repo.

---

## Levantar el proyecto

### Desarrollo local (hot-reload)

```bash
docker compose up --build
```

Aplica automáticamente `docker-compose.override.yml`. Quedan expuestos:

- Frontend (Vite): <http://localhost:5173>
- API + docs: <http://localhost:8000/docs>

### Producción (Ubuntu Server)

No usa el override de desarrollo:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

- Frontend (nginx): <http://SERVER_IP:8080> (configurable con `FRONTEND_PORT`)
- La API queda accesible internamente vía el proxy `/api` del frontend.

---

## Verificación (smoke-test de F0)

> **Importante:** la URL depende del modo de arranque.
> - En **producción** el backend NO publica el puerto 8000 al host; se accede vía el proxy `/api` del frontend → usar `http://localhost:8080/api/...`.
> - En **desarrollo** el override expone el backend directo → usar `http://localhost:8000/...`.

### En producción (`docker-compose.prod.yml`)

```bash
# 1) Salud integral vía el proxy del frontend: db y redis deben dar true
curl -s http://localhost:8080/api/health
# => {"status":"ok","checks":{"database":true,"redis":true}, ...}

# 2) Circuito backend → Redis → worker
TASK=$(curl -s -X POST http://localhost:8080/api/debug/ping-worker | grep -o '"task_id":"[^"]*"' | cut -d'"' -f4)
sleep 2
curl -s http://localhost:8080/api/debug/task/$TASK
# => {"status":"SUCCESS","result":{"pong":true, ...}}
```

### En desarrollo (override auto-aplicado)

```bash
curl -s http://localhost:8000/health
```

En el frontend, la tarjeta muestra un indicador **verde** si el backend responde `ok`.

> Los endpoints `/debug/*` existen solo para validar la plomería en F0 y se eliminan cuando llega el motor real en la Fase 2.

---

## API (Fase 1)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/health` | Estado de Postgres y Redis |
| `GET` | `/analysis-types` | Tipos de análisis (BIEC activo; bajo/alto deshabilitados) |
| `POST` | `/scans` | Crea proyecto + autorización + scan. **Rechaza con 422 sin autorización confirmada o si se pide un tipo distinto de BIEC** |
| `GET` | `/scans` | Lista de scans (más reciente primero) |
| `GET` | `/scans/{id}` | Detalle de un scan |

El **principio rector se aplica en el servidor**, no solo en el front: la validación de autorización vive en el schema de la API, así que aunque se saltee la UI, no se crea un scan sin permiso. En producción estos endpoints se consumen vía el proxy `/api` del frontend (ej. `POST /api/scans`).

### Migraciones (Alembic)

El esquema se gestiona con Alembic. El `entrypoint.sh` del backend corre `alembic upgrade head` **automáticamente al arrancar** el contenedor (tanto en dev como en prod), antes de levantar la API. No hay que correr migraciones a mano.

---

## Nota de red del worker (Fase 2)

Algunas herramientas del BIEC (nmap SYN, `ssl-enum-ciphers`) requieren capacidades de red (`NET_RAW`). Se contemplará en el compose del worker de forma **acotada** (`cap_add`), evitando `--privileged` global. Se documenta al implementar la Fase 2.

---

## Licencia

Propiedad de Grupo VECTUS. Uso interno.
