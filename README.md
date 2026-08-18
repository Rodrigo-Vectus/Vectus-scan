# Vectus SCAN

Plataforma web de **orquestación de análisis de vulnerabilidades** de Grupo VECTUS. Ejecuta y gestiona escaneos sobre activos web con autorización previa, parsea y consolida los hallazgos, y genera un informe corporativo descargable.

> **Principio rector (no negociable).** Vectus SCAN orquesta herramientas de escaneo sobre objetivos que tienen una **autorización asociada cargada en el sistema**. No es una herramienta de intrusión: no ejecuta explotación ni acciones ofensivas por su cuenta. Ningún scan puede lanzarse sin un objetivo cuya autorización (registro con fecha y usuario) esté previamente cargada.

---

## Estado del proyecto

Se construye **por fases**. Estado actual:

| Fase | Descripción | Estado |
|------|-------------|--------|
| **F0** | Scaffolding + Docker + repo | ✅ hecha |
| **F1** | UI base y selección de análisis (formulario + compuerta de autorización) | ✅ hecha |
| **F2a** | Motor BIEC: ejecución por etapas, guardado de salidas crudas, estado y cronómetro (polling) | ✅ hecha |
| **F2b** | WebSocket en vivo (fallback a polling) + semántica de estado de tool + afinado de timeouts/rate-limits | ✅ hecha |
| **F3a** | Parseo por herramienta + consolidación/dedup + API y vista de hallazgos | ✅ hecha |
| **F3b** | Correlación cruzada y control de falsos positivos (nikto vs curl, CVE por versión, CDN/origen) | ✅ hecha |
| **F4** | Informe `.docx` sobre plantilla VECTUS, a pedido (botón) | ✅ hecha |
| **F5** | Historial y dashboard | ✅ actual |

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
| `POST` | `/scans/{id}/launch` | **Re-verifica autorización**, crea las 5 etapas y encola el BIEC. 403 sin autorización · 409 si ya fue lanzado |
| `GET` | `/scans/{id}/progress` | Estado de ejecución: etapas, tool runs y tiempos (polling) |
| `WS` | `/ws/scans/{id}` | Push en vivo del progreso (F2b). Reenvía los eventos del canal Redis `scan:<id>`; el front cae a polling si el WS falla |
| `POST` | `/scans/{id}/analyze` | Reprocesa el raw y reconstruye los hallazgos (F3). 409 si el scan no terminó |
| `GET` | `/scans/{id}/findings` | Hallazgos consolidados + resumen por severidad (F3) |
| `GET` | `/scans/{id}/report.docx` | Genera y descarga el informe .docx a pedido (F4). 409 si el scan no terminó |
| `GET` | `/scans/dashboard` | Indicadores agregados + historial de barridos (F5) |

El **principio rector se aplica en el servidor**, no solo en el front: la validación de autorización vive en el schema de la API, así que aunque se saltee la UI, no se crea un scan sin permiso. En producción estos endpoints se consumen vía el proxy `/api` del frontend (ej. `POST /api/scans`).

### Migraciones (Alembic)

El esquema se gestiona con Alembic. El `entrypoint.sh` del backend corre `alembic upgrade head` **automáticamente al arrancar** el contenedor (tanto en dev como en prod), antes de levantar la API. No hay que correr migraciones a mano.

---

## Motor BIEC (Fase 2a)

El worker ejecuta las 5 etapas del BIEC en orden contra el objetivo autorizado y **guarda la salida cruda** de cada herramienta en el volumen `scandata` (`/data/scans/<scan_id>/<etapa>/<tool>`). En F2a **no se interpreta** ninguna salida: el parseo y la consolidación a hallazgos son la Fase 3.

Herramientas por etapa: reconocimiento (nmap, whatweb, dig, whois) · enumeración (subfinder, pasivo, solo contexto) · descubrimiento (ffuf con wordlist curada) · vulnerabilidades (nuclei, nikto) · configuración (curl headers, nmap ssl-enum-ciphers).

Refuerzos del principio rector en el motor: se **re-verifica la autorización** antes de ejecutar; el barrido corre **solo contra el target autorizado**; los subdominios de subfinder son **contexto** y no se escanean; y todos los comandos se arman con **listas de argumentos (sin shell)** con validación estricta del target, para que un objetivo malicioso no derive en inyección de comandos ni de flags.

**Red en Docker:** el worker corre con `cap_add: [NET_RAW]` (para nmap SYN y `ssl-enum-ciphers`), acotado a ese servicio y sin `--privileged`.

**Binarios Go:** nuclei, subfinder y ffuf se descargan de sus releases oficiales en el build (versiones fijadas por `ARG`, sobreescribibles con `--build-arg`).

---

## Estado en vivo (Fase 2b)

El progreso se transmite en vivo por **WebSocket** (`/ws/scans/{id}`): el motor del worker publica eventos en el canal Redis `scan:<id>` y el backend los reenvía al navegador. Cada evento es un aviso de cambio; el front, al recibirlo, vuelve a pedir `/scans/{id}/progress` (la base de datos sigue siendo la fuente de verdad). Si el WebSocket no conecta o se cae, el front **cae automáticamente a polling** cada 2,5 s, así que la vista funciona igual. nginx reenvía el upgrade del WebSocket en el mismo `location /api/`.

**Semántica de estado de herramienta:** una tool se marca `completada` si terminó con éxito (exit 0) **o** si dejó salida cruda no vacía aunque su exit sea ≠ 0 (caso típico: nikto reporta hallazgos pero corta por `maxtime`). El `exit_code` real se guarda siempre para auditoría.

**Afinado:** nuclei corre con `-timeout 10 -retries 1` además del rate-limit; los timeouts de subproceso y las estimaciones por etapa se calibraron con corridas reales.

---

## Parseo y consolidación (Fase 3a)

Cuando un scan termina, el worker **parsea las salidas crudas** y las normaliza a hallazgos (`Finding`, modelo del anexo B.1). Un parser por herramienta (nmap servicios y TLS, whatweb, ffuf, nuclei, curl headers, nikto, dig/subfinder de contexto) traduce cada salida siguiendo las reglas de B.2–B.10, y luego se **consolidan y de-duplican** (B.11): un mismo hallazgo detectado por dos herramientas (p. ej. la versión del servidor por whatweb y por curl) queda como un solo `Finding` con sus `ocurrencias` y ambas herramientas de origen.

Principio rector en el parseo: no se eleva severidad ni se inventan hallazgos. La **buena postura** se registra con `estado=positivo` (TLS moderno, namespace protegido por auth, cabeceras completas) y las hipótesis no confirmadas como `a_validar` (nunca como vulnerabilidad confirmada). El resumen por severidad excluye `positivo` y `falso_positivo`.

La consolidación corre automática al terminar el scan y también se puede **reprocesar** sin re-escanear con `POST /scans/{id}/analyze` (útil al mejorar los parsers). Los parsers son funciones puras, cubiertas por tests con fixtures. El XML de nmap se parsea con `defusedxml`.

La correlación cruzada más fina se implementa en **F3b** (siguiente sección).

---

## Correlación y falsos positivos (Fase 3b)

Sobre los candidatos ya parseados, antes de consolidar, se aplican reglas que cruzan la salida de varias herramientas (Parte B del anexo):

- **Contraste nikto ↔ curl (B.10):** nikto reporta "cabecera X ausente" probando rutas 404 aleatorias. Si en la home (cabeceras reales de curl) esa cabecera **sí** está presente, el ítem se marca `falso_positivo` (queda registrado, no suma a la tabla). Solo se aplica cuando hay cabeceras reales de curl para contrastar.
- **CVE por versión (B.8):** cada banner con versión (nmap, whatweb, curl) genera un ítem `a_validar` "revisar CVEs de la rama", con la **salvedad obligatoria**: los paquetes de distribución backportean parches manteniendo el número de versión, así que el banner por sí solo no confirma vulnerabilidad. Se de-duplica por producto/versión entre herramientas.
- **CDN vs origen (B.5):** a partir de la IP y el PTR del XML de nmap se anota si el barrido pegó al **origen real** (hosting/VPS) o a un **edge/CDN** (en cuyo caso se evalúa el edge, no el origen). Cambia la lectura de todo el resultado.

---

## Informe .docx (Fase 4)

El informe se genera **a pedido** con el botón *exportar informe (.docx)* de la vista de hallazgos (nunca automático, no se guarda). El backend edita la **plantilla corporativa** de VECTUS con python-docx (no la recrea): conserva portada, logos, estilos y footers, y rellena cliente/alcance, la **tabla resumen de severidad**, un **bloque por vulnerabilidad** (clonado de la plantilla: severidad, CVSS, ocurrencias, descripción, sistema afectado, CVE, recomendaciones, más info) y la **conclusión** con los conteos reales.

Regla de oro (B.12): a la tabla de vulnerabilidades entran solo hallazgos **confirmados** de severidad crítica/alta/media/baja. Los `info` (contexto), la buena postura (`positivo`) y las áreas a validar (`a_validar`) no son vulnerabilidades y no se cuentan ahí. Si no hay vulnerabilidades confirmadas, el informe lo dice honestamente.

Cada vulnerabilidad se enriquece con un **catálogo curado por tipo** (`report_catalog.py`): descripción técnica, desglose CVSS 3.1 completo (vector, complejidad, privilegios, interacción, impactos, alcance), recomendación para el equipo técnico y referencias. Los hallazgos sin ficha (p. ej. de nuclei) usan sus propios datos con un desglose por defecto según la severidad. La conclusión deriva las prioridades de los hallazgos reales y no deja placeholders de plantilla.

El nombre del **cliente** se toma del campo del formulario de creación del scan (`scans.cliente`), con respaldo al cliente/nombre del proyecto. La plantilla vive embebida en `backend/app/report_template/`.

---

## Historial y dashboard (Fase 5)

La portada muestra una tira de **indicadores** (barridos totales, completados, en curso y vulnerabilidades confirmadas agregadas por severidad) y un **historial** de barridos con fecha, cliente, objetivo, estado, un mini-resumen de severidad por barrido y accesos directos al detalle y al informe `.docx`. Todo se sirve desde `GET /scans/dashboard`, que calcula los conteos por scan con una sola consulta agrupada. Coherente con el resto: solo cuentan como vulnerabilidad los hallazgos confirmados de severidad crítica/alta/media/baja.

---

## Rediseño de la web (Fase 6)

La consola se reorganizó como un panel SOC con **barra lateral** (Scanners · Informes · Dashboard) y se sacaron las ejecuciones de la pantalla principal. Paleta dark navy (`#070B14`) con acentos cyan (`#22D3EE`) y teal (`#2DD4BF`), tipografías **Inter** (interfaz) y **JetBrains Mono** (IDs/IPs/datos), bundleadas para no depender de red. **Scanners** es el inicio (limpio), **Informes** permite abrir el desglose y el informe por ID de análisis, y **Dashboard** muestra indicadores y distribución por severidad.

---

## Licencia

Propiedad de Grupo VECTUS. Uso interno.
