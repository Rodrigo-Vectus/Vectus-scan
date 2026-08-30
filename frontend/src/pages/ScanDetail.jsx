import { useCallback, useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  getScan,
  getProgress,
  getFindings,
  relaunchScan,
  reportUrl,
  launchScan,
  openProgressSocket,
  messagesFromError,
} from "../api.js";

function fmtDate(iso) {
  try {
    return new Date(iso).toLocaleString("es-AR", {
      day: "2-digit", month: "2-digit", year: "2-digit",
      hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

function fmtDur(sec) {
  if (sec == null || isNaN(sec)) return "—";
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return `${m}m ${String(s).padStart(2, "0")}s`;
}

const RUNNING = new Set(["en_cola", "corriendo"]);

const SEV_LABEL = { critica: "Crítica", alta: "Alta", media: "Media", baja: "Baja", info: "Info" };
const SEV_KEYS = ["critica", "alta", "media", "baja", "info"];

function StageRow({ stage }) {
  return (
    <li className="stage-row">
      <span className="stage-order mono">{String(stage.order).padStart(2, "0")}</span>
      <div className="stage-main">
        <div className="stage-head">
          <span className="stage-label">{stage.label}</span>
          <span className={`badge badge-${stage.status}`}>{stage.status}</span>
        </div>
        {stage.tool_runs.length > 0 && (
          <div className="tool-chips">
            {stage.tool_runs.map((t) => (
              <span key={t.id} className={`chip chip-${t.status}`}>{t.tool}</span>
            ))}
          </div>
        )}
      </div>
    </li>
  );
}

function Timer({ prog }) {
  const { status, started_at, finished_at, estimated_seconds } = prog;
  const [, tick] = useState(0);
  const running = RUNNING.has(status);

  useEffect(() => {
    if (!running) return;
    const iv = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(iv);
  }, [running]);

  let label, value;
  if (status === "creado") {
    label = "estimado";
    value = fmtDur(estimated_seconds);
  } else if (running) {
    const elapsed = started_at ? (Date.now() - new Date(started_at).getTime()) / 1000 : 0;
    label = "transcurrido";
    value = `${fmtDur(elapsed)} / est. ${fmtDur(estimated_seconds)}`;
  } else {
    const total = started_at && finished_at
      ? (new Date(finished_at).getTime() - new Date(started_at).getTime()) / 1000 : null;
    label = "duración";
    value = fmtDur(total);
  }

  return (
    <div className="timer">
      <span className="timer-label">{label}</span>
      <span className="timer-value mono">{value}</span>
    </div>
  );
}

function Progress({ prog }) {
  const total = prog.stages.length || 5;
  const done = prog.stages.filter((s) => s.status === "completada").length;
  const errored = prog.stages.some((s) => s.status === "error");
  const pct = Math.round((done / total) * 100);

  return (
    <div className="exec">
      <div className="exec-top">
        <span className={`badge badge-lg badge-${prog.status}`}>{prog.status}</span>
        <Timer prog={prog} />
      </div>
      <div className="progress-track" aria-label={`progreso ${pct}%`}>
        <div className={`progress-fill ${errored ? "has-error" : ""}`} style={{ width: `${pct}%` }} />
      </div>
      <p className="progress-meta mono">{done}/{total} etapas</p>
      <ul className="stage-list">
        {prog.stages.map((s) => <StageRow key={s.id} stage={s} />)}
      </ul>
    </div>
  );
}

function SevHero({ summary }) {
  return (
    <div className="sev-hero">
      {SEV_KEYS.map((k) => (
        <div key={k} className={`sev-tile tile-${k}`}>
          <span className="sev-tile-num mono">{summary[k]}</span>
          <span className="sev-tile-lbl">{SEV_LABEL[k]}</span>
        </div>
      ))}
      <div className="sev-tile tile-total">
        <span className="sev-tile-num mono">{summary.total}</span>
        <span className="sev-tile-lbl">Total</span>
      </div>
    </div>
  );
}

function FindingsList({ data }) {
  const { findings } = data;
  const reportables = findings.filter(
    (f) => f.estado !== "positivo" && f.estado !== "falso_positivo"
  );
  const positivos = findings.filter((f) => f.estado === "positivo");

  return (
    <div className="findings-wrap">
      <div className="section-label">
        <span className="section-label-text">hallazgos</span>
        <span className="section-rule" />
      </div>

      {reportables.length === 0 && <p className="muted">Sin hallazgos reportables.</p>}

      {/* Lista de hallazgos (rediseñada en F15).

          Antes cada hallazgo era una caja con borde y sombra, y todos los
          campos —incluida la evidencia, que es un volcado HTTP crudo— se
          mostraban como prosa en el mismo tratamiento. Ahora:
          · Filas separadas por una línea, sin cajas.
          · La severidad es una barra de color a la izquierda, no una píldora
            suelta: al recorrer la lista se ve el perfil de riesgo de un vistazo.
          · La evidencia va en su propio bloque monoespaciado con scroll, que
            es lo que es: una traza técnica, no un párrafo.
          · Los metadatos cortos (sistema, CVE, CWE, ocurrencias) van en una
            fila de etiquetas, no en una lista de definiciones de dos columnas
            que dejaba la mitad del ancho vacía. */}
      <ol className="fx-list">
        {reportables.map((f, i) => (
          <li key={f.id} className={`fx sev-${f.severidad}`}>
            <details>
              <summary className="fx-head">
                <span className="fx-idx mono">{String(i + 1).padStart(2, "0")}</span>
                <span className="fx-sev mono">{SEV_LABEL[f.severidad] || f.severidad}</span>
                <span className="fx-title">{f.titulo}</span>
                {f.estado === "a_validar" && (
                  <span className="fx-flag mono" title="Requiere validación manual">
                    a validar
                  </span>
                )}
                {f.ocurrencias > 1 && (
                  <span className="fx-count mono" title="Ocurrencias">
                    ×{f.ocurrencias}
                  </span>
                )}
                <span className="fx-tool mono">{f.herramienta_origen}</span>
                <span className="fx-caret" aria-hidden="true" />
              </summary>

              <div className="fx-body">
                <div className="fx-meta">
                  {f.sistema_afectado && (
                    <span className="fx-meta-item">
                      <b>sistema</b><code>{f.sistema_afectado}</code>
                    </span>
                  )}
                  {f.cve && f.cve !== "No aplica" && (
                    <span className="fx-meta-item">
                      <b>cve</b><code>{f.cve}</code>
                    </span>
                  )}
                  {f.cwe && (
                    <span className="fx-meta-item">
                      <b>cwe</b><code>{f.cwe}</code>
                    </span>
                  )}
                </div>

                {f.evidencia && (
                  <div className="fx-block">
                    <p className="fx-block-label mono">evidencia</p>
                    <pre className="fx-pre">{f.evidencia}</pre>
                  </div>
                )}

                {f.recomendacion && (
                  <div className="fx-block">
                    <p className="fx-block-label mono">recomendación</p>
                    <p className="fx-text">{f.recomendacion}</p>
                  </div>
                )}

                {f.mas_info && (
                  <div className="fx-block">
                    <p className="fx-block-label mono">más info</p>
                    <p className="fx-text mono fx-refs">{f.mas_info}</p>
                  </div>
                )}
              </div>
            </details>
          </li>
        ))}
      </ol>

      {positivos.length > 0 && (
        <div className="positivos">
          <p className="positivos-title">Buena postura ({positivos.length})</p>
          <ul>
            {positivos.map((f) => (
              <li key={f.id}>
                <span className="ok-check">✓</span> {f.titulo}
                <span className="finding-tool mono"> · {f.herramienta_origen}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [prog, setProg] = useState(null);
  const [error, setError] = useState(null);
  const [launching, setLaunching] = useState(false);
  const [findings, setFindings] = useState(null);
  const [busy, setBusy] = useState(false);
  const [aviso, setAviso] = useState(null);
  const [findingsError, setFindingsError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    getScan(id).then(setScan).catch((e) => setError(messagesFromError(e)[0]));
  }, [id]);

  const terminal = prog && (prog.status === "completado" || prog.status === "error");

  const loadFindings = useCallback(async () => {
    try {
      const f = await getFindings(id);
      setFindings(f);
      setFindingsError(null);
      return f;
    } catch (err) {
      // El error se muestra: antes se tragaba y, como el bloque de hallazgos
      // se renderiza solo si `findings` existe, un 500 del backend hacía
      // desaparecer toda la sección sin ninguna señal de que algo falló.
      setFindingsError(messagesFromError(err)[0]);
      return null;
    }
  }, [id]);

  useEffect(() => {
    if (terminal) loadFindings();
  }, [terminal, loadFindings]);

  // Progreso en vivo: WebSocket principal, polling de respaldo; la DB es la
  // fuente de verdad. Al llegar a estado terminal se corta todo.
  useEffect(() => {
    let ws = null, poll = null, debounce = null, stopped = false;
    const teardown = () => {
      stopped = true;
      if (ws) { try { ws.close(); } catch { /* noop */ } ws = null; }
      if (poll) { clearInterval(poll); poll = null; }
      clearTimeout(debounce);
    };
    const refetch = async () => {
      try {
        const p = await getProgress(id);
        if (stopped) return;
        setProg(p);
        if (p.status === "completado" || p.status === "error") teardown();
      } catch { /* la próxima señal reintenta */ }
    };
    const nudge = () => { clearTimeout(debounce); debounce = setTimeout(refetch, 250); };
    const startPolling = () => { if (poll || stopped) return; poll = setInterval(refetch, 2500); };
    refetch();
    try {
      ws = openProgressSocket(id, nudge);
      ws.onclose = () => { if (!stopped) startPolling(); };
      ws.onerror = () => { if (!stopped) startPolling(); };
    } catch { startPolling(); }
    return teardown;
  }, [id]);

  const launch = async () => {
    setLaunching(true);
    setError(null);
    try {
      setProg(await launchScan(id));
    } catch (e) {
      setError(messagesFromError(e)[0]);
    } finally {
      setLaunching(false);
    }
  };

  // No hay botón de "re-analizar" en la interfaz a propósito. Reprocesar
  // vuelve a interpretar la evidencia cruda ya guardada con los parsers
  // actuales: sirve después de cambiar un parser, no en el uso diario. El
  // endpoint sigue disponible (POST /scans/{id}/analyze) para lanzarlo por
  // consola. Para volver a barrer el objetivo está "Relanzar barrido".
  const relanzar = async () => {
    setBusy(true);
    setAviso(null);
    try {
      const nuevo = await relaunchScan(id);
      navigate(`/scans/${nuevo.id}`);
    } catch (err) {
      setAviso(messagesFromError(err)[0]);
      setBusy(false);
    }
  };

  if (error) {
    return (
      <div className="form-errors" role="alert"><p>{error}</p></div>
    );
  }
  if (!scan) return <p className="muted">Cargando análisis…</p>;

  const notLaunched = !prog || prog.status === "creado";
  const status = prog?.status || scan.status;

  return (
    <div className="detail">
      <header className="detail-hero">
        <div className="detail-hero-main">
          <p className="eyebrow2">análisis #{scan.id} · {scan.analysis_type}</p>
          <h1 className="detail-target mono">{scan.target}</h1>
          <div className="detail-status">
            <span className={`badge badge-${status}`}>{status}</span>
            {(scan.cliente || scan.project?.client) && (
              <span className="muted">· {scan.cliente || scan.project.client}</span>
            )}
          </div>
        </div>
        {aviso && <p className="detail-aviso">{aviso}</p>}
        {terminal && (
          <div className="detail-actions-top">
            <a className="btn btn-primary" href={reportUrl(id)}>Exportar informe</a>
            <button
              className="btn btn-ghost"
              disabled={busy}
              onClick={relanzar}
              title="Vuelve a ejecutar el barrido sobre el mismo objetivo, en un análisis nuevo"
            >
              {busy ? "…" : "Relanzar barrido"}
            </button>
          </div>
        )}
      </header>

      {terminal && findings && <SevHero summary={findings.summary} />}
      {terminal && findings && (
        <p className="findings-meta">
          <span><b className="mono">{findings.summary.a_validar}</b> a validar</span>
          <span><b className="mono">{findings.summary.positivos}</b> buena postura</span>
        </p>
      )}

      {/* Franja de metadatos (F15c). Antes era una fila de <span> con el
          rótulo y el valor pegados: "ProyectoPrueba 1ClientePrueba…" se leía
          como una sola palabra. Ahora cada dato es una columna con el rótulo
          arriba y el valor abajo, separadas por una línea. */}
      <dl className="meta-strip">
        <div className="meta-cell">
          <dt>Proyecto</dt><dd>{scan.project.name}</dd>
        </div>
        <div className="meta-cell">
          <dt>Cliente</dt><dd>{scan.cliente || scan.project.client || "—"}</dd>
        </div>
        <div className="meta-cell">
          <dt>Responsable</dt><dd>{scan.authorization.responsible_user}</dd>
        </div>
        <div className="meta-cell">
          <dt>Autorización</dt>
          <dd className={scan.authorization.authorized ? "meta-ok" : "meta-no"}>
            {scan.authorization.authorized ? "✓ confirmada" : "sin confirmar"}
          </dd>
        </div>
        <div className="meta-cell">
          <dt>Creado</dt><dd className="mono">{fmtDate(scan.created_at)}</dd>
        </div>
      </dl>

      {notLaunched ? (
        <div className="detail-actions">
          <button className="btn btn-primary btn-lg launch-btn" disabled={launching} onClick={launch}>
            {launching ? "Encolando…" : "Lanzar BIEC"}
          </button>
          <p className="hint">Corre las 5 etapas en orden sobre el objetivo autorizado.</p>
        </div>
      ) : (
        <div className="exec-wrap">
          <div className="section-label">
            <span className="section-label-text">ejecución</span>
            <span className="section-rule" />
          </div>
          <Progress prog={prog} />
        </div>
      )}

      {terminal && findings && <FindingsList data={findings} />}
      {terminal && !findings && (
        <div className="findings-wrap">
          <p className="section-label">
            <span className="section-label-text">hallazgos</span>
          </p>
          {findingsError ? (
            <p className="modal-err">
              No se pudieron cargar los hallazgos: {findingsError}
            </p>
          ) : (
            <p className="muted">Cargando hallazgos…</p>
          )}
        </div>
      )}
    </div>
  );
}
