import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  getScan,
  getProgress,
  getFindings,
  analyzeScan,
  launchScan,
  openProgressSocket,
  messagesFromError,
} from "../api.js";

function fmtDate(iso) {
  try {
    return new Date(iso).toLocaleString();
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
              <span key={t.id} className={`chip chip-${t.status}`}>
                {t.tool}
              </span>
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
    const elapsed = started_at
      ? (Date.now() - new Date(started_at).getTime()) / 1000
      : 0;
    label = "transcurrido";
    value = `${fmtDur(elapsed)} / est. ${fmtDur(estimated_seconds)}`;
  } else {
    const total =
      started_at && finished_at
        ? (new Date(finished_at).getTime() - new Date(started_at).getTime()) /
          1000
        : null;
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
        <span className={`badge badge-lg badge-${prog.status}`}>
          {prog.status}
        </span>
        <Timer prog={prog} />
      </div>

      <div className="progress-track" aria-label={`progreso ${pct}%`}>
        <div
          className={`progress-fill ${errored ? "has-error" : ""}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="progress-meta mono">
        {done}/{total} etapas
      </p>

      <ul className="stage-list">
        {prog.stages.map((s) => (
          <StageRow key={s.id} stage={s} />
        ))}
      </ul>
    </div>
  );
}

const SEV_LABEL = {
  critica: "Crítica",
  alta: "Alta",
  media: "Media",
  baja: "Baja",
  info: "Info",
};
const SEV_KEYS = ["critica", "alta", "media", "baja", "info"];

function Findings({ scanId }) {
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = () =>
    getFindings(scanId)
      .then(setData)
      .catch(() => {});

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  const reanalyze = async () => {
    setBusy(true);
    try {
      await analyzeScan(scanId);
      // el reproceso corre en el worker; recargamos unas veces
      let n = 0;
      const iv = setInterval(async () => {
        await load();
        if (++n >= 4) clearInterval(iv);
      }, 1500);
    } catch {
      /* noop */
    } finally {
      setTimeout(() => setBusy(false), 1500);
    }
  };

  if (!data) return null;
  const { summary, findings } = data;
  const reportables = findings.filter(
    (f) => f.estado !== "positivo" && f.estado !== "falso_positivo"
  );
  const positivos = findings.filter((f) => f.estado === "positivo");

  return (
    <div className="findings-wrap">
      <div className="section-label">
        <span className="section-label-text">hallazgos</span>
        <span className="section-rule" />
        <button className="btn btn-ghost btn-sm" disabled={busy} onClick={reanalyze}>
          {busy ? "reprocesando…" : "re-analizar"}
        </button>
      </div>

      <div className="sev-summary">
        {SEV_KEYS.map((k) => (
          <div key={k} className={`sev-cell sev-${k}`}>
            <span className="sev-count">{summary[k]}</span>
            <span className="sev-name">{SEV_LABEL[k]}</span>
          </div>
        ))}
        <div className="sev-cell sev-total">
          <span className="sev-count">{summary.total}</span>
          <span className="sev-name">Total</span>
        </div>
      </div>
      <p className="findings-meta mono">
        {summary.a_validar} a validar · {summary.positivos} buena postura
      </p>

      {reportables.length === 0 && (
        <p className="muted">Sin hallazgos reportables.</p>
      )}

      <div className="finding-list">
        {reportables.map((f) => (
          <details key={f.id} className="finding">
            <summary>
              <span className={`badge badge-sev sev-${f.severidad}`}>
                {SEV_LABEL[f.severidad] || f.severidad}
              </span>
              <span className="finding-title">{f.titulo}</span>
              {f.estado === "a_validar" && (
                <span className="badge badge-validar">a validar</span>
              )}
              <span className="finding-tool mono">{f.herramienta_origen}</span>
            </summary>
            <dl className="finding-detail">
              {f.sistema_afectado && (
                <>
                  <dt>Sistema</dt>
                  <dd className="mono">{f.sistema_afectado}</dd>
                </>
              )}
              {f.cve && f.cve !== "No aplica" && (
                <>
                  <dt>CVE</dt>
                  <dd className="mono">{f.cve}</dd>
                </>
              )}
              {f.cwe && (
                <>
                  <dt>CWE</dt>
                  <dd className="mono">{f.cwe}</dd>
                </>
              )}
              {f.evidencia && (
                <>
                  <dt>Evidencia</dt>
                  <dd>{f.evidencia}</dd>
                </>
              )}
              {f.recomendacion && (
                <>
                  <dt>Recomendación</dt>
                  <dd>{f.recomendacion}</dd>
                </>
              )}
              {f.mas_info && (
                <>
                  <dt>Más info</dt>
                  <dd className="mono">{f.mas_info}</dd>
                </>
              )}
              {f.ocurrencias > 1 && (
                <>
                  <dt>Ocurrencias</dt>
                  <dd>{f.ocurrencias}</dd>
                </>
              )}
            </dl>
          </details>
        ))}
      </div>

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

  useEffect(() => {
    getScan(id)
      .then(setScan)
      .catch((e) => setError(messagesFromError(e)[0]));
  }, [id]);

  // Progreso en vivo: WebSocket como canal principal, polling como respaldo.
  // La DB es la fuente de verdad: ante cualquier aviso (WS o tick) se vuelve
  // a pedir getProgress. Al llegar a estado terminal se corta todo.
  useEffect(() => {
    let ws = null;
    let poll = null;
    let debounce = null;
    let stopped = false;

    const teardown = () => {
      stopped = true;
      if (ws) {
        try {
          ws.close();
        } catch {
          /* noop */
        }
        ws = null;
      }
      if (poll) {
        clearInterval(poll);
        poll = null;
      }
      clearTimeout(debounce);
    };

    const refetch = async () => {
      try {
        const p = await getProgress(id);
        if (stopped) return;
        setProg(p);
        if (p.status === "completado" || p.status === "error") teardown();
      } catch {
        /* la próxima señal reintenta */
      }
    };

    const nudge = () => {
      clearTimeout(debounce);
      debounce = setTimeout(refetch, 250);
    };

    const startPolling = () => {
      if (poll || stopped) return;
      poll = setInterval(refetch, 2500);
    };

    refetch(); // snapshot inicial

    try {
      ws = openProgressSocket(id, nudge);
      ws.onclose = () => {
        if (!stopped) startPolling();
      };
      ws.onerror = () => {
        if (!stopped) startPolling();
      };
    } catch {
      startPolling();
    }

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

  if (error) {
    return (
      <div className="detail">
        <div className="form-errors" role="alert">
          <p>{error}</p>
        </div>
      </div>
    );
  }

  if (!scan) return <p className="muted">Cargando barrido…</p>;

  const notLaunched = !prog || prog.status === "creado";

  return (
    <div className="detail">
      <section className="intro">
        <p className="eyebrow">
          barrido #{scan.id} · {scan.analysis_type}
        </p>
        <div className="detail-title-row">
          <h1 className="h1 mono">{scan.target}</h1>
        </div>
      </section>

      <div className="detail-grid">
        <div className="panel">
          <div className="section-label">
            <span className="section-label-text">proyecto</span>
            <span className="section-rule" />
          </div>
          <dl className="kv">
            <dt>Proyecto</dt>
            <dd>{scan.project.name}</dd>
            <dt>Cliente</dt>
            <dd>{scan.project.client || "—"}</dd>
            <dt>Creado</dt>
            <dd className="mono">{fmtDate(scan.created_at)}</dd>
          </dl>
        </div>

        <div className="panel panel-auth">
          <div className="section-label">
            <span className="section-label-text">autorización</span>
            <span className="section-rule" />
          </div>
          <dl className="kv">
            <dt>Responsable</dt>
            <dd>{scan.authorization.responsible_user}</dd>
            <dt>Confirmada</dt>
            <dd>
              {scan.authorization.authorized ? (
                <span className="ok-check">✓ sí</span>
              ) : (
                "no"
              )}
            </dd>
            <dt>Referencia</dt>
            <dd className="mono">{scan.authorization.note || "—"}</dd>
          </dl>
        </div>
      </div>

      {notLaunched ? (
        <div className="detail-actions">
          <button
            className="btn btn-primary btn-lg launch-btn"
            disabled={launching}
            onClick={launch}
          >
            {launching ? "Encolando…" : "Lanzar BIEC"}
          </button>
          <p className="hint">
            Corre las 5 etapas en orden sobre el objetivo autorizado.
          </p>
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

      {prog && (prog.status === "completado" || prog.status === "error") && (
        <Findings scanId={id} />
      )}
    </div>
  );
}
