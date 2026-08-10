import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import {
  getScan,
  getProgress,
  launchScan,
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

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [prog, setProg] = useState(null);
  const [error, setError] = useState(null);
  const [launching, setLaunching] = useState(false);
  const pollRef = useRef(null);

  useEffect(() => {
    getScan(id)
      .then(setScan)
      .catch((e) => setError(messagesFromError(e)[0]));
    getProgress(id)
      .then(setProg)
      .catch(() => {});
  }, [id]);

  const running = prog && RUNNING.has(prog.status);

  useEffect(() => {
    if (!running) return;
    pollRef.current = setInterval(async () => {
      try {
        setProg(await getProgress(id));
      } catch {
        /* red intermitente: el próximo tick reintenta */
      }
    }, 2000);
    return () => clearInterval(pollRef.current);
  }, [running, id]);

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
    </div>
  );
}
