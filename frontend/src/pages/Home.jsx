import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getAnalysisTypes, getDashboard, reportUrl } from "../api.js";

function AnalysisCard({ type, onLaunch }) {
  const enabled = type.enabled;
  return (
    <div className={`analysis-card ${enabled ? "is-enabled" : "is-disabled"}`}>
      <div className="analysis-head">
        <h3 className="analysis-title">{type.label}</h3>
        {enabled ? (
          <span className="tag tag-active">activo</span>
        ) : (
          <span className="tag tag-soon">próximamente</span>
        )}
      </div>
      <p className="analysis-desc">{type.description}</p>
      <button
        className="btn btn-primary analysis-cta"
        disabled={!enabled}
        onClick={() => enabled && onLaunch(type.id)}
      >
        {enabled ? "Nuevo barrido" : "No disponible"}
      </button>
    </div>
  );
}

const fmtDate = (iso) => {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("es-AR", {
      day: "2-digit", month: "2-digit", year: "2-digit",
      hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return iso;
  }
};

function StatCards({ d }) {
  return (
    <div className="stat-cards">
      <div className="stat-card">
        <span className="stat-num">{d.total_scans}</span>
        <span className="stat-lbl">Barridos</span>
      </div>
      <div className="stat-card">
        <span className="stat-num">{d.completados}</span>
        <span className="stat-lbl">Completados</span>
      </div>
      <div className="stat-card">
        <span className="stat-num">{d.en_curso}</span>
        <span className="stat-lbl">En curso</span>
      </div>
      <div className="stat-card stat-vulns">
        <div className="stat-sev">
          <span className="chip sev-critica">{d.vuln_critica} C</span>
          <span className="chip sev-alta">{d.vuln_alta} A</span>
          <span className="chip sev-media">{d.vuln_media} M</span>
          <span className="chip sev-baja">{d.vuln_baja} B</span>
        </div>
        <span className="stat-lbl">Vulnerabilidades confirmadas</span>
      </div>
    </div>
  );
}

function SevMini({ s }) {
  const parts = [];
  if (s.critica) parts.push(["critica", s.critica]);
  if (s.alta) parts.push(["alta", s.alta]);
  if (s.media) parts.push(["media", s.media]);
  if (s.baja) parts.push(["baja", s.baja]);
  if (parts.length === 0 && s.status === "completado") {
    return <span className="sev-none">sin vulns</span>;
  }
  return (
    <span className="sev-mini">
      {parts.map(([sev, n]) => (
        <span key={sev} className={`chip chip-sm sev-${sev}`}>
          {n}
        </span>
      ))}
      {s.a_validar > 0 && (
        <span className="chip chip-sm chip-validar">{s.a_validar}?</span>
      )}
    </span>
  );
}

function History({ scans }) {
  if (scans === null) return <p className="muted">Cargando barridos…</p>;
  if (scans.length === 0) {
    return (
      <div className="empty">
        Todavía no hay barridos. Elegí BIEC arriba para registrar el primero.
      </div>
    );
  }
  return (
    <div className="history">
      <div className="history-head">
        <span>Fecha</span>
        <span>Cliente</span>
        <span>Objetivo</span>
        <span>Estado</span>
        <span>Hallazgos</span>
        <span></span>
      </div>
      {scans.map((s) => (
        <div key={s.id} className="history-row">
          <span className="mono h-date">{fmtDate(s.created_at)}</span>
          <span className="h-cli">{s.cliente || "—"}</span>
          <Link to={`/scans/${s.id}`} className="mono h-target">
            {s.target}
          </Link>
          <span className={`badge badge-${s.status}`}>{s.status}</span>
          <span className="h-sev">
            <SevMini s={s} />
          </span>
          <span className="h-actions">
            <Link to={`/scans/${s.id}`} className="link-sm">
              ver
            </Link>
            {(s.status === "completado" || s.status === "error") && (
              <a className="link-sm" href={reportUrl(s.id)}>
                informe
              </a>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function Home() {
  const [types, setTypes] = useState(null);
  const [dash, setDash] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    getAnalysisTypes().then(setTypes).catch(() => setTypes([]));
    getDashboard()
      .then(setDash)
      .catch(() => setDash({ scans: [] }));
  }, []);

  const launch = (id) => {
    if (id === "biec") navigate("/scans/new");
  };

  return (
    <div className="home">
      <section className="intro">
        <p className="eyebrow">análisis de vulnerabilidades</p>
        <h1 className="h1">Elegí el tipo de barrido</h1>
        <p className="lead">
          Cada barrido corre sobre un objetivo con autorización registrada. Sin
          ese permiso, no se lanza.
        </p>
      </section>

      {dash && dash.total_scans > 0 && <StatCards d={dash} />}

      <section className="analysis-grid">
        {types === null ? (
          <p className="muted">Cargando…</p>
        ) : (
          types.map((t) => (
            <AnalysisCard key={t.id} type={t} onLaunch={launch} />
          ))
        )}
      </section>

      <section className="recent">
        <div className="section-label">
          <span className="section-label-text">historial de barridos</span>
          <span className="section-rule" />
        </div>
        <History scans={dash ? dash.scans : null} />
      </section>
    </div>
  );
}
