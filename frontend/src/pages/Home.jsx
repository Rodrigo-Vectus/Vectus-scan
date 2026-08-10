import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getAnalysisTypes, listScans } from "../api.js";

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

function RecentScans({ scans }) {
  if (scans === null) return <p className="muted">Cargando barridos…</p>;
  if (scans.length === 0) {
    return (
      <div className="empty">
        Todavía no hay barridos. Elegí BIEC arriba para registrar el primero.
      </div>
    );
  }
  return (
    <ul className="scan-list">
      {scans.map((s) => (
        <li key={s.id}>
          <Link to={`/scans/${s.id}`} className="scan-row">
            <span className={`badge badge-${s.status}`}>{s.status}</span>
            <span className="scan-target mono">{s.target}</span>
            <span className="scan-project">{s.project.name}</span>
            <span className="scan-type mono">{s.analysis_type}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

export default function Home() {
  const [types, setTypes] = useState(null);
  const [scans, setScans] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    getAnalysisTypes().then(setTypes).catch(() => setTypes([]));
    listScans().then(setScans).catch(() => setScans([]));
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
          Cada barrido corre sobre un objetivo con autorización registrada.
          Sin ese permiso, no se lanza.
        </p>
      </section>

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
          <span className="section-label-text">barridos recientes</span>
          <span className="section-rule" />
        </div>
        <RecentScans scans={scans} />
      </section>
    </div>
  );
}
