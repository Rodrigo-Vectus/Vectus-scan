import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getDashboard } from "../api.js";

const fmtDate = (iso) => {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("es-AR", {
      day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return iso;
  }
};

const SEVS = [
  ["critica", "Crítica"],
  ["alta", "Alta"],
  ["media", "Media"],
  ["baja", "Baja"],
];

function SevDistribution({ d }) {
  const vals = {
    critica: d.vuln_critica, alta: d.vuln_alta, media: d.vuln_media, baja: d.vuln_baja,
  };
  const max = Math.max(1, ...Object.values(vals));
  return (
    <div className="panel-card">
      <p className="panel-title">Vulnerabilidades por severidad</p>
      {SEVS.map(([k, label]) => (
        <div key={k} className="sevbar-row">
          <span className="sevbar-name">{label}</span>
          <span className="sevbar-track">
            <span
              className={`sevbar-fill fill-${k}`}
              style={{ width: `${(vals[k] / max) * 100}%` }}
            />
          </span>
          <span className="sevbar-val">{vals[k]}</span>
        </div>
      ))}
    </div>
  );
}

function RecentActivity({ scans }) {
  const recent = scans.slice(0, 6);
  return (
    <div className="panel-card">
      <p className="panel-title">Actividad reciente</p>
      {recent.length === 0 ? (
        <p className="muted">Sin actividad.</p>
      ) : (
        recent.map((s) => (
          <Link key={s.id} to={`/scans/${s.id}`} className="act-row">
            <span className={`badge badge-${s.status}`}>{s.status}</span>
            <span className="act-target mono">{s.target}</span>
            <span className="act-date mono">{fmtDate(s.created_at)}</span>
          </Link>
        ))
      )}
    </div>
  );
}

export default function Dashboard() {
  const [d, setD] = useState(null);

  useEffect(() => {
    getDashboard().then(setD).catch(() => setD(null));
  }, []);

  if (!d) {
    return (
      <div>
        <div className="page-head">
          <p className="eyebrow2">monitoreo</p>
          <h1 className="page-title">Dashboard</h1>
        </div>
        <p className="muted">Cargando indicadores…</p>
      </div>
    );
  }

  return (
    <div>
      <div className="page-head">
        <p className="eyebrow2">monitoreo</p>
        <h1 className="page-title">Dashboard</h1>
        <p className="page-sub">Estado agregado de los barridos y su exposición.</p>
      </div>

      <div className="kpi-row">
        <div className="kpi accent">
          <div className="kpi-num">{d.total_scans}</div>
          <div className="kpi-lbl">Barridos</div>
        </div>
        <div className="kpi">
          <div className="kpi-num">{d.completados}</div>
          <div className="kpi-lbl">Completados</div>
        </div>
        <div className="kpi">
          <div className="kpi-num">{d.en_curso}</div>
          <div className="kpi-lbl">En curso</div>
        </div>
        <div className="kpi">
          <div className="kpi-num">{d.vuln_total}</div>
          <div className="kpi-lbl">Vulnerabilidades</div>
        </div>
      </div>

      <div className="dash-grid">
        <SevDistribution d={d} />
        <RecentActivity scans={d.scans} />
      </div>
    </div>
  );
}
