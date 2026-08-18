import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import { getDashboard, reportUrl } from "../api.js";

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

function SevMini({ s }) {
  const parts = [];
  if (s.critica) parts.push(["critica", s.critica]);
  if (s.alta) parts.push(["alta", s.alta]);
  if (s.media) parts.push(["media", s.media]);
  if (s.baja) parts.push(["baja", s.baja]);
  if (parts.length === 0) {
    return <span className="sev-none">{s.status === "completado" ? "sin vulns" : "—"}</span>;
  }
  return (
    <span className="sev-mini">
      {parts.map(([sev, n]) => (
        <span key={sev} className={`chip chip-sm sev-${sev}`}>{n}</span>
      ))}
      {s.a_validar > 0 && <span className="chip chip-sm chip-validar">{s.a_validar}?</span>}
    </span>
  );
}

export default function Informes() {
  const [dash, setDash] = useState(null);
  const [q, setQ] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    getDashboard().then(setDash).catch(() => setDash({ scans: [] }));
  }, []);

  const open = (e) => {
    e.preventDefault();
    const id = q.trim().replace(/[^0-9]/g, "");
    if (id) navigate(`/scans/${id}`);
  };

  const scans = dash ? dash.scans : null;

  return (
    <div>
      <div className="page-head">
        <p className="eyebrow2">informes</p>
        <h1 className="page-title">Informes y desgloses</h1>
        <p className="page-sub">
          Ingresá el ID de un análisis para abrir su desglose y descargar el informe, o
          elegilo del listado.
        </p>
      </div>

      <form className="id-lookup" onSubmit={open}>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="ID del análisis (p. ej. 5)"
          inputMode="numeric"
        />
        <button className="btn btn-primary" type="submit">
          Abrir <ArrowRight size={15} style={{ verticalAlign: "-2px" }} />
        </button>
      </form>

      {scans === null ? (
        <p className="muted">Cargando análisis…</p>
      ) : scans.length === 0 ? (
        <div className="empty">Todavía no hay análisis registrados.</div>
      ) : (
        <div className="rep-table">
          <div className="rep-head">
            <span>ID</span>
            <span>Fecha</span>
            <span>Objetivo</span>
            <span>Cliente</span>
            <span>Hallazgos</span>
            <span></span>
          </div>
          {scans.map((s) => (
            <div key={s.id} className="rep-row">
              <span className="rep-id">#{s.id}</span>
              <span className="rep-date">{fmtDate(s.created_at)}</span>
              <Link to={`/scans/${s.id}`} className="rep-target mono">{s.target}</Link>
              <span>{s.cliente || "—"}</span>
              <SevMini s={s} />
              <span className="rep-actions">
                <Link to={`/scans/${s.id}`}>desglose</Link>
                {(s.status === "completado" || s.status === "error") && (
                  <a href={reportUrl(s.id)}>informe</a>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
