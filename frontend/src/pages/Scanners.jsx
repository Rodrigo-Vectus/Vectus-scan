import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ScanSearch, Layers, ShieldAlert } from "lucide-react";
import { getAnalysisTypes } from "../api.js";

const ICONS = { biec: ScanSearch, bajo_nivel: Layers, alto_nivel: ShieldAlert };

function ScannerCard({ type, onLaunch }) {
  const Icon = ICONS[type.id] || ScanSearch;
  const enabled = type.enabled;
  return (
    <div className={`scanner ${enabled ? "enabled" : "disabled"}`}>
      <div className="scanner-top">
        <div className="scanner-ico">
          <Icon />
        </div>
        <span className={`pill ${enabled ? "on" : ""}`}>
          {enabled ? "activo" : "próximamente"}
        </span>
      </div>
      <div className="scanner-name">{type.label}</div>
      <p className="scanner-desc">{type.description}</p>
      <button
        className="btn btn-primary"
        disabled={!enabled}
        onClick={() => enabled && onLaunch(type.id)}
      >
        {enabled ? "Nuevo barrido" : "No disponible"}
      </button>
    </div>
  );
}

export default function Scanners() {
  const [types, setTypes] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    getAnalysisTypes().then(setTypes).catch(() => setTypes([]));
  }, []);

  const launch = (id) => {
    if (id === "biec") navigate("/scans/new");
  };

  return (
    <div>
      <div className="page-head">
        <p className="eyebrow2">scanners</p>
        <h1 className="page-title">Análisis de vulnerabilidades</h1>
        <p className="page-sub">
          Cada barrido corre sobre un objetivo con autorización registrada. Sin ese
          permiso, no se lanza.
        </p>
      </div>

      {types === null ? (
        <p className="muted">Cargando…</p>
      ) : (
        <div className="scanner-grid">
          {types.map((t) => (
            <ScannerCard key={t.id} type={t} onLaunch={launch} />
          ))}
        </div>
      )}
    </div>
  );
}
