import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ScanSearch, Layers, ShieldAlert, ArrowRight } from "lucide-react";
import { getAnalysisTypes } from "../api.js";

const ICONS = { biec: ScanSearch, bajo_nivel: Layers, alto_nivel: ShieldAlert };

/* Qué herramientas corre cada análisis. El BIEC son 7 etapas y ver las
   herramientas reales dice más del producto que una descripción genérica. */
const STACK = {
  biec: ["nmap", "whatweb", "subfinder", "ffuf", "nuclei", "nikto",
         "retire.js", "wapiti", "wpscan", "curl"],
};

/**
 * Fila de análisis (rediseñada en F15).
 *
 * Antes eran tres tarjetas en una grilla. Se sacaron: una caja con borde,
 * sombra y un botón a ancho completo es el patrón por defecto de cualquier
 * plantilla, y con tres elementos deja media pantalla vacía. Ahora son filas
 * separadas por una línea, que es como se listan las cosas en una consola.
 */
function ScannerRow({ type, onLaunch }) {
  const Icon = ICONS[type.id] || ScanSearch;
  const enabled = type.enabled;
  const stack = STACK[type.id];

  return (
    <div className={`srow ${enabled ? "is-on" : "is-off"}`}>
      <div className="srow-mark">
        <Icon />
      </div>

      <div className="srow-body">
        <div className="srow-head">
          <h2 className="srow-name">{type.label}</h2>
          <span className={`srow-state ${enabled ? "on" : ""}`}>
            {enabled ? "operativo" : "próximamente"}
          </span>
        </div>
        <p className="srow-desc">{type.description}</p>
        {stack && (
          <ul className="srow-stack" aria-label="Herramientas que ejecuta">
            {stack.map((h) => <li key={h}>{h}</li>)}
          </ul>
        )}
      </div>

      <div className="srow-action">
        {enabled ? (
          <button className="srow-go" onClick={() => onLaunch(type.id)}>
            Nuevo barrido <ArrowRight size={15} />
          </button>
        ) : (
          <span className="srow-na">No disponible</span>
        )}
      </div>
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
        <div className="srow-list">
          {types.map((t) => (
            <ScannerRow key={t.id} type={t} onLaunch={launch} />
          ))}
        </div>
      )}
    </div>
  );
}
