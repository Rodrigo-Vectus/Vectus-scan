import { useEffect, useState } from "react";

// F0: pantalla mínima de scaffolding. Consulta /api/health para probar
// el circuito frontend → proxy → backend → (Postgres + Redis).
// La UI real (selección de análisis, formulario de scan con checkbox de
// autorización obligatorio) se construye en la Fase 1.
export default function App() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then(setHealth)
      .catch(() => setError(true));
  }, []);

  const dotClass = error
    ? "dot dot-red"
    : !health
    ? "dot dot-yellow"
    : health.status === "ok"
    ? "dot dot-green"
    : "dot dot-yellow";

  const statusText = error
    ? "backend sin respuesta"
    : !health
    ? "conectando…"
    : `backend: ${health.status}`;

  return (
    <div className="shell">
      <div className="card">
        <div className="brand">
          <span className="brand-mark">VECTUS</span>
          <span className="brand-sub">SCAN</span>
        </div>
        <p className="tagline">
          Orquestación de análisis de vulnerabilidades
        </p>

        <div className="status">
          <span className={dotClass} />
          <span className="status-text">{statusText}</span>
        </div>

        {health && (
          <div className="checks">
            <span>db: {health.checks.database ? "ok" : "fail"}</span>
            <span>redis: {health.checks.redis ? "ok" : "fail"}</span>
          </div>
        )}

        <p className="phase">Fase 0 · scaffolding</p>
      </div>
    </div>
  );
}
