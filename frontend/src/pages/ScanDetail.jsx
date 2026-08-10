import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { getScan, messagesFromError } from "../api.js";

function fmtDate(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getScan(id)
      .then(setScan)
      .catch((err) => setError(messagesFromError(err)[0]));
  }, [id]);

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

  return (
    <div className="detail">
      <section className="intro">
        <p className="eyebrow">barrido #{scan.id} · {scan.analysis_type}</p>
        <div className="detail-title-row">
          <h1 className="h1 mono">{scan.target}</h1>
          <span className={`badge badge-lg badge-${scan.status}`}>
            {scan.status}
          </span>
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
            <dt>Objetivo</dt>
            <dd className="mono">{scan.authorization.target}</dd>
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
            <dt>Registrada</dt>
            <dd className="mono">{fmtDate(scan.authorization.created_at)}</dd>
          </dl>
        </div>
      </div>

      <div className="detail-actions">
        <button className="btn btn-primary btn-lg" disabled>
          Lanzar BIEC
        </button>
        <p className="hint">
          La ejecución por etapas se habilita con el motor (próxima fase).
        </p>
      </div>
    </div>
  );
}
