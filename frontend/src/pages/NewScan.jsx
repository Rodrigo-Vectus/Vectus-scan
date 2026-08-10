import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createScan, messagesFromError } from "../api.js";

const EMPTY = {
  project_name: "",
  client: "",
  target: "",
  responsible_user: "",
  note: "",
};

export default function NewScan() {
  const [form, setForm] = useState(EMPTY);
  const [authorized, setAuthorized] = useState(false);
  const [errors, setErrors] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  // Requisitos mínimos del lado del cliente. La validación dura vive en la API.
  const requiredFilled =
    form.project_name.trim() &&
    form.target.trim() &&
    form.responsible_user.trim();
  const canSubmit = Boolean(requiredFilled) && authorized && !submitting;

  const submit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    setErrors([]);
    try {
      const scan = await createScan({
        project_name: form.project_name.trim(),
        client: form.client.trim() || null,
        target: form.target.trim(),
        responsible_user: form.responsible_user.trim(),
        analysis_type: "biec",
        authorized: true,
        note: form.note.trim() || null,
      });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setErrors(messagesFromError(err));
      setSubmitting(false);
    }
  };

  return (
    <div className="newscan">
      <section className="intro">
        <p className="eyebrow">nuevo barrido · BIEC</p>
        <h1 className="h1">Registrar objetivo</h1>
        <p className="lead">
          Cargá el objetivo y su autorización. El barrido queda registrado en
          estado <span className="mono">creado</span>; la ejecución llega con el
          motor.
        </p>
      </section>

      <div className="form">
        <div className="field">
          <label htmlFor="project_name">Proyecto</label>
          <input
            id="project_name"
            value={form.project_name}
            onChange={set("project_name")}
            placeholder="Auditoría Q3 — Portal público"
          />
        </div>

        <div className="field">
          <label htmlFor="client">
            Cliente <span className="optional">opcional</span>
          </label>
          <input
            id="client"
            value={form.client}
            onChange={set("client")}
            placeholder="ACME S.A."
          />
        </div>

        <div className="field">
          <label htmlFor="target">Objetivo</label>
          <input
            id="target"
            className="mono"
            value={form.target}
            onChange={set("target")}
            placeholder="https://ejemplo.com"
          />
          <p className="hint">URL o host del activo a escanear.</p>
        </div>

        <div className="field">
          <label htmlFor="responsible_user">Responsable</label>
          <input
            id="responsible_user"
            value={form.responsible_user}
            onChange={set("responsible_user")}
            placeholder="Quién declara contar con el permiso"
          />
        </div>

        {/* ── Compuerta de autorización ── */}
        <div className={`auth-gate ${authorized ? "is-open" : "is-locked"}`}>
          <div className="auth-gate-head">
            <span className="auth-lock" aria-hidden="true">
              {authorized ? "🔓" : "🔒"}
            </span>
            <span className="auth-gate-title">Autorización</span>
          </div>
          <label className="auth-check">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
            />
            <span>
              Confirmo que cuento con autorización por escrito para escanear
              este objetivo.
            </span>
          </label>
          <textarea
            className="auth-note mono"
            value={form.note}
            onChange={set("note")}
            placeholder="Referencia de la autorización (nº de contrato, orden, etc.) — opcional"
            rows={2}
          />
        </div>

        {errors.length > 0 && (
          <div className="form-errors" role="alert">
            {errors.map((m, i) => (
              <p key={i}>{m}</p>
            ))}
          </div>
        )}

        <button className="btn btn-primary btn-lg" disabled={!canSubmit} onClick={submit}>
          {submitting
            ? "Registrando…"
            : authorized
            ? "Registrar barrido"
            : "Confirmá la autorización para continuar"}
        </button>
      </div>
    </div>
  );
}
