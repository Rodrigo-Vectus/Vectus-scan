import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ArrowRight, FolderInput, Pencil, Trash2 } from "lucide-react";
import {
  deleteFolder,
  deleteScan,
  getDashboard,
  messagesFromError,
  moveScan,
  reportUrl,
  updateFolder,
} from "../api.js";
import { useAuth } from "../auth.jsx";
import { useFolders } from "../folders.jsx";

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

function ConfirmDelete({ scan, busy, error, onCancel, onConfirm }) {
  return (
    <div className="modal-overlay" onClick={busy ? undefined : onCancel}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()}>
        <h2 className="modal-title">Eliminar análisis #{scan.id}</h2>
        <p className="modal-body">
          Se eliminan del historial el análisis, sus hallazgos y la evidencia cruda
          guardada en disco.
        </p>
        <p className="modal-meta">
          <span className="mono">{scan.target}</span>
          {scan.cliente ? ` · ${scan.cliente}` : ""}
        </p>
        <p className="modal-warn">Esta acción no se puede deshacer.</p>
        {error && <p className="modal-err">{error}</p>}
        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={onCancel} disabled={busy}>Cancelar</button>
          <button className="btn btn-danger" onClick={onConfirm} disabled={busy}>
            {busy ? "Eliminando…" : "Eliminar"}
          </button>
        </div>
      </div>
    </div>
  );
}

function MoveDialog({ scan, folders, busy, error, onCancel, onConfirm }) {
  const [destino, setDestino] = useState(
    scan.folder_id === null || scan.folder_id === undefined ? "" : String(scan.folder_id)
  );
  return (
    <div className="modal-overlay" onClick={busy ? undefined : onCancel}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()}>
        <h2 className="modal-title">Mover análisis #{scan.id}</h2>
        <p className="modal-body">Elegí la carpeta de destino.</p>
        <p className="modal-meta">
          <span className="mono">{scan.target}</span>
          {scan.cliente ? ` · ${scan.cliente}` : ""}
        </p>
        <div className="field" style={{ marginTop: 14 }}>
          <select value={destino} onChange={(e) => setDestino(e.target.value)}>
            <option value="">Sin carpeta</option>
            {folders.map((f) => (
              <option key={f.id} value={f.id}>{f.nombre}</option>
            ))}
          </select>
        </div>
        {error && <p className="modal-err">{error}</p>}
        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={onCancel} disabled={busy}>Cancelar</button>
          <button
            className="btn btn-primary"
            onClick={() => onConfirm(destino === "" ? null : Number(destino))}
            disabled={busy}
          >
            {busy ? "Moviendo…" : "Mover"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Informes() {
  const [dash, setDash] = useState(null);
  const [q, setQ] = useState("");
  const [pendingDelete, setPendingDelete] = useState(null);
  const [pendingMove, setPendingMove] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [avisoCarpeta, setAvisoCarpeta] = useState(null);
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const { isAdmin } = useAuth();
  const { folders, refresh: refreshFolders } = useFolders();

  const filtro = params.get("carpeta"); // null = todos · "sin" · "<id>"
  const lista = folders || [];
  const carpetaActual = useMemo(
    () => lista.find((f) => String(f.id) === filtro) || null,
    [lista, filtro]
  );

  const recargar = async () => setDash(await getDashboard());

  useEffect(() => {
    getDashboard().then(setDash).catch(() => setDash({ scans: [] }));
  }, []);

  const open = (e) => {
    e.preventDefault();
    const id = q.trim().replace(/[^0-9]/g, "");
    if (id) navigate(`/scans/${id}`);
  };

  const confirmDelete = async () => {
    setBusy(true); setError(null);
    try {
      await deleteScan(pendingDelete.id);
      setPendingDelete(null);
      await Promise.all([recargar(), refreshFolders()]);
    } catch (err) {
      setError(messagesFromError(err)[0]);
    } finally { setBusy(false); }
  };

  const confirmMove = async (folderId) => {
    setBusy(true); setError(null);
    try {
      await moveScan(pendingMove.id, folderId);
      setPendingMove(null);
      await Promise.all([recargar(), refreshFolders()]);
    } catch (err) {
      setError(messagesFromError(err)[0]);
    } finally { setBusy(false); }
  };

  const renombrar = async () => {
    const nombre = window.prompt("Nuevo nombre de la carpeta", carpetaActual.nombre);
    if (!nombre || nombre.trim() === carpetaActual.nombre) return;
    setAvisoCarpeta(null);
    try {
      await updateFolder(carpetaActual.id, { nombre: nombre.trim() });
      await refreshFolders();
    } catch (err) {
      setAvisoCarpeta(messagesFromError(err)[0]);
    }
  };

  const borrarCarpeta = async () => {
    setAvisoCarpeta(null);
    try {
      await deleteFolder(carpetaActual.id);
      await refreshFolders();
      setParams({}); // volver a "Todos"
    } catch (err) {
      // El backend responde 409 con el detalle si la carpeta tiene análisis.
      setAvisoCarpeta(messagesFromError(err)[0]);
    }
  };

  const todos = dash ? dash.scans : null;
  const scans = useMemo(() => {
    if (!todos) return null;
    if (!filtro) return todos;
    if (filtro === "sin") return todos.filter((s) => !s.folder_id);
    return todos.filter((s) => String(s.folder_id) === filtro);
  }, [todos, filtro]);

  const titulo = carpetaActual
    ? carpetaActual.nombre
    : filtro === "sin"
      ? "Sin carpeta"
      : "Informes y desgloses";

  return (
    <div>
      <div className="page-head">
        <p className="eyebrow2">informes</p>
        <div className="page-title-row">
          <h1 className="page-title">{titulo}</h1>
          {carpetaActual && (
            <span className="page-title-actions">
              <button className="icon-btn" onClick={renombrar} title="Renombrar carpeta">
                <Pencil size={15} />
              </button>
              <button className="icon-btn" onClick={borrarCarpeta} title="Eliminar carpeta">
                <Trash2 size={15} />
              </button>
            </span>
          )}
        </div>
        <p className="page-sub">
          {filtro
            ? "Análisis de esta carpeta. Podés mover cualquiera desde el ícono de su fila."
            : "Ingresá el ID de un análisis para abrir su desglose y descargar el informe, o elegilo del listado."}
        </p>
        {avisoCarpeta && <p className="modal-err">{avisoCarpeta}</p>}
      </div>

      {!filtro && (
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
      )}

      {scans === null ? (
        <p className="muted">Cargando análisis…</p>
      ) : scans.length === 0 ? (
        <div className="empty">
          {filtro ? "Esta carpeta todavía no tiene análisis." : "Todavía no hay análisis registrados."}
        </div>
      ) : (
        <div className="rep-table">
          <div className="rep-head">
            <span>ID</span>
            <span>Fecha</span>
            <span>Objetivo</span>
            <span>Cliente</span>
            <span>Carpeta</span>
            <span>Hallazgos</span>
            <span></span>
          </div>
          {scans.map((s) => (
            <div key={s.id} className="rep-row">
              <span className="rep-id">#{s.id}</span>
              <span className="rep-date">{fmtDate(s.created_at)}</span>
              <Link to={`/scans/${s.id}`} className="rep-target mono">{s.target}</Link>
              <span>{s.cliente || "—"}</span>
              <span className="rep-folder">{s.folder_nombre || "—"}</span>
              <SevMini s={s} />
              <span className="rep-actions">
                <Link to={`/scans/${s.id}`}>desglose</Link>
                {(s.status === "completado" || s.status === "error") && (
                  <a href={reportUrl(s.id)}>informe</a>
                )}
                <button
                  type="button"
                  className="rep-icon"
                  onClick={() => { setError(null); setPendingMove(s); }}
                  title="Mover a una carpeta"
                  aria-label={`Mover análisis ${s.id}`}
                >
                  <FolderInput size={15} />
                </button>
                {isAdmin && (
                  <button
                    type="button"
                    className="rep-icon rep-del"
                    onClick={() => { setError(null); setPendingDelete(s); }}
                    title="Eliminar análisis"
                    aria-label={`Eliminar análisis ${s.id}`}
                  >
                    <Trash2 size={15} />
                  </button>
                )}
              </span>
            </div>
          ))}
        </div>
      )}

      {pendingDelete && (
        <ConfirmDelete
          scan={pendingDelete}
          busy={busy}
          error={error}
          onCancel={() => { setPendingDelete(null); setError(null); }}
          onConfirm={confirmDelete}
        />
      )}
      {pendingMove && (
        <MoveDialog
          scan={pendingMove}
          folders={lista}
          busy={busy}
          error={error}
          onCancel={() => { setPendingMove(null); setError(null); }}
          onConfirm={confirmMove}
        />
      )}
    </div>
  );
}
