import { useEffect, useState, useCallback } from "react";
import {
  listUsers,
  createUser,
  updateUser,
  getAuthEvents,
  messagesFromError,
} from "../api.js";
import { useAuth } from "../auth.jsx";

const ROLES = ["administrador", "analista"];
const KIND_LABEL = {
  login: "ingreso",
  logout: "salida",
  code_sent: "código enviado",
  code_failed: "código fallido",
  login_failed: "ingreso fallido",
};

function fmt(dt) {
  if (!dt) return "—";
  try {
    return new Date(dt).toLocaleString("es-AR", {
      day: "2-digit",
      month: "2-digit",
      year: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return dt;
  }
}

export default function Usuarios() {
  const { user, isAdmin } = useAuth();
  const [users, setUsers] = useState(null);
  const [events, setEvents] = useState(null);
  const [errors, setErrors] = useState([]);
  const [form, setForm] = useState({ email: "", nombre: "", rol: "analista" });
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setErrors([]);
    try {
      const list = await listUsers();
      setUsers(list);
    } catch (err) {
      setErrors(messagesFromError(err));
      setUsers([]);
    }
    if (isAdmin) {
      try {
        setEvents(await getAuthEvents({ limit: 50 }));
      } catch {
        setEvents([]);
      }
    }
  }, [isAdmin]);

  useEffect(() => {
    load();
  }, [load]);

  const create = async () => {
    if (!form.email.trim() || !form.nombre.trim() || creating) return;
    setCreating(true);
    setErrors([]);
    try {
      await createUser({
        email: form.email.trim().toLowerCase(),
        nombre: form.nombre.trim(),
        rol: form.rol,
      });
      setForm({ email: "", nombre: "", rol: "analista" });
      await load();
    } catch (err) {
      setErrors(messagesFromError(err));
    } finally {
      setCreating(false);
    }
  };

  const patch = async (id, body) => {
    setErrors([]);
    try {
      await updateUser(id, body);
      await load();
    } catch (err) {
      setErrors(messagesFromError(err));
    }
  };

  return (
    <div>
      <div className="page-head">
        <p className="eyebrow2">gestión</p>
        <h1 className="page-title">Usuarios</h1>
        <p className="page-sub">
          {isAdmin
            ? "Alta, edición y roles. El acceso es por código de un solo uso enviado al email registrado."
            : "Usuarios con acceso a la plataforma."}
        </p>
      </div>

      {errors.length > 0 && (
        <div className="form-errors" role="alert">
          {errors.map((m, i) => (
            <p key={i}>{m}</p>
          ))}
        </div>
      )}

      {isAdmin && (
        <div className="user-create">
          <input
            className="mono"
            placeholder="email@vectus.la"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
          />
          <input
            placeholder="Nombre y apellido"
            value={form.nombre}
            onChange={(e) => setForm({ ...form, nombre: e.target.value })}
          />
          <select value={form.rol} onChange={(e) => setForm({ ...form, rol: e.target.value })}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <button
            className="btn btn-primary"
            disabled={!form.email.trim() || !form.nombre.trim() || creating}
            onClick={create}
          >
            {creating ? "Creando…" : "Agregar"}
          </button>
        </div>
      )}

      <div className="utable">
        <div className="utable-head">
          <span>Email</span>
          <span>Nombre</span>
          <span>Rol</span>
          <span>Estado</span>
          <span>Alta</span>
        </div>
        {users === null ? (
          <p className="muted" style={{ padding: "14px 16px" }}>
            Cargando…
          </p>
        ) : users.length === 0 ? (
          <p className="muted" style={{ padding: "14px 16px" }}>
            Sin usuarios.
          </p>
        ) : (
          users.map((u) => (
            <div className="utable-row" key={u.id}>
              <span className="mono u-email">
                {u.email}
                {u.id === user?.id && <em className="u-you"> (vos)</em>}
              </span>
              <span>{u.nombre}</span>
              <span>
                {isAdmin ? (
                  <select
                    className="u-rolsel"
                    value={u.rol}
                    onChange={(e) => patch(u.id, { rol: e.target.value })}
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                ) : (
                  <span className={`pill ${u.rol === "administrador" ? "on" : ""}`}>{u.rol}</span>
                )}
              </span>
              <span>
                {isAdmin ? (
                  <button
                    className={`u-toggle ${u.activo ? "is-on" : "is-off"}`}
                    onClick={() => patch(u.id, { activo: !u.activo })}
                  >
                    {u.activo ? "activo" : "inactivo"}
                  </button>
                ) : (
                  <span className={u.activo ? "u-on" : "u-off"}>{u.activo ? "activo" : "inactivo"}</span>
                )}
              </span>
              <span className="u-date">{fmt(u.created_at)}</span>
            </div>
          ))
        )}
      </div>

      {isAdmin && (
        <div className="accesos-wrap">
          <div className="section-label">
            <span className="section-label-text">accesos recientes</span>
            <span className="section-rule" />
          </div>
          <div className="utable">
            <div className="utable-head acc-head">
              <span>Fecha</span>
              <span>Email</span>
              <span>Evento</span>
              <span>IP</span>
            </div>
            {events === null ? (
              <p className="muted" style={{ padding: "14px 16px" }}>
                Cargando…
              </p>
            ) : events.length === 0 ? (
              <p className="muted" style={{ padding: "14px 16px" }}>
                Sin eventos.
              </p>
            ) : (
              events.map((e) => (
                <div className="utable-row acc-row" key={e.id}>
                  <span className="u-date mono">{fmt(e.at)}</span>
                  <span className="mono u-email">{e.email}</span>
                  <span className={`acc-kind acc-${e.kind}`}>{KIND_LABEL[e.kind] || e.kind}</span>
                  <span className="mono u-ip">{e.ip || "—"}</span>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
