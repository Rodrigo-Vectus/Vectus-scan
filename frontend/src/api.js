const BASE = "/api";

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin", // manda la cookie de sesión (mismo origen)
    ...opts,
  });

  if (!res.ok) {
    let detail;
    try {
      detail = (await res.json()).detail;
    } catch {
      detail = res.statusText;
    }
    const err = new Error("request failed");
    err.status = res.status;
    err.detail = detail;
    throw err;
  }

  return res.status === 204 ? null : res.json();
}

// Convierte el `detail` de FastAPI (string o lista de errores de validación)
// en mensajes legibles para el usuario.
export function messagesFromError(err) {
  const d = err?.detail;
  if (!d) return ["Ocurrió un error inesperado."];
  if (typeof d === "string") return [d];
  if (Array.isArray(d)) {
    return d.map((e) => (e.msg || "").replace(/^Value error,\s*/, "").trim());
  }
  return ["Ocurrió un error inesperado."];
}

export const getAnalysisTypes = () => req("/analysis-types");
export const createScan = (body) =>
  req("/scans", { method: "POST", body: JSON.stringify(body) });
export const listScans = () => req("/scans");
export const getDashboard = () => req("/scans/dashboard");
export const getScan = (id) => req(`/scans/${id}`);
export const launchScan = (id) =>
  req(`/scans/${id}/launch`, { method: "POST" });
export const getProgress = (id) => req(`/scans/${id}/progress`);
export const getFindings = (id) => req(`/scans/${id}/findings`);
export const analyzeScan = (id) =>
  req(`/scans/${id}/analyze`, { method: "POST" });
// Elimina el análisis del historial (hallazgos + evidencia). Solo admin.
export const deleteScan = (id) => req(`/scans/${id}`, { method: "DELETE" });
export const reportUrl = (id) => `${BASE}/scans/${id}/report.docx`;

// WebSocket de progreso en vivo (F2b). Cada mensaje es un "aviso" de cambio;
// el llamador reacciona volviendo a pedir getProgress. Devuelve el socket
// para poder cerrarlo. Los mensajes tipo "ping" se ignoran.
export function openProgressSocket(id, onNudge) {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${window.location.host}/api/ws/scans/${id}`);
  ws.onmessage = (ev) => {
    let m = null;
    try {
      m = JSON.parse(ev.data);
    } catch {
      /* mensaje no-JSON: igual tratamos como aviso */
    }
    if (!m || m.type !== "ping") onNudge(m);
  };
  return ws;
}

// ─── Autenticación / usuarios (F7) ──────────────────────────────────
export const requestCode = (email) =>
  req("/auth/request-code", { method: "POST", body: JSON.stringify({ email }) });
export const verifyCode = (email, code) =>
  req("/auth/verify", { method: "POST", body: JSON.stringify({ email, code }) });
export const logout = () => req("/auth/logout", { method: "POST" });
export const getMe = () => req("/auth/me");

export const listUsers = () => req("/users");
export const createUser = (body) =>
  req("/users", { method: "POST", body: JSON.stringify(body) });
export const updateUser = (id, body) =>
  req(`/users/${id}`, { method: "PATCH", body: JSON.stringify(body) });

export const getAuthEvents = (params = {}) => {
  const q = new URLSearchParams();
  if (params.email) q.set("email", params.email);
  if (params.limit) q.set("limit", String(params.limit));
  const qs = q.toString();
  return req(`/auth/events${qs ? `?${qs}` : ""}`);
};

// ─── Carpetas (F10) ──────────────────────────────────────────────────
export const listFolders = () => req("/folders");
export const createFolder = (body) =>
  req("/folders", { method: "POST", body: JSON.stringify(body) });
export const updateFolder = (id, body) =>
  req(`/folders/${id}`, { method: "PATCH", body: JSON.stringify(body) });
export const deleteFolder = (id) => req(`/folders/${id}`, { method: "DELETE" });
export const moveScan = (id, folder_id) =>
  req(`/scans/${id}/folder`, { method: "PATCH", body: JSON.stringify({ folder_id }) });
