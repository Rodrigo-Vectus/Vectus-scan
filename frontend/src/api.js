const BASE = "/api";

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
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
export const getScan = (id) => req(`/scans/${id}`);
export const launchScan = (id) =>
  req(`/scans/${id}/launch`, { method: "POST" });
export const getProgress = (id) => req(`/scans/${id}/progress`);
export const getFindings = (id) => req(`/scans/${id}/findings`);
export const analyzeScan = (id) =>
  req(`/scans/${id}/analyze`, { method: "POST" });

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
