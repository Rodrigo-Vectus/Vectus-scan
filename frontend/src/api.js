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
