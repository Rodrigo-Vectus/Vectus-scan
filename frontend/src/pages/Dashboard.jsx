import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import { getDashboard } from "../api.js";
import { useFolders } from "../folders.jsx";
import { SegmentBar, StackedBars, Leyenda, SEV_LABEL } from "../components/Charts.jsx";

const SEVS = ["critica", "alta", "media", "baja"];
const RANGOS = [
  { id: "30", label: "30 días" },
  { id: "90", label: "90 días" },
  { id: "", label: "Todo" },
];

const fmtFecha = (iso, conHora = true) => {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("es-AR", {
      day: "2-digit", month: "2-digit",
      ...(conHora ? { hour: "2-digit", minute: "2-digit" } : {}),
    });
  } catch {
    return iso;
  }
};

/** Agrupa los scans en cubos temporales para la tendencia. */
function tendencia(scans, dias) {
  if (scans.length === 0) return [];
  const ahora = Date.now();
  const ventana = dias ? Number(dias) : 120;
  const cubos = 6;
  const ancho = (ventana * 86400000) / cubos;
  const out = Array.from({ length: cubos }, (_, i) => ({
    etiqueta: fmtFecha(new Date(ahora - (cubos - 1 - i) * ancho).toISOString(), false),
    valores: { critica: 0, alta: 0, media: 0, baja: 0 },
  }));
  for (const s of scans) {
    const idx = cubos - 1 - Math.floor((ahora - new Date(s.created_at).getTime()) / ancho);
    if (idx < 0 || idx >= cubos) continue;
    for (const k of SEVS) out[idx].valores[k] += s[k] || 0;
  }
  return out;
}

export default function Dashboard() {
  const [dash, setDash] = useState(null);
  const [rango, setRango] = useState("30");
  const [carpeta, setCarpeta] = useState("");
  const navigate = useNavigate();
  const { folders } = useFolders();

  useEffect(() => {
    getDashboard().then(setDash).catch(() => setDash({ scans: [] }));
  }, []);

  // Todo sale del payload del dashboard: sin llamadas extra ni estados de
  // carga intermedios, el filtro es instantáneo.
  const scans = useMemo(() => {
    let out = dash ? dash.scans : [];
    if (carpeta) out = out.filter((s) => String(s.folder_id) === carpeta);
    if (rango) {
      const desde = Date.now() - Number(rango) * 86400000;
      out = out.filter((s) => new Date(s.created_at).getTime() >= desde);
    }
    return out;
  }, [dash, carpeta, rango]);

  const tot = useMemo(() => {
    const t = { critica: 0, alta: 0, media: 0, baja: 0, a_validar: 0, en_curso: 0 };
    for (const s of scans) {
      for (const k of SEVS) t[k] += s[k] || 0;
      t.a_validar += s.a_validar || 0;
      if (s.status === "en_cola" || s.status === "corriendo") t.en_curso++;
    }
    t.vulns = SEVS.reduce((a, k) => a + t[k], 0);
    return t;
  }, [scans]);

  const objetivos = useMemo(() => {
    const m = new Map();
    for (const s of scans) {
      const d = m.get(s.target) || {
        target: s.target, id: s.id, ultimo: s.created_at, total: 0,
        valores: { critica: 0, alta: 0, media: 0, baja: 0 },
      };
      for (const k of SEVS) { d.valores[k] += s[k] || 0; d.total += s[k] || 0; }
      if (new Date(s.created_at) > new Date(d.ultimo)) { d.ultimo = s.created_at; d.id = s.id; }
      m.set(s.target, d);
    }
    return [...m.values()]
      .sort((a, b) =>
        b.valores.critica - a.valores.critica ||
        b.valores.alta - a.valores.alta ||
        b.total - a.total)
      .slice(0, 6);
  }, [scans]);

  if (!dash) return <p className="muted">Cargando dashboard…</p>;

  return (
    <div>
      <div className="page-head">
        <p className="eyebrow2">monitoreo</p>
        <h1 className="page-title">Dashboard</h1>
        <p className="page-sub">Estado agregado de los barridos y su exposición.</p>
      </div>

      <div className="dash-filtros">
        <div className="segmented">
          {RANGOS.map((r) => (
            <button key={r.id} className={rango === r.id ? "active" : ""}
                    onClick={() => setRango(r.id)}>
              {r.label}
            </button>
          ))}
        </div>
        <select value={carpeta} onChange={(e) => setCarpeta(e.target.value)}
                className="dash-select">
          <option value="">Todas las carpetas</option>
          {(folders || []).map((f) => (
            <option key={f.id} value={f.id}>{f.nombre}</option>
          ))}
        </select>
      </div>

      {scans.length === 0 ? (
        <div className="empty">No hay barridos en el período elegido.</div>
      ) : (
        <>
          {/* Un solo bloque fuerte en lugar de seis tarjetas: el número que
              importa, cómo se reparte, y el resto como contexto al costado. */}
          <section className="hero">
            <div className="hero-main">
              <p className="hero-label">Vulnerabilidades confirmadas</p>
              <p className={`hero-num ${tot.vulns ? "hay" : ""}`}>{tot.vulns}</p>
              <SegmentBar valores={tot} claves={SEVS} />
              <Leyenda claves={SEVS} valores={tot} />
            </div>
            <div className="hero-side">
              <Link to="/informes" className="hero-stat">
                <span className="hero-stat-num">{scans.length}</span>
                <span className="hero-stat-lbl">barridos</span>
              </Link>
              <div className="hero-stat">
                <span className="hero-stat-num">{tot.a_validar}</span>
                <span className="hero-stat-lbl">a validar</span>
              </div>
              <div className="hero-stat">
                <span className={`hero-stat-num ${tot.en_curso ? "activo" : ""}`}>
                  {tot.en_curso}
                </span>
                <span className="hero-stat-lbl">en curso</span>
              </div>
            </div>
          </section>

          <div className="dash-grid">
            <section className="panel-card">
              <p className="panel-title">
                Objetivos con más exposición
                <Link to="/informes" className="panel-link">
                  ver todos <ArrowRight size={13} />
                </Link>
              </p>
              <table className="dash-table">
                <tbody>
                  {objetivos.map((o) => (
                    <tr key={o.target} onClick={() => navigate(`/scans/${o.id}`)}>
                      <td className="mono trunc" title={o.target}>{o.target}</td>
                      <td className="col-sev">
                        {o.total === 0 ? (
                          <span className="sev-none">sin vulns</span>
                        ) : (
                          SEVS.map((k) => (o.valores[k] ? (
                            <span key={k} className={`dot-sev sev-${k}`}
                                  title={SEV_LABEL[k]}>{o.valores[k]}</span>
                          ) : null))
                        )}
                      </td>
                      <td className="col-fecha mono">{fmtFecha(o.ultimo, false)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>

            <section className="panel-card">
              <p className="panel-title">Tendencia</p>
              <StackedBars series={tendencia(scans, rango)} claves={SEVS} />
            </section>
          </div>
        </>
      )}
    </div>
  );
}
