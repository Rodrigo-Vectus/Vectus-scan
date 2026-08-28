/**
 * Gráficos del dashboard, en SVG a mano.
 *
 * No se usa librería de charts a propósito: son dos formas simples, y una
 * dependencia traería su propio sistema de temas que habría que pelear
 * contra la paleta. Acá los colores salen de las mismas variables CSS que
 * el resto de la consola, así que el tema claro/oscuro funciona solo.
 */

export const SEV_COLOR = {
  critica: "var(--sev-critica)",
  alta: "var(--sev-alta)",
  media: "var(--sev-media)",
  baja: "var(--sev-baja)",
};

export const SEV_LABEL = {
  critica: "Crítica",
  alta: "Alta",
  media: "Media",
  baja: "Baja",
};

/** Barra única segmentada: el reparto de la exposición total. */
export function SegmentBar({ valores, claves }) {
  const total = claves.reduce((a, k) => a + (valores[k] || 0), 0);
  if (!total) return <div className="segbar segbar-vacia" />;
  return (
    <div className="segbar">
      {claves.map((k) => {
        const v = valores[k] || 0;
        if (!v) return null;
        return (
          <span
            key={k}
            style={{ width: `${(v / total) * 100}%`, background: SEV_COLOR[k] }}
            title={`${SEV_LABEL[k]}: ${v}`}
          />
        );
      })}
    </div>
  );
}

/** Barras apiladas por período. `series` = [{etiqueta, valores:{sev:n}}]. */
export function StackedBars({ series, claves, alto = 130 }) {
  const max = Math.max(
    1,
    ...series.map((s) => claves.reduce((a, k) => a + (s.valores[k] || 0), 0))
  );
  const n = series.length || 1;
  const ancho = 100 / n;

  return (
    <div className="chart-stack">
      <svg viewBox={`0 0 100 ${alto}`} preserveAspectRatio="none"
           className="chart-svg" style={{ height: alto }}>
        {series.map((s, i) => {
          let y = alto;
          return claves.map((k) => {
            const v = s.valores[k] || 0;
            if (!v) return null;
            const h = (v / max) * (alto - 6);
            y -= h;
            return (
              <rect key={`${i}-${k}`} x={i * ancho + ancho * 0.22} y={y}
                    width={ancho * 0.56} height={h} fill={SEV_COLOR[k]}>
                <title>{`${s.etiqueta} · ${SEV_LABEL[k]}: ${v}`}</title>
              </rect>
            );
          });
        })}
      </svg>
      <div className="chart-xaxis">
        {series.map((s, i) => (
          <span key={i} style={{ width: `${ancho}%` }}>{s.etiqueta}</span>
        ))}
      </div>
    </div>
  );
}

/** Leyenda compartida. */
export function Leyenda({ claves, valores }) {
  return (
    <div className="leyenda">
      {claves.map((k) => (
        <span key={k} className="leyenda-item">
          <i style={{ background: SEV_COLOR[k] }} />
          {SEV_LABEL[k]}
          {valores ? <b className="mono">{valores[k] ?? 0}</b> : null}
        </span>
      ))}
    </div>
  );
}
