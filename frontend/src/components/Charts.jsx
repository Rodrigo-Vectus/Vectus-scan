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

/**
 * Barras apiladas por período (reescrito en F15e).
 *
 * Qué estaba mal y por qué se cambió:
 *
 * · `preserveAspectRatio="none"` estiraba el SVG para llenar el contenedor,
 *   así que el sistema de coordenadas no era proporcional: las barras se
 *   deformaban horizontalmente y cualquier radio de esquina salía ovalado.
 *   Ahora el viewBox es proporcional y el SVG se escala con `width: 100%`.
 *
 * · No había línea de base ni referencia de escala. Una barra de 9 se veía
 *   igual que una de 90; no se podía saber si el período fue bueno o malo.
 *   Ahora hay eje inferior, dos marcas horizontales y un techo redondeado a
 *   1, 2 o 5 por década, porque un eje que termina en 37 no se lee.
 *
 * · Los períodos sin barridos no dibujaban nada y el panel quedaba con
 *   huecos que parecían un error de carga. Ahora se marcan con una base
 *   tenue: "acá no hubo barridos" es información.
 *
 * · Las etiquetas del eje X eran <span> en un div aparte, con anchos en
 *   porcentaje que no coincidían con la posición real de las barras. Ahora
 *   son <text> dentro del SVG, centradas en su columna.
 */
export function StackedBars({ series, claves, alto = 172 }) {
  const W = 340;
  const PAD_IZQ = 24;   // espacio para las marcas de valor
  const PAD_DER = 8;
  const PAD_SUP = 14;   // aire para el total sobre la barra más alta
  const PAD_INF = 24;   // espacio para las etiquetas de período

  const totales = series.map((s) =>
    claves.reduce((a, k) => a + (s.valores[k] || 0), 0)
  );
  const pico = Math.max(1, ...totales);

  /** Redondea hacia arriba a 1, 2 o 5 por década (1, 2, 5, 10, 20, 50…). */
  const techoLegible = (n) => {
    const decada = Math.pow(10, Math.floor(Math.log10(n)));
    for (const m of [1, 2, 5, 10]) {
      if (n <= m * decada) return m * decada;
    }
    return 10 * decada;
  };
  const techo = techoLegible(pico);

  const areaAlta = alto - PAD_SUP - PAD_INF;
  const areaAncha = W - PAD_IZQ - PAD_DER;
  const paso = areaAncha / (series.length || 1);
  const anchoBarra = Math.min(30, paso * 0.52);
  const y = (v) => PAD_SUP + areaAlta - (v / techo) * areaAlta;
  const marcas = techo > 1 ? [0, techo / 2, techo] : [0, techo];

  return (
    <div className="chart-stack">
      <svg viewBox={`0 0 ${W} ${alto}`} className="chart-svg"
           role="img" aria-label="Vulnerabilidades confirmadas por período">
        {marcas.map((m) => (
          <g key={m}>
            <line className="chart-grid" x1={PAD_IZQ} x2={W - PAD_DER}
                  y1={y(m)} y2={y(m)} />
            <text className="chart-tick" x={PAD_IZQ - 7} y={y(m) + 3.5}
                  textAnchor="end">{m}</text>
          </g>
        ))}

        {series.map((s, i) => {
          const centro = PAD_IZQ + paso * i + paso / 2;
          const x = centro - anchoBarra / 2;
          const total = totales[i];

          if (!total) {
            return (
              <g key={i}>
                <rect className="chart-vacio" x={x} y={y(0) - 2}
                      width={anchoBarra} height={2} rx={1}>
                  <title>{`${s.etiqueta}: sin barridos`}</title>
                </rect>
                <text className="chart-tick" x={centro} y={alto - 7}
                      textAnchor="middle">{s.etiqueta}</text>
              </g>
            );
          }

          // Se apila de abajo hacia arriba en el orden de `claves`.
          let acumulado = 0;
          const tramos = claves
            .filter((k) => s.valores[k])
            .map((k) => {
              const v = s.valores[k];
              const arriba = y(acumulado + v);
              const altura = y(acumulado) - arriba;
              acumulado += v;
              return { k, v, arriba, altura };
            });

          return (
            <g key={i} className="chart-col">
              {tramos.map(({ k, v, arriba, altura }, j) => (
                <rect key={k} x={x} y={arriba} width={anchoBarra} height={altura}
                      fill={SEV_COLOR[k]}
                      rx={j === tramos.length - 1 ? 3 : 0}>
                  <title>{`${s.etiqueta} · ${SEV_LABEL[k]}: ${v}`}</title>
                </rect>
              ))}
              <text className="chart-total" x={centro} y={y(total) - 6}
                    textAnchor="middle">{total}</text>
              <text className="chart-tick" x={centro} y={alto - 7}
                    textAnchor="middle">{s.etiqueta}</text>
            </g>
          );
        })}

        <line className="chart-eje" x1={PAD_IZQ} x2={W - PAD_DER}
              y1={y(0)} y2={y(0)} />
      </svg>
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
