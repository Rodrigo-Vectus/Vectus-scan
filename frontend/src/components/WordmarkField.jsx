import { useEffect, useRef } from "react";
import { useTheme } from "../theme.jsx";
import { wordmarkPoints } from "../assets/wordmarkPoints.js";

/**
 * Campo de partículas del login (F14a).
 *
 * Dos capas sobre un mismo canvas:
 *  1. Una red ambiente de nodos unidos por proximidad, recorrida por un
 *     barrido radial que los enciende a su paso. No se dibuja el haz: solo
 *     se ve el efecto, que es lo que hace el producto (recorrer una
 *     superficie y detectar lo que hay).
 *  2. El wordmark de VECTUS, armado con la nube de puntos muestreada del
 *     logo real. Entra de izquierda a derecha, se asienta y queda
 *     respirando; cada 6,5 s una banda lo recorre encendiendo las letras.
 *
 * Sin librerías: canvas 2D a mano, como los gráficos del dashboard (D43),
 * así no hay churn en el lockfile del build de Docker.
 *
 * Los colores salen de las variables CSS, así que el cambio de tema no
 * necesita lógica propia: se releen y listo.
 *
 * @param {{ boxRef: React.RefObject<HTMLElement> }} props
 *   boxRef apunta al elemento que reserva el espacio del wordmark; de su
 *   `getBoundingClientRect()` sale dónde armar la palabra.
 */
export default function WordmarkField({ boxRef }) {
  const canvasRef = useRef(null);
  const { theme } = useTheme();
  // Se guarda en un ref para que el bucle lo lea sin re-crear el efecto.
  const paletaRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const box = boxRef?.current;
    if (!canvas || !box) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const sinMovimiento = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;

    const LINK = 130; // distancia máxima para unir dos nodos
    let ancho = 0;
    let alto = 0;
    let red = [];
    let marcas = [];
    let barrido = 0;
    let t0 = performance.now();
    let raf = null;

    /* ── paleta ──────────────────────────────────────────────── */
    const leerPaleta = () => {
      const s = getComputedStyle(document.documentElement);
      const v = (n) => s.getPropertyValue(n).trim();
      paletaRef.current = {
        nodo: v("--muted"),
        caliente: v("--accent"),
        familia: [v("--brand-blue"), v("--brand-gray"), v("--brand-sky")],
      };
    };
    leerPaleta();

    /** Convierte #rgb o #rrggbb a rgba(). Devuelve el original si no matchea
     *  (una variable podría venir ya como rgb()). */
    const conAlfa = (color, alfa) => {
      let h = color.replace("#", "");
      if (h.length === 3) h = h.split("").map((c) => c + c).join("");
      if (h.length !== 6 || /[^0-9a-f]/i.test(h)) return color;
      const r = parseInt(h.slice(0, 2), 16);
      const g = parseInt(h.slice(2, 4), 16);
      const b = parseInt(h.slice(4, 6), 16);
      return `rgba(${r},${g},${b},${alfa})`;
    };

    /* ── construcción ────────────────────────────────────────── */
    const armarRed = () => {
      // Densidad por área con techo: en un monitor grande no queremos
      // quemar CPU dibujando cientos de nodos.
      const n = Math.min(80, Math.round((ancho * alto) / 17000));
      red = Array.from({ length: n }, () => ({
        x: Math.random() * ancho,
        y: Math.random() * alto,
        vx: (Math.random() - 0.5) * 0.14,
        vy: (Math.random() - 0.5) * 0.14,
        r: Math.random() * 1.3 + 0.7,
        e: 0, // excitación del barrido: 1 = recién alcanzado
      }));
    };

    const puntos = wordmarkPoints();

    const ubicarMarcas = () => {
      const r = box.getBoundingClientRect();
      const primeraVez = marcas.length !== puntos.length;
      if (primeraVez) {
        marcas = puntos.map((p) => ({
          fam: p.fam,
          fase: Math.random() * 6.283,
          vel: 0.55 + Math.random() * 0.9,
          demora: 0,
          avance: 0,
          ox: 0, oy: 0, // origen
          tx: 0, ty: 0, // destino
          x: 0, y: 0,
        }));
      }
      puntos.forEach((p, i) => {
        const m = marcas[i];
        m.tx = r.left + p.x * r.width;
        m.ty = r.top + p.y * r.height;
        // La demora crece con x: la palabra se arma de izquierda a derecha.
        m.demora = 260 + p.x * 620 + Math.random() * 160;
        if (primeraVez) {
          const a = Math.random() * 6.283;
          const d = 220 + Math.random() * 520;
          m.ox = m.tx + Math.cos(a) * d;
          m.oy = m.ty + Math.sin(a) * d;
          m.x = m.ox;
          m.y = m.oy;
        }
      });
    };

    const medir = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      ancho = window.innerWidth;
      alto = window.innerHeight;
      canvas.width = ancho * dpr;
      canvas.height = alto * dpr;
      canvas.style.width = `${ancho}px`;
      canvas.style.height = `${alto}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      armarRed();
      ubicarMarcas();
    };

    /* ── dibujo ──────────────────────────────────────────────── */
    const suavizar = (t) => 1 - Math.pow(1 - t, 3.2);

    const dibujarRed = () => {
      const P = paletaRef.current;
      const ox = ancho / 2;
      const oy = alto * 0.46;
      barrido = (barrido + 0.0052) % 6.2832;

      for (const p of red) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < -20) p.x = ancho + 20;
        if (p.x > ancho + 20) p.x = -20;
        if (p.y < -20) p.y = alto + 20;
        if (p.y > alto + 20) p.y = -20;
        let a = Math.atan2(p.y - oy, p.x - ox);
        if (a < 0) a += 6.2832;
        let d = Math.abs(a - barrido);
        if (d > Math.PI) d = 6.2832 - d;
        if (d < 0.05) p.e = 1;
        p.e *= 0.982;
      }

      ctx.lineWidth = 1;
      for (let i = 0; i < red.length; i++) {
        for (let j = i + 1; j < red.length; j++) {
          const a = red[i];
          const b = red[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const d2 = dx * dx + dy * dy;
          if (d2 > LINK * LINK) continue;
          const k = 1 - Math.sqrt(d2) / LINK;
          const calor = Math.max(a.e, b.e);
          ctx.strokeStyle =
            calor > 0.04
              ? conAlfa(P.caliente, 0.14 * k * (0.35 + calor * 1.4))
              : conAlfa(P.nodo, 0.14 * k);
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
      for (const p of red) {
        ctx.fillStyle =
          p.e > 0.04
            ? conAlfa(P.caliente, Math.min(1, 0.5 + p.e * 0.5))
            : conAlfa(P.nodo, 0.5);
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r * (1 + p.e * 1.4), 0, 6.2832);
        ctx.fill();
      }
    };

    const dibujarMarcas = (t, ahora) => {
      const P = paletaRef.current;
      const r = box.getBoundingClientRect();
      // Banda que recorre la palabra cada 6,5 s, una vez armada.
      const ciclo = 6500;
      const fase = ((t - 2200) % ciclo) / ciclo;
      const bandaX = t > 2200 ? r.left + fase * (r.width + 160) - 80 : -9999;

      for (let i = 0; i < marcas.length; i++) {
        const m = marcas[i];
        // El destino se recalcula en CADA cuadro, no solo al redimensionar:
        // el alto del formulario cambia al pasar de paso o al aparecer un
        // aviso, y el flex centrado desplaza la caja. Si el destino quedara
        // fijo, la palabra se despegaría y terminaría pisando el texto.
        m.tx = r.left + puntos[i].x * r.width;
        m.ty = r.top + puntos[i].y * r.height;

        if (m.avance < 1) {
          const local = (t - m.demora) / (760 / m.vel);
          m.avance = Math.max(0, Math.min(1, local));
          const e = suavizar(m.avance);
          m.x = m.ox + (m.tx - m.ox) * e;
          m.y = m.oy + (m.ty - m.oy) * e;
        } else {
          // Asentado: deriva de menos de un píxel, para que no quede muerto.
          m.x = m.tx + Math.sin(ahora / 1400 + m.fase) * 0.8;
          m.y = m.ty + Math.cos(ahora / 1700 + m.fase) * 0.8;
        }
        const dx = Math.abs(m.x - bandaX);
        const encendido = m.avance >= 1 && dx < 52 ? 1 - dx / 52 : 0;
        const alfa = 0.35 + m.avance * 0.55;

        if (encendido > 0.02) {
          ctx.fillStyle = conAlfa(P.caliente, Math.min(1, alfa + encendido * 0.5));
          ctx.beginPath();
          ctx.arc(m.x, m.y, 1.4 + encendido * 1.5, 0, 6.2832);
        } else {
          ctx.fillStyle = conAlfa(P.familia[m.fam], alfa);
          ctx.beginPath();
          ctx.arc(m.x, m.y, 1.4, 0, 6.2832);
        }
        ctx.fill();
      }
    };

    const cuadro = (ahora) => {
      ctx.clearRect(0, 0, ancho, alto);
      dibujarRed();
      dibujarMarcas(ahora - t0, ahora);
      raf = requestAnimationFrame(cuadro);
    };

    /** Un solo cuadro, con la palabra ya armada y quieta. */
    const cuadroQuieto = () => {
      const P = paletaRef.current;
      ctx.clearRect(0, 0, ancho, alto);
      for (const p of red) {
        ctx.fillStyle = conAlfa(P.nodo, 0.5);
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, 6.2832);
        ctx.fill();
      }
      for (const m of marcas) {
        m.x = m.tx;
        m.y = m.ty;
        m.avance = 1;
        ctx.fillStyle = conAlfa(P.familia[m.fam], 0.9);
        ctx.beginPath();
        ctx.arc(m.x, m.y, 1.4, 0, 6.2832);
        ctx.fill();
      }
    };

    const arrancar = () => {
      if (raf) cancelAnimationFrame(raf);
      if (sinMovimiento) {
        cuadroQuieto();
        return;
      }
      raf = requestAnimationFrame(cuadro);
    };

    const frenar = () => {
      if (raf) cancelAnimationFrame(raf);
      raf = null;
    };

    // Con la pestaña oculta no se gasta CPU.
    const alCambiarVisibilidad = () => {
      if (document.hidden) frenar();
      else arrancar();
    };

    medir();
    arrancar();
    window.addEventListener("resize", medir);
    document.addEventListener("visibilitychange", alCambiarVisibilidad);

    return () => {
      frenar();
      window.removeEventListener("resize", medir);
      document.removeEventListener("visibilitychange", alCambiarVisibilidad);
    };
  }, [boxRef]);

  // El tema cambió: las variables CSS ya tienen otros valores, hay que
  // releerlas. Se hace en un efecto aparte para no reiniciar la animación.
  useEffect(() => {
    const s = getComputedStyle(document.documentElement);
    const v = (n) => s.getPropertyValue(n).trim();
    if (!paletaRef.current) return;
    paletaRef.current = {
      nodo: v("--muted"),
      caliente: v("--accent"),
      familia: [v("--brand-blue"), v("--brand-gray"), v("--brand-sky")],
    };
  }, [theme]);

  return <canvas ref={canvasRef} className="login-field-canvas" aria-hidden="true" />;
}
