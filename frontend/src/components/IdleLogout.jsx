import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";

// Minutos de inactividad antes de cerrar la sesión, y segundos de aviso
// previo. 15 minutos de reloj: el cartel aparece en el minuto 14.
const IDLE_MINUTES = 15;
const WARN_SECONDS = 60;

const IDLE_MS = IDLE_MINUTES * 60 * 1000;
const WARN_MS = WARN_SECONDS * 1000;

// Eventos que cuentan como actividad REAL del usuario. El polling de
// progreso y el WebSocket no están acá a propósito: si la pantalla queda
// abierta mirando un scan, eso no es actividad.
const EVENTS = ["mousedown", "mousemove", "keydown", "wheel", "touchstart", "scroll"];

// No reseteamos el contador en cada mousemove: alcanza con hacerlo como
// mucho una vez cada 5 s.
const THROTTLE_MS = 5000;

/**
 * Cierra la sesión tras IDLE_MINUTES sin interacción del usuario.
 *
 * Es un control de la interfaz, no una barrera de seguridad: la sesión del
 * backend sigue viva hasta que este componente llame a logout (o hasta que
 * venza su propio TTL). Sirve para el caso real —la consola desatendida—,
 * no contra alguien que tenga la cookie y hable con la API a mano.
 */
export default function IdleLogout() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();

  const [restante, setRestante] = useState(null); // segundos en el aviso
  const lastActivity = useRef(Date.now());
  const lastBump = useRef(0);
  const warning = useRef(false);

  const cerrar = useCallback(async () => {
    warning.current = false;
    setRestante(null);
    await signOut();
    navigate("/login", { replace: true, state: { idle: true } });
  }, [navigate, signOut]);

  const seguirConectado = useCallback(() => {
    lastActivity.current = Date.now();
    lastBump.current = Date.now();
    warning.current = false;
    setRestante(null);
  }, []);

  useEffect(() => {
    if (!user) return undefined;

    const onActivity = () => {
      // Durante el aviso ignoramos la actividad pasiva: el usuario tiene
      // que decidir explícitamente con el botón. Así un movimiento del
      // mouse al pasar no revive una sesión abandonada.
      if (warning.current) return;
      const now = Date.now();
      if (now - lastBump.current < THROTTLE_MS) return;
      lastBump.current = now;
      lastActivity.current = now;
    };

    EVENTS.forEach((e) =>
      window.addEventListener(e, onActivity, { passive: true })
    );

    const tick = setInterval(() => {
      const inactivo = Date.now() - lastActivity.current;
      if (inactivo >= IDLE_MS) {
        cerrar();
        return;
      }
      if (inactivo >= IDLE_MS - WARN_MS) {
        warning.current = true;
        setRestante(Math.ceil((IDLE_MS - inactivo) / 1000));
      }
    }, 1000);

    return () => {
      EVENTS.forEach((e) => window.removeEventListener(e, onActivity));
      clearInterval(tick);
    };
  }, [user, cerrar]);

  if (!user || restante === null) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-box">
        <h2 className="modal-title">Tu sesión está por cerrarse</h2>
        <p className="modal-body">
          No detectamos actividad en los últimos {IDLE_MINUTES - 1} minutos. Por
          seguridad, la sesión se cierra sola.
        </p>
        <p className="modal-meta">
          Se cierra en <span className="mono">{restante}</span> s
        </p>
        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={cerrar}>
            Cerrar ahora
          </button>
          <button className="btn btn-primary" onClick={seguirConectado} autoFocus>
            Seguir conectado
          </button>
        </div>
      </div>
    </div>
  );
}
