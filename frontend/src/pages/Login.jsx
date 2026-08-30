import { useEffect, useRef, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { requestCode, verifyCode, messagesFromError } from "../api.js";
import { useAuth } from "../auth.jsx";
import ThemeSwitch from "../components/ThemeSwitch.jsx";
import WordmarkField from "../components/WordmarkField.jsx";

/**
 * Rejilla de 6 celdas para el código (F14a).
 *
 * Reemplaza al input único con `letter-spacing`. Gana pegar el código
 * completo de una (que es lo que se hace en la práctica: se copia del mail),
 * avance automático y retroceso que vuelve a la celda anterior.
 * Hacia afuera sigue siendo el mismo string de 6 dígitos, así que la lógica
 * de verificación no cambia.
 */
function CodeGrid({ value, onChange, onEnter, disabled }) {
  const refs = useRef([]);
  const digitos = value.padEnd(6, " ").slice(0, 6).split("");

  const escribir = (i, raw) => {
    const d = raw.replace(/\D/g, "").slice(-1);
    const arr = value.padEnd(6, " ").slice(0, 6).split("");
    arr[i] = d || " ";
    // Se recorta a la derecha: el string nunca lleva espacios al final.
    onChange(arr.join("").replace(/\s+$/, ""));
    if (d && i < 5) refs.current[i + 1]?.focus();
  };

  const tecla = (i, e) => {
    if (e.key === "Enter") return onEnter?.();
    if (e.key === "Backspace" && !digitos[i].trim() && i > 0) {
      refs.current[i - 1]?.focus();
    }
    if (e.key === "ArrowLeft" && i > 0) refs.current[i - 1]?.focus();
    if (e.key === "ArrowRight" && i < 5) refs.current[i + 1]?.focus();
  };

  const pegar = (e) => {
    e.preventDefault();
    const d = (e.clipboardData.getData("text") || "").replace(/\D/g, "").slice(0, 6);
    if (!d) return;
    onChange(d);
    refs.current[Math.min(d.length, 5)]?.focus();
  };

  return (
    <div className="code-grid" onPaste={pegar}>
      {[0, 1, 2, 3, 4, 5].map((i) => (
        <input
          key={i}
          ref={(el) => (refs.current[i] = el)}
          className={digitos[i].trim() ? "lleno" : ""}
          inputMode="numeric"
          autoComplete={i === 0 ? "one-time-code" : "off"}
          maxLength={1}
          disabled={disabled}
          value={digitos[i].trim()}
          onChange={(e) => escribir(i, e.target.value)}
          onKeyDown={(e) => tecla(i, e)}
          onFocus={(e) => e.target.select()}
          aria-label={`Dígito ${i + 1} de 6`}
          autoFocus={i === 0}
        />
      ))}
    </div>
  );
}

export default function Login() {
  const [step, setStep] = useState("email"); // "email" | "code"
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [errors, setErrors] = useState([]);
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);

  const { refresh } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const dest = location.state?.from?.pathname || "/";
  // Llega con state.idle cuando el temporizador cerró la sesión sola.
  const porInactividad = location.state?.idle === true;

  // Caja que reserva el espacio del wordmark. El canvas la mide para saber
  // dónde armar la palabra; no dibuja nada por sí misma.
  const cajaWordmark = useRef(null);

  // El wordmark tarda ~1,5 s en armarse y la primera pantalla lo espera para
  // no competir. Al cambiar de paso ya no hay nada que esperar.
  const [primeraVez, setPrimeraVez] = useState(true);
  useEffect(() => {
    const t = setTimeout(() => setPrimeraVez(false), 2600);
    return () => clearTimeout(t);
  }, []);

  const sendCode = async () => {
    if (!email.trim() || busy) return;
    setBusy(true);
    setErrors([]);
    setInfo("");
    try {
      const reenvio = step === "code";
      await requestCode(email.trim().toLowerCase());
      setStep("code");
      // Sin este aviso, tocar "Reenviar código" no daba ninguna señal.
      if (reenvio) setInfo("Código reenviado.");
      // Antes acá se seteaba un aviso genérico ("te enviamos un código,
      // revisá tu correo"). Es la misma información que la línea de abajo,
      // que además dice a qué dirección y cuánto dura: el aviso duplicado
      // solo empujaba el layout y tapaba la rejilla del código.
    } catch (err) {
      // 429: demasiado seguido. Igual pasamos al paso de código.
      if (err.status === 429) {
        setStep("code");
        setInfo("Ya te enviamos un código hace poco. Revisá tu correo.");
      } else {
        setErrors(messagesFromError(err));
      }
    } finally {
      setBusy(false);
    }
  };

  // La rejilla puede dejar HUECOS: si se borra un dígito del medio queda
  // "123 56", cuyo .trim().length también es 6. Validar con la expresión
  // regular es lo único que garantiza seis dígitos corridos.
  const codigoCompleto = /^\d{6}$/.test(code);

  const verify = async () => {
    if (!codigoCompleto || busy) return;
    setBusy(true);
    setErrors([]);
    try {
      await verifyCode(email.trim().toLowerCase(), code);
      await refresh();
      navigate(dest, { replace: true });
    } catch (err) {
      setErrors(messagesFromError(err));
      setBusy(false);
    }
  };

  const changeEmail = () => {
    setStep("email");
    setCode("");
    setErrors([]);
    setInfo("");
  };

  const claseSeq = `login-seq${primeraVez && step === "email" ? "" : " rapida"}`;

  return (
    <div className="login-screen">
      <WordmarkField boxRef={cajaWordmark} />

      {/* El selector de tema vive fuera del Layout, así que en el login hay
          que montarlo aparte. Comparte el mismo estado y persistencia. */}
      <div className="login-theme">
        <ThemeSwitch />
      </div>

      <div className="login-body">
        {/* El wordmark lo dibuja el canvas; esto solo reserva el lugar. */}
        <div className="login-wordmark" ref={cajaWordmark} aria-hidden="true" />
        <h1 className="login-tagline">Orquestación de escaneos</h1>

        <div className="login-form">
          {porInactividad && !info && (
            <div className="login-info">
              Cerramos tu sesión por inactividad. Ingresá de nuevo.
            </div>
          )}
          {info && <div className="login-info">{info}</div>}
          {errors.length > 0 && (
            <div className="form-errors" role="alert">
              {errors.map((m, i) => (
                <p key={i}>{m}</p>
              ))}
            </div>
          )}

          {step === "email" ? (
            <div className={claseSeq} key="paso-email">
              <div className="field">
                <div className="login-row">
                  <label htmlFor="email">Correo corporativo</label>
                  <span className="login-status">
                    <i aria-hidden="true" /> Acceso restringido
                  </span>
                </div>
                <input
                  id="email"
                  type="email"
                  className="mono"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && sendCode()}
                  placeholder="vos@vectus.la"
                  autoFocus
                />
              </div>
              <button
                className="btn btn-primary btn-lg"
                disabled={!email.trim() || busy}
                onClick={sendCode}
              >
                {busy ? "Enviando…" : "Enviar código"}
              </button>
            </div>
          ) : (
            <div className={claseSeq} key="paso-codigo">
              <p className="login-sub">
                Si el correo está registrado, enviamos un código a {email}. Vence
                en 10 minutos.
              </p>
              <div className="field">
                <div className="login-row">
                  <label>Código de 6 dígitos</label>
                  <span className="login-status">
                    <i aria-hidden="true" /> Verificación
                  </span>
                </div>
                <CodeGrid value={code} onChange={setCode} onEnter={verify} disabled={busy} />
              </div>
              <button
                className="btn btn-primary btn-lg"
                disabled={!codigoCompleto || busy}
                onClick={verify}
              >
                {busy ? "Verificando…" : "Entrar"}
              </button>
              <div className="login-alt">
                <button className="linklike" onClick={changeEmail} disabled={busy}>
                  Cambiar email
                </button>
                <button className="linklike" onClick={sendCode} disabled={busy}>
                  Reenviar código
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      <p className="login-foot mono">vectus-scan · acceso restringido</p>
    </div>
  );
}
