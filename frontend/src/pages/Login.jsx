import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { requestCode, verifyCode, messagesFromError } from "../api.js";
import { useAuth } from "../auth.jsx";

function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <path d="M4 28 A24 24 0 0 1 28 4" stroke="#22D3EE" strokeWidth="2.4" strokeLinecap="round" />
      <path d="M4 28 A17 17 0 0 1 21 11" stroke="#2DD4BF" strokeWidth="2.4" strokeLinecap="round" opacity="0.85" />
      <path d="M4 28 A10 10 0 0 1 14 18" stroke="#3B4A63" strokeWidth="2.4" strokeLinecap="round" />
    </svg>
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

  const sendCode = async () => {
    if (!email.trim() || busy) return;
    setBusy(true);
    setErrors([]);
    setInfo("");
    try {
      await requestCode(email.trim().toLowerCase());
      setStep("code");
      setInfo("Si el email está registrado, te enviamos un código. Revisá tu correo.");
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

  const verify = async () => {
    if (code.trim().length !== 6 || busy) return;
    setBusy(true);
    setErrors([]);
    try {
      await verifyCode(email.trim().toLowerCase(), code.trim());
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

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-brand">
          <BrandMark />
          <span className="brand-text">
            <b>vectus</b> <span>scan</span>
          </span>
        </div>

        <p className="eyebrow2">acceso</p>
        <h1 className="login-title">
          {step === "email" ? "Ingresá con tu email" : "Ingresá el código"}
        </h1>
        <p className="login-sub">
          {step === "email"
            ? "Te enviamos un código de un solo uso al correo registrado."
            : `Enviado a ${email}. Vence en 10 minutos.`}
        </p>

        {info && <div className="login-info">{info}</div>}
        {errors.length > 0 && (
          <div className="form-errors" role="alert">
            {errors.map((m, i) => (
              <p key={i}>{m}</p>
            ))}
          </div>
        )}

        {step === "email" ? (
          <>
            <div className="field">
              <label htmlFor="email">Email</label>
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
            <button className="btn btn-primary btn-lg" disabled={!email.trim() || busy} onClick={sendCode}>
              {busy ? "Enviando…" : "Enviar código"}
            </button>
          </>
        ) : (
          <>
            <div className="field">
              <label htmlFor="code">Código de 6 dígitos</label>
              <input
                id="code"
                className="mono code-input"
                inputMode="numeric"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                onKeyDown={(e) => e.key === "Enter" && verify()}
                placeholder="••••••"
                autoFocus
              />
            </div>
            <button className="btn btn-primary btn-lg" disabled={code.length !== 6 || busy} onClick={verify}>
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
          </>
        )}
      </div>
      <p className="login-foot mono">vectus-scan · acceso restringido</p>
    </div>
  );
}
