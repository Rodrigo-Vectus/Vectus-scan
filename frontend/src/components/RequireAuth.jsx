import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth.jsx";

function Splash() {
  return (
    <div className="auth-splash">
      <span className="dot" /> cargando…
    </div>
  );
}

/** Exige sesión válida. Sin sesión → redirige a /login (guardando el destino). */
export function RequireAuth() {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Splash />;
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  return <Outlet />;
}

/** Exige rol administrador. Logueado pero no admin → al inicio. */
export function RequireAdmin() {
  const { user, loading, isAdmin } = useAuth();
  if (loading) return <Splash />;
  if (!user) return <Navigate to="/login" replace />;
  if (!isAdmin) return <Navigate to="/" replace />;
  return <Outlet />;
}
