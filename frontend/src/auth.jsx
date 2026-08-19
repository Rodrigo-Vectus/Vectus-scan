import { createContext, useContext, useEffect, useState, useCallback } from "react";
import { getMe, logout as apiLogout } from "./api.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const me = await getMe();
      setUser(me);
      return me;
    } catch {
      setUser(null);
      return null;
    }
  }, []);

  useEffect(() => {
    // Al montar, resolvemos la sesión actual (cookie httpOnly del backend).
    let alive = true;
    (async () => {
      await refresh();
      if (alive) setLoading(false);
    })();
    return () => {
      alive = false;
    };
  }, [refresh]);

  const signOut = useCallback(async () => {
    try {
      await apiLogout();
    } catch {
      /* ignorar: la sesión se limpia igual del lado del cliente */
    }
    setUser(null);
  }, []);

  const isAdmin = user?.rol === "administrador";

  return (
    <AuthContext.Provider value={{ user, loading, isAdmin, refresh, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (ctx === null) {
    throw new Error("useAuth debe usarse dentro de <AuthProvider>");
  }
  return ctx;
}
