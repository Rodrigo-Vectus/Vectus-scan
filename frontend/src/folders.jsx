import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { listFolders } from "./api.js";

/**
 * Carpetas de análisis (F10).
 *
 * Viven en un contexto porque las consumen dos lugares a la vez: la barra
 * lateral (listado + conteos) e Informes (filtro y selector de destino al
 * mover). Sin esto, mover un scan actualizaría la tabla pero dejaría los
 * conteos del menú desfasados hasta recargar.
 */
const FoldersContext = createContext(null);

export function FoldersProvider({ children }) {
  const [folders, setFolders] = useState(null); // null = cargando
  const [error, setError] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setFolders(await listFolders());
      setError(false);
    } catch {
      // Si falla (sesión vencida, backend caído) se muestra la app sin
      // carpetas en vez de romper toda la pantalla.
      setFolders([]);
      setError(true);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <FoldersContext.Provider value={{ folders, error, refresh }}>
      {children}
    </FoldersContext.Provider>
  );
}

export function useFolders() {
  const ctx = useContext(FoldersContext);
  if (ctx === null) {
    throw new Error("useFolders debe usarse dentro de <FoldersProvider>");
  }
  return ctx;
}
