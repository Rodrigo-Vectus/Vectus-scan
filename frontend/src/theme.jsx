import { createContext, useCallback, useContext, useEffect, useState } from "react";

// Temas disponibles: `navy` es el oscuro de siempre (y el que se aplica si
// no hay preferencia guardada; se representa con la ausencia de
// `data-theme`), `light` es el claro.
export const THEMES = ["navy", "light"];
export const THEME_DEFAULT = "navy";
export const THEME_STORAGE_KEY = "vectus-theme";

/** Escribe el tema en el <html>. Compartida con el script de index.html,
 *  que hace lo mismo antes del primer pintado para evitar el parpadeo. */
export function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === THEME_DEFAULT) root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
}

function leerGuardado() {
  try {
    const t = window.localStorage.getItem(THEME_STORAGE_KEY);
    return THEMES.includes(t) ? t : THEME_DEFAULT;
  } catch {
    // Modo privado o storage bloqueado: se cae al tema por defecto.
    return THEME_DEFAULT;
  }
}

const ThemeContext = createContext(null);

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(leerGuardado);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = useCallback((next) => {
    if (!THEMES.includes(next)) return;
    setThemeState(next);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      /* si no se puede persistir, al menos vale para esta pestaña */
    }
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (ctx === null) {
    throw new Error("useTheme debe usarse dentro de <ThemeProvider>");
  }
  return ctx;
}
