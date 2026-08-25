import { Moon, Sun } from "lucide-react";
import { useTheme } from "../theme.jsx";

const OPCIONES = [
  { id: "navy", label: "oscuro", Icon: Moon },
  { id: "light", label: "claro", Icon: Sun },
];

/** Selector de tema (barra superior). La elección se guarda en el
 *  navegador: es por equipo, no por usuario, y no viaja al backend. */
export default function ThemeSwitch() {
  const { theme, setTheme } = useTheme();

  return (
    <div className="theme-switch" role="group" aria-label="Tema de la interfaz">
      {OPCIONES.map(({ id, label, Icon }) => (
        <button
          key={id}
          type="button"
          className={theme === id ? "active" : ""}
          onClick={() => setTheme(id)}
          title={`Tema ${label}`}
          aria-label={`Tema ${label}`}
          aria-pressed={theme === id}
        >
          <Icon />
        </button>
      ))}
    </div>
  );
}
