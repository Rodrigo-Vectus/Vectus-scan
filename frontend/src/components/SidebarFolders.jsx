import { useEffect, useState } from "react";
import { NavLink, useSearchParams } from "react-router-dom";
import { ChevronDown, Folder, FolderPlus, Inbox } from "lucide-react";
import { createFolder, messagesFromError } from "../api.js";
import { useFolders } from "../folders.jsx";

// La sección arranca cerrada. Se recuerda si el usuario la dejó abierta para
// no tener que desplegarla en cada navegación; borrar esta clave la devuelve
// al comportamiento por defecto.
const ABIERTA_KEY = "vectus-carpetas-abiertas";

function leerAbierta() {
  try {
    return window.localStorage.getItem(ABIERTA_KEY) === "1";
  } catch {
    return false;
  }
}

/**
 * Listado de carpetas en la barra lateral, al estilo de Nessus.
 *
 * Cada carpeta enlaza a Informes con el filtro por querystring
 * (`/informes?carpeta=3`) en vez de una ruta propia: así se reutiliza la
 * tabla de informes tal cual y el filtro queda en una URL compartible.
 *
 * No hay entrada "Sin carpeta": los análisis sueltos se ven en "Todos". Como
 * destino al mover sí existe, que es lo que permite vaciar una carpeta para
 * poder borrarla.
 */
export default function SidebarFolders() {
  const { folders, refresh } = useFolders();
  const [params] = useSearchParams();
  const actual = params.get("carpeta");

  const [abierta, setAbierta] = useState(leerAbierta);
  const [creando, setCreando] = useState(false);
  const [nombre, setNombre] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  // Si se está viendo una carpeta, la sección se abre sola: quedaría raro
  // estar dentro de una y no verla marcada en el menú.
  useEffect(() => {
    if (actual) setAbierta(true);
  }, [actual]);

  const alternar = () => {
    const next = !abierta;
    setAbierta(next);
    if (!next) setCreando(false);
    try {
      window.localStorage.setItem(ABIERTA_KEY, next ? "1" : "0");
    } catch {
      /* sin persistencia: vale para esta pestaña */
    }
  };

  const nuevaCarpeta = (e) => {
    e.stopPropagation(); // no alternar la sección al tocar el "+"
    setAbierta(true);
    setCreando((v) => !v);
    setError(null);
  };

  const crear = async (e) => {
    e.preventDefault();
    const n = nombre.trim();
    if (!n || busy) return;
    setBusy(true);
    setError(null);
    try {
      await createFolder({ nombre: n });
      await refresh();
      setNombre("");
      setCreando(false);
    } catch (err) {
      setError(messagesFromError(err)[0]);
    } finally {
      setBusy(false);
    }
  };

  const lista = folders || [];

  return (
    <div>
      <button
        type="button"
        className="nav-section-toggle"
        onClick={alternar}
        aria-expanded={abierta}
      >
        {/* El ícono de la izquierda es además el botón de crear carpeta: por
            eso detiene la propagación, para no plegar la sección al tocarlo. */}
        <span
          className="nav-add"
          role="button"
          tabIndex={0}
          onClick={nuevaCarpeta}
          onKeyDown={(e) => e.key === "Enter" && nuevaCarpeta(e)}
          title="Nueva carpeta"
          aria-label="Nueva carpeta"
        >
          <FolderPlus />
        </span>
        <span className="nav-section-label">Carpetas</span>
        <ChevronDown className={`nav-chevron ${abierta ? "abierto" : ""}`} />
      </button>

      {abierta && (
        <>
          {creando && (
            <form className="nav-newfolder" onSubmit={crear}>
              <input
                value={nombre}
                onChange={(e) => setNombre(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Escape") {
                    setCreando(false);
                    setNombre("");
                    setError(null);
                  }
                }}
                placeholder="Nombre"
                maxLength={120}
                autoFocus
              />
              {error && <p className="nav-newfolder-err">{error}</p>}
            </form>
          )}

          <NavLink
            to="/informes"
            end
            className={() => `nav-item nav-folder ${!actual ? "active" : ""}`}
          >
            <Inbox />
            Todos
          </NavLink>

          {lista.map((f) => (
            <NavLink
              key={f.id}
              to={`/informes?carpeta=${f.id}`}
              className={() =>
                `nav-item nav-folder ${actual === String(f.id) ? "active" : ""}`
              }
              title={f.descripcion || f.nombre}
            >
              <Folder />
              <span className="nav-folder-name">{f.nombre}</span>
              <span className="nav-folder-count">{f.scans}</span>
            </NavLink>
          ))}
        </>
      )}
    </div>
  );
}
