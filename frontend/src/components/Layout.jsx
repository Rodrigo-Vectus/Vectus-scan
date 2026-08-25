import { NavLink, Outlet, useLocation, useParams, useNavigate } from "react-router-dom";
import { ScanLine, FileText, LayoutDashboard, Users, LogOut } from "lucide-react";
import { useAuth } from "../auth.jsx";
import logoVectus from "../assets/logo-vectus.png";
import ThemeSwitch from "./ThemeSwitch.jsx";
import SidebarFolders from "./SidebarFolders.jsx";

function BrandMark() {
  // Logo corporativo de Vectus. El isotipo provisional de arcos quedó
  // archivado en `assets/brandmark-arcos-legacy.svg`.
  return <img className="brand-logo" src={logoVectus} alt="Vectus" />;
}

const NAV = [
  { group: "análisis", items: [
    { to: "/", label: "Scanners", icon: ScanLine, end: true },
    { to: "/informes", label: "Informes", icon: FileText },
  ]},
  { group: "monitoreo", items: [
    { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  ]},
  { group: "gestión", items: [
    { to: "/usuarios", label: "Usuarios", icon: Users },
  ]},
];

const TITLES = {
  "/": "Scanners",
  "/informes": "Informes",
  "/dashboard": "Dashboard",
  "/scans/new": "Nuevo barrido",
  "/usuarios": "Usuarios",
};

function Crumb() {
  const { pathname } = useLocation();
  const { id } = useParams();
  let title = TITLES[pathname];
  if (!title && pathname.startsWith("/scans/")) title = `Análisis #${id}`;
  return (
    <div className="crumb">
      vectus-scan / <b>{title || "—"}</b>
    </div>
  );
}

export default function Layout() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();

  const salir = async () => {
    await signOut();
    navigate("/login", { replace: true });
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <BrandMark />
          <span className="brand-text">
            <b>vectus</b> <span>scan</span>
          </span>
        </div>
        <nav className="nav">
          {NAV.map((section) => (
            <div key={section.group}>
              <div className="nav-eyebrow">{section.group}</div>
              {section.items.map(({ to, label, icon: Icon, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                >
                  <Icon />
                  {label}
                </NavLink>
              ))}
            </div>
          ))}
          <SidebarFolders />
        </nav>
        {user && (
          <div className="sidebar-user">
            <div className="su-info">
              <span className="su-name">{user.nombre}</span>
              <span className="su-role mono">{user.rol}</span>
            </div>
            <button className="su-logout" onClick={salir} title="Cerrar sesión">
              <LogOut />
            </button>
          </div>
        )}
      </aside>

      <div className="main">
        <div className="topbar2">
          <Crumb />
          <div className="topbar2-right">
            <ThemeSwitch />
            <span className="topbar2-sep" />
            <span className="dot" />
            192.168.11.125
          </div>
        </div>
        <div className="page-wrap">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
