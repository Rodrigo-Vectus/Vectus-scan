import { NavLink, Outlet, useLocation, useParams, useNavigate } from "react-router-dom";
import { ScanLine, FileText, LayoutDashboard, Users, LogOut } from "lucide-react";
import { useAuth } from "../auth.jsx";

function BrandMark() {
  // Arcos concéntricos: eco del isotipo VECTUS, en cyan/teal.
  return (
    <svg className="brand-mark" viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <path d="M4 28 A24 24 0 0 1 28 4" stroke="#22D3EE" strokeWidth="2.4" strokeLinecap="round" />
      <path d="M4 28 A17 17 0 0 1 21 11" stroke="#2DD4BF" strokeWidth="2.4" strokeLinecap="round" opacity="0.85" />
      <path d="M4 28 A10 10 0 0 1 14 18" stroke="#3B4A63" strokeWidth="2.4" strokeLinecap="round" />
    </svg>
  );
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
