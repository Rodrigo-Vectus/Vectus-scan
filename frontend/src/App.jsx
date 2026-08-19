import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import { RequireAuth } from "./components/RequireAuth.jsx";
import Login from "./pages/Login.jsx";
import Scanners from "./pages/Scanners.jsx";
import Informes from "./pages/Informes.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import NewScan from "./pages/NewScan.jsx";
import ScanDetail from "./pages/ScanDetail.jsx";
import Usuarios from "./pages/Usuarios.jsx";

export default function App() {
  return (
    <Routes>
      {/* Pública */}
      <Route path="/login" element={<Login />} />

      {/* Protegidas: requieren sesión (guard client-side) */}
      <Route element={<RequireAuth />}>
        <Route element={<Layout />}>
          <Route path="/" element={<Scanners />} />
          <Route path="/informes" element={<Informes />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/scans/new" element={<NewScan />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/usuarios" element={<Usuarios />} />
        </Route>
      </Route>
    </Routes>
  );
}
