import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import Scanners from "./pages/Scanners.jsx";
import Informes from "./pages/Informes.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import NewScan from "./pages/NewScan.jsx";
import ScanDetail from "./pages/ScanDetail.jsx";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Scanners />} />
        <Route path="/informes" element={<Informes />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scans/new" element={<NewScan />} />
        <Route path="/scans/:id" element={<ScanDetail />} />
      </Route>
    </Routes>
  );
}
