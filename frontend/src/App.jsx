import { Routes, Route, Link, useLocation } from "react-router-dom";
import Home from "./pages/Home.jsx";
import NewScan from "./pages/NewScan.jsx";
import ScanDetail from "./pages/ScanDetail.jsx";

function TopBar() {
  const { pathname } = useLocation();
  const onHome = pathname === "/";
  return (
    <header className="topbar">
      <Link to="/" className="wordmark" aria-label="Vectus SCAN — inicio">
        <span className="wordmark-a">VECTUS</span>
        <span className="wordmark-b">SCAN</span>
      </Link>
      <div className="topbar-meta">
        <span className="env-dot" />
        <span className="env-label">consola de barridos</span>
      </div>
      {!onHome && (
        <Link to="/" className="topbar-back">
          ← inicio
        </Link>
      )}
    </header>
  );
}

export default function App() {
  return (
    <div className="app">
      <TopBar />
      <main className="content">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/scans/new" element={<NewScan />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
        </Routes>
      </main>
    </div>
  );
}
