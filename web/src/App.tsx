import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { useAuth } from "./context/AuthContext";
import { AirGapImportPage } from "./pages/AirGapImportPage";
import { CveSearchPage } from "./pages/CveSearchPage";
import { FleetPage } from "./pages/FleetPage";
import { GovernancePage } from "./pages/GovernancePage";
import { HostDetailPage } from "./pages/HostDetailPage";
import { LoginPage } from "./pages/LoginPage";
import { OperationsPage } from "./pages/OperationsPage";

export function AppRoutes() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#090e1a] text-sm text-slate-300">
        Verificando sesión...
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<FleetPage />} />
        <Route path="/hosts/:hostId" element={<HostDetailPage />} />
        <Route path="/cves" element={<CveSearchPage />} />
        <Route path="/import" element={<AirGapImportPage />} />
        <Route path="/governance" element={<GovernancePage />} />
        <Route path="/operations" element={<OperationsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}

export default AppRoutes;
