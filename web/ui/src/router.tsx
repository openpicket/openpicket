import { lazy, Suspense, type ReactNode } from "react";
import { createBrowserRouter, Navigate } from "react-router";
import { AppLayout } from "./components/AppLayout";
import { RequireAuth } from "./components/RequireAuth";
import { LoadingBlock } from "./components/common";
import { RouteError } from "./components/RouteError";
import { LoginPage } from "./pages/LoginPage";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const AlertsPage = lazy(() => import("./pages/AlertsPage"));
const AlertPage = lazy(() => import("./pages/AlertPage"));
const DecisionsPage = lazy(() => import("./pages/DecisionsPage"));
const ApprovalsPage = lazy(() => import("./pages/ApprovalsPage"));
const IpPage = lazy(() => import("./pages/IpPage"));
const LogsPage = lazy(() => import("./pages/LogsPage"));
const NodesPage = lazy(() => import("./pages/NodesPage"));
const NodePage = lazy(() => import("./pages/NodePage"));
const PoliciesPage = lazy(() => import("./pages/PoliciesPage"));
const GeoIpPage = lazy(() => import("./pages/GeoIpPage"));
const MetricsPage = lazy(() => import("./pages/MetricsPage"));
const NotificationsPage = lazy(() => import("./pages/NotificationsPage"));
const SystemPage = lazy(() => import("./pages/SystemPage"));

function page(el: ReactNode) {
  return <Suspense fallback={<LoadingBlock h={300} />}>{el}</Suspense>;
}

export const router = createBrowserRouter([
  { path: "/login", element: <LoginPage />, errorElement: <RouteError /> },
  {
    path: "/",
    element: (
      <RequireAuth>
        <AppLayout />
      </RequireAuth>
    ),
    errorElement: <RouteError />,
    children: [
      { index: true, element: page(<DashboardPage />) },
      { path: "alerts", element: page(<AlertsPage />) },
      { path: "alerts/:instance/:id", element: page(<AlertPage />) },
      { path: "decisions", element: page(<DecisionsPage />) },
      { path: "approvals", element: page(<ApprovalsPage />) },
      { path: "ip", element: page(<IpPage />) },
      { path: "ip/:ip", element: page(<IpPage />) },
      { path: "logs", element: page(<LogsPage />) },
      { path: "nodes", element: page(<NodesPage />) },
      { path: "nodes/:id", element: page(<NodePage />) },
      { path: "policies", element: page(<PoliciesPage />) },
      { path: "geoip", element: page(<GeoIpPage />) },
      { path: "metrics", element: page(<MetricsPage />) },
      { path: "notifications", element: page(<NotificationsPage />) },
      { path: "system", element: page(<SystemPage />) },
      { path: "*", element: <Navigate to="/" replace /> },
    ],
  },
]);
