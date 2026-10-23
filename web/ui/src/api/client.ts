import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { AuthService } from "../gen/openpicket/api/v1/auth_pb";
import { NodeService } from "../gen/openpicket/api/v1/nodes_pb";
import { AlertService, DashboardService, DecisionService } from "../gen/openpicket/api/v1/crowdsec_pb";
import { GeoService, PolicyService } from "../gen/openpicket/api/v1/policies_pb";
import { SystemService } from "../gen/openpicket/api/v1/system_pb";
import { LogService } from "../gen/openpicket/api/v1/logs_pb";
import { MetricsService } from "../gen/openpicket/api/v1/metrics_pb";
import { NotificationService } from "../gen/openpicket/api/v1/notifications_pb";
import { IntelService } from "../gen/openpicket/api/v1/intel_pb";
import { HubService } from "../gen/openpicket/api/v1/hub_pb";

/** Base URL of the API (same origin). */
export const apiBase = new URL("/api", window.location.origin).href;

// Connect requests carry Connect-Protocol-Version: the manager refuses
// state-changing requests without it (CSRF protection).
export const transport = createConnectTransport({
  baseUrl: apiBase,
  useBinaryFormat: false,
  fetch: (input, init) => globalThis.fetch(input, { ...init, credentials: "same-origin" }),
});

export const api = {
  auth: createClient(AuthService, transport),
  nodes: createClient(NodeService, transport),
  alerts: createClient(AlertService, transport),
  decisions: createClient(DecisionService, transport),
  dashboard: createClient(DashboardService, transport),
  policies: createClient(PolicyService, transport),
  geo: createClient(GeoService, transport),
  system: createClient(SystemService, transport),
  logs: createClient(LogService, transport),
  metrics: createClient(MetricsService, transport),
  notifications: createClient(NotificationService, transport),
  intel: createClient(IntelService, transport),
  hub: createClient(HubService, transport),
};

/** Uploads a MaxMind database (multipart; not a Connect call). */
export async function uploadGeoDatabase(file: File): Promise<{ kind: string; database_type: string }> {
  const body = new FormData();
  body.append("file", file);
  const res = await fetch(`${apiBase}/geo/upload`, {
    method: "POST",
    body,
    credentials: "same-origin",
    headers: { "X-OpenPicket-Request": "1" },
  });
  if (!res.ok) throw new Error((await res.text()).trim() || `upload failed (${res.status})`);
  return res.json();
}

/** Uploads a CrowdSec item with the data files it reads (multipart). */
export async function uploadHubItem(type: string, stage: string, item: File, data: File[]): Promise<{ type: string; name: string }> {
  const body = new FormData();
  body.append("type", type);
  body.append("stage", stage);
  body.append("item", item);
  for (const f of data) body.append("data", f);
  const res = await fetch(`${apiBase}/hub/upload`, {
    method: "POST",
    body,
    credentials: "same-origin",
    headers: { "X-OpenPicket-Request": "1" },
  });
  if (!res.ok) throw new Error((await res.text()).trim() || `upload failed (${res.status})`);
  return res.json();
}
