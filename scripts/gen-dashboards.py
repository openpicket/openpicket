#!/usr/bin/env python3
"""Generates the Grafana dashboards of the Helm chart
(deploy/helm/openpicket/dashboards/*.json). Edit here, then run it."""
import json
import os

OUT = os.path.join(os.path.dirname(__file__), "..", "deploy", "helm", "openpicket", "dashboards")
DS = {"type": "prometheus", "uid": "${datasource}"}


class Board:
    def __init__(self, uid, title, tags, variables=()):
        self.uid, self.title, self.tags = uid, title, tags
        self.panels, self.y, self.id = [], 0, 1
        self.vars = [{"name": "datasource", "type": "datasource", "query": "prometheus", "label": "Data source"},
                     {"name": "namespace", "type": "query", "datasource": DS, "label": "Namespace",
                      "query": "label_values(openpicket_sink_latency_seconds_count, namespace)", "refresh": 2}]
        self.vars += list(variables)

    def row(self, title):
        self.panels.append({"type": "row", "title": title, "id": self.id, "collapsed": False,
                            "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1}, "panels": []})
        self.id += 1
        self.y += 1
        self.x = 0

    def _add(self, p, w, h):
        if getattr(self, "x", 0) + w > 24:
            self.x = 0
            self.y += h
        p["gridPos"] = {"x": getattr(self, "x", 0), "y": self.y, "w": w, "h": h}
        p["id"] = self.id
        p["datasource"] = DS
        self.id += 1
        self.x = getattr(self, "x", 0) + w
        if self.x >= 24:
            self.x = 0
            self.y += h
        self.panels.append(p)

    def stat(self, title, expr, w=4, h=4, unit="short", thresholds=None, desc=""):
        steps = thresholds or [{"color": "green", "value": None}]
        self._add({"type": "stat", "title": title, "description": desc,
                   "targets": [{"expr": expr, "refId": "A", "instant": True}],
                   "fieldConfig": {"defaults": {"unit": unit, "thresholds": {"mode": "absolute", "steps": steps}}, "overrides": []},
                   "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "area"}}, w, h)

    def ts(self, title, targets, w=12, h=8, unit="short", desc="", stack=False):
        self._add({"type": "timeseries", "title": title, "description": desc,
                   "targets": [{"expr": e, "legendFormat": l, "refId": chr(65 + i)} for i, (e, l) in enumerate(targets)],
                   "fieldConfig": {"defaults": {"unit": unit, "custom": {"fillOpacity": 10, "lineWidth": 1,
                                                                        "stacking": {"mode": "normal" if stack else "none"}}},
                                   "overrides": []},
                   "options": {"legend": {"displayMode": "table", "placement": "bottom", "calcs": ["lastNotNull", "max"]},
                               "tooltip": {"mode": "multi"}}}, w, h)

    def table(self, title, expr, w=24, h=8, desc=""):
        self._add({"type": "table", "title": title, "description": desc,
                   "targets": [{"expr": expr, "refId": "A", "instant": True, "format": "table"}],
                   "transformations": [{"id": "organize", "options": {"excludeByName": {"Time": True, "__name__": True, "job": True,
                                                                                         "endpoint": True, "pod": True, "service": True,
                                                                                         "container": True, "instance": True, "namespace": True}}}],
                   "fieldConfig": {"defaults": {}, "overrides": []}}, w, h)

    def write(self):
        d = {"uid": self.uid, "title": self.title, "tags": self.tags, "schemaVersion": 39, "editable": True,
             "time": {"from": "now-6h", "to": "now"}, "refresh": "30s", "timezone": "",
             "templating": {"list": self.vars}, "panels": self.panels, "annotations": {"list": []}}
        with open(os.path.join(OUT, f"{self.uid}.json"), "w") as f:
            json.dump(d, f, indent=1)
            f.write("\n")


NS = 'namespace="$namespace"'
red = lambda v: [{"color": "green", "value": None}, {"color": "red", "value": v}]

b = Board("openpicket-overview", "OpenPicket / Overview", ["openpicket"])
b.row("Edge")
b.stat("Nodes connected", f"sum(openpicket_node_connected{{{NS}}})")
b.stat("Blocked values (edge)", f"max(sum by (node) (openpicket_node_ban_elements{{{NS}}}))",
       desc="Ban set elements of the node with the most.")
b.stat("Nodes with apply errors", f"count(max by (node) (openpicket_node_apply_error{{{NS}}}) == 1) or vector(0)", thresholds=red(1))
b.stat("Sinks failing", f"sum(max by (sink) (openpicket_sink_circuit_open{{{NS}}})) or vector(0)", thresholds=red(1))
b.stat("Decision relay age", f"time() - max(openpicket_relay_last_pull_timestamp_seconds{{{NS}}})", unit="s",
       thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 60}, {"color": "red", "value": 300}])
b.stat("Agent log drops (1h)", f"sum(increase(openpicket_node_log_dropped_total{{{NS}}}[1h])) or vector(0)", thresholds=red(1))
b.row("Log pipeline")
b.ts("Records ingested", [(f"sum by (type) (rate(openpicket_ingest_records_total{{{NS}}}[5m]))", "{{type}}")], unit="ops", stack=True)
b.ts("Sink latency p95", [(f"histogram_quantile(0.95, sum by (sink, le) (rate(openpicket_sink_latency_seconds_bucket{{{NS}}}[5m])))", "{{sink}}")], unit="s")
b.ts("Sink errors", [(f"sum by (sink) (rate(openpicket_sink_errors_total{{{NS}}}[5m]))", "{{sink}}")], unit="ops")
b.ts("Records not stored", [
    (f"sum by (sink) (rate(openpicket_sink_rejected_records_total{{{NS}}}[5m]))", "rejected {{sink}}"),
    (f"sum by (reason) (rate(openpicket_loki_rejected_records_total{{{NS}}}[5m]))", "loki {{reason}}"),
    (f"sum by (sink) (rate(openpicket_sink_gap_records_total{{{NS}}}[5m]))", "gap {{sink}}")], unit="ops")
b.ts("Agent ack latency p95", [(f"histogram_quantile(0.95, sum by (le) (rate(openpicket_ack_latency_seconds_bucket{{{NS}}}[5m])))", "p95")], unit="s")
b.ts("Agent queues", [(f"sum by (node) (openpicket_node_log_queue_bytes{{{NS}}})", "{{node}}")], unit="bytes")
b.row("Decisions and alerts")
b.ts("Edge decision version", [(f"max(openpicket_relay_version{{{NS}}})", "cluster"),
                               (f"max by (node) (openpicket_node_decisions_version{{{NS}}})", "{{node}}")])
b.ts("Relay pulls", [(f"sum by (result) (rate(openpicket_relay_pulls_total{{{NS}}}[5m]))", "{{result}}"),
                     (f"sum(increase(openpicket_relay_full_resyncs_total{{{NS}}}[5m]))", "full resyncs")])
b.ts("Alerts synced from LAPI", [(f"sum by (instance) (rate(openpicket_alerts_synced_total{{{NS}}}[5m]))", "{{instance}}")], unit="ops")
b.ts("Alert sync errors", [(f"sum by (instance) (increase(openpicket_alerts_sync_errors_total{{{NS}}}[5m]))", "{{instance}}")])
b.write()

n = Board("openpicket-nodes", "OpenPicket / Nodes", ["openpicket"],
          [{"name": "node", "type": "query", "datasource": DS, "label": "Node", "multi": True, "includeAll": True,
            "query": 'label_values(openpicket_node_connected{namespace="$namespace"}, node)', "refresh": 2}])
NN = 'namespace="$namespace", node=~"$node"'
n.row("Nodes")
n.table("Connected nodes", f"max by (node, site) (openpicket_node_connected{{{NN}}})")
n.ts("Ban set elements", [(f"sum by (node, direction, family) (openpicket_node_ban_elements{{{NN}}})", "{{node}} {{direction}} {{family}}")])
n.ts("Decisions refused locally", [(f"max by (node) (openpicket_node_decisions_rejected{{{NN}}})", "{{node}}")],
     desc="Allowlist, local networks or set limits.")
n.ts("Port policy matches", [(f"sum by (node, rule) (rate(openpicket_node_policy_packets{{{NN}}}[5m]))", "{{node}} {{rule}}")], unit="pps")
n.ts("NFLOG records", [(f"sum by (node, prefix) (rate(openpicket_node_nflog_records{{{NN}}}[5m]))", "{{node}} {{prefix}}")], unit="ops")
n.ts("Log queue", [(f"max by (node) (openpicket_node_log_queue_bytes{{{NN}}})", "{{node}} used"),
                   (f"max by (node) (openpicket_node_log_queue_capacity_bytes{{{NN}}})", "{{node}} capacity")], unit="bytes")
n.ts("Records sent / dropped", [(f"sum by (node) (rate(openpicket_node_log_sent_records{{{NN}}}[5m]))", "{{node}} sent"),
                                (f"sum by (node) (rate(openpicket_node_log_agent_dropped_records{{{NN}}}[5m]))", "{{node}} dropped")], unit="ops")
n.ts("Apply errors", [(f"max by (node, what) (openpicket_node_apply_error{{{NN}}})", "{{node}} {{what}}")])
n.ts("Policy version", [(f"max by (node) (openpicket_node_policy_version{{{NN}}})", "{{node}}")])
n.write()

c = Board("openpicket-crowdsec", "OpenPicket / CrowdSec", ["openpicket", "crowdsec"])
c.row("Detection")
c.stat("Active decisions", f"sum(max by (reason, origin, action) (cs_active_decisions{{{NS}}}))", w=6)
c.stat("Alerts (24h)", f"sum(increase(cs_alerts{{{NS}}}[24h])) or sum(cs_alerts{{{NS}}})", w=6)
c.stat("Lines read (5m)", f"sum(increase({{__name__=~\"cs_.*source_hits_total\", {NS}}}[5m]))", w=6)
c.stat("Unparsed (5m)", f"sum(increase(cs_parser_hits_ko_total{{{NS}}}[5m])) or vector(0)", w=6, thresholds=red(1))
c.ts("Bucket overflows", [(f"sum by (name) (rate(cs_bucket_overflowed_total{{{NS}}}[5m]))", "{{name}}")], unit="ops")
c.ts("Active decisions by reason", [(f"max by (reason) (cs_active_decisions{{{NS}}})", "{{reason}}")], stack=True)
c.ts("Parsed per parser", [(f"sum by (name) (rate(cs_node_hits_ok_total{{{NS}}}[5m]))", "{{name}}")], unit="ops")
c.ts("Whitelisted", [(f"sum by (name, reason) (rate(cs_node_wl_hits_ok_total{{{NS}}}[5m]))", "{{name}} {{reason}}")], unit="ops")
c.row("Local API")
c.ts("LAPI requests", [(f"sum by (route, method) (rate(cs_lapi_route_requests_total{{{NS}}}[5m]))", "{{method}} {{route}}")], unit="reqps")
c.ts("LAPI latency p95", [(f"histogram_quantile(0.95, sum by (endpoint, le) (rate(cs_lapi_request_duration_seconds_bucket{{{NS}}}[5m])))", "{{endpoint}}")], unit="s")
c.ts("Bouncer pulls", [(f"sum by (bouncer) (rate(cs_lapi_bouncer_requests_total{{{NS}}}[5m]))", "{{bouncer}}")], unit="reqps")
c.ts("AppSec", [(f"sum by (appsec_engine) (rate(cs_appsec_reqs_total{{{NS}}}[5m]))", "{{appsec_engine}} processed"),
                (f"sum by (appsec_engine) (rate(cs_appsec_block_total{{{NS}}}[5m]))", "{{appsec_engine}} blocked")], unit="reqps")
c.write()
print("dashboards written")
