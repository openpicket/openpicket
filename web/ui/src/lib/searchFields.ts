/** Fields of the search language per page (help popover). */
export interface FieldDoc {
  name: string;
  kind: "text" | "number" | "time" | "bool";
  description: string;
  example?: string;
}

export const ALERT_FIELDS: FieldDoc[] = [
  { name: "value", kind: "text", description: "Source value (IP, range, host)", example: "value=198.51.100.4" },
  { name: "scenario", kind: "text", description: "Scenario", example: "scenario:ssh" },
  { name: "country", kind: "text", description: "Source country (ISO code)", example: "country=CN" },
  { name: "as", kind: "text", description: "Source AS name", example: 'as:"DigitalOcean"' },
  { name: "asn", kind: "text", description: "Source AS number", example: "asn=14061" },
  { name: "node", kind: "text", description: "Node that saw the traffic", example: "node=edge-01" },
  { name: "direction", kind: "text", description: "inbound, outbound or internal", example: "direction=outbound" },
  { name: "target", kind: "text", description: "Destination IP (alert context dst_ip)", example: "target=192.168.1.10" },
  { name: "port", kind: "text", description: "Destination port", example: "port=22" },
  { name: "signature", kind: "text", description: "Suricata signature", example: "signature:ET" },
  { name: "message", kind: "text", description: "Alert message" },
  { name: "machine", kind: "text", description: "CrowdSec agent (machine)" },
  { name: "origin", kind: "text", description: "Origin of a decision of the alert", example: "origin=cscli" },
  { name: "type", kind: "text", description: "Type of a decision of the alert", example: "type=ban" },
  { name: "active", kind: "bool", description: "Has an active decision", example: "active:true" },
  { name: "events", kind: "number", description: "Event count", example: "events>10" },
  { name: "created", kind: "time", description: "Creation time: date, RFC 3339 or ago (24h, 7d)", example: "created>24h" },
  { name: "simulated", kind: "bool", description: "Simulation mode alert", example: "simulated:true" },
  { name: "instance", kind: "text", description: "LAPI instance" },
  { name: "id", kind: "number", description: "Alert id" },
  { name: "meta.<key>", kind: "text", description: "Any alert context key", example: "meta.ja4:t13d" },
];

export const DECISION_FIELDS: FieldDoc[] = [
  { name: "value", kind: "text", description: "Blocked value", example: "value=198.51.100.4" },
  { name: "scenario", kind: "text", description: "Scenario (reason)", example: "scenario:portscan" },
  { name: "origin", kind: "text", description: "crowdsec, cscli, lists...", example: "origin=cscli" },
  { name: "action", kind: "text", description: "ban, captcha, throttle", example: "action=ban" },
  { name: "status", kind: "text", description: "active or expired", example: "status=active" },
  { name: "scope", kind: "text", description: "Ip, Range, Country, AS" },
  { name: "country", kind: "text", description: "Source country", example: "country=RU" },
  { name: "as", kind: "text", description: "Source AS name" },
  { name: "node", kind: "text", description: "Node of the alert" },
  { name: "until", kind: "time", description: "Expiry", example: "until<2026-12-01" },
  { name: "alert", kind: "number", description: "Alert id" },
  { name: "instance", kind: "text", description: "LAPI instance" },
];

export const SYNTAX: [string, string][] = [
  ["ssh", "Free text in any field"],
  ['"port scan"', "Phrase"],
  ["field:value", "Contains (case-insensitive)"],
  ["field=value", "Equals"],
  ["field>10, field<=24h", "Comparison (numbers, times)"],
  ["-field:value, NOT x", "Negation"],
  ['field:""', "Empty"],
  ["a OR b, (a OR b) c", "Alternatives and grouping"],
];
