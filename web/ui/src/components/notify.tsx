import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Code,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  PasswordInput,
  Select,
  Stack,
  Switch,
  TagsInput,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconX } from "@tabler/icons-react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api/client";
import { queryClient } from "../api/queryClient";
import { errorMessage } from "../api/errors";
import type { Destination, Rule } from "../gen/openpicket/api/v1/notifications_pb";
import { t } from "../lib/i18n";

export const SEVERITIES = ["info", "warning", "critical"];

export const RULE_TYPES: { value: string; label: string; description: string }[] = [
  { value: "new_alert", label: "New alert", description: "Every new alert matching the query." },
  { value: "new_decision", label: "New decision", description: "Every new active decision of an alert matching the query." },
  { value: "ip_ban", label: "IP ban", description: "New bans, optionally only for some addresses or CIDRs." },
  { value: "compromised_host", label: "Compromised host", description: "An inside host talked to a C2 server or malware site." },
  { value: "alert_threshold", label: "Alert threshold", description: "At least N matching alerts within the window." },
  { value: "alert_spike", label: "Alert spike", description: "Matching alerts jump above a factor of the previous windows." },
  { value: "lapi_down", label: "LAPI down", description: "A CrowdSec LAPI cannot be synced." },
  { value: "node_offline", label: "Node offline", description: "A node lost its data plane connection for the window." },
  { value: "policy_error", label: "Apply error", description: "A node could not apply decisions or port policies." },
  { value: "sink_down", label: "Log sink down", description: "Deliveries to Loki or CrowdSec are failing." },
];

export function ruleTypeLabel(type: string): string {
  return t(RULE_TYPES.find((r) => r.value === type)?.label ?? type);
}

const QUERY_TYPES = ["new_alert", "new_decision", "ip_ban", "compromised_host", "alert_threshold", "alert_spike"];
const ID_RE = /^[a-z0-9_-]{1,64}$/;

function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

const emptyRule = (): Partial<Rule> => ({
  id: "",
  name: "",
  enabled: true,
  type: "new_alert",
  severity: "",
  query: "",
  threshold: 10,
  windowSeconds: 300,
  spikeFactor: 3,
  cooldownSeconds: 600,
  destinations: [],
  ipFilters: [],
  includeSimulated: false,
});

export function RuleModal(props: { opened: boolean; onClose: () => void; rule?: Rule; destinations: Destination[]; readOnly: boolean }) {
  const editing = !!props.rule;
  const [r, setR] = useState<Partial<Rule>>(emptyRule());
  useEffect(() => {
    if (props.opened) setR(props.rule ? { ...props.rule } : emptyRule());
  }, [props.opened, props.rule]);
  const set = <K extends keyof Rule>(k: K, v: Rule[K]) => setR((old) => ({ ...old, [k]: v }));
  const save = useMutation({
    mutationFn: () =>
      api.notifications.putRule({
        rule: {
          id: r.id,
          name: r.name,
          enabled: r.enabled,
          type: r.type,
          severity: r.severity,
          query: r.query,
          threshold: r.threshold,
          windowSeconds: r.windowSeconds,
          spikeFactor: r.spikeFactor,
          cooldownSeconds: r.cooldownSeconds,
          destinations: r.destinations,
          ipFilters: r.ipFilters,
          includeSimulated: r.includeSimulated,
        },
      }),
    meta: { errorTitle: t("Could not save the rule") },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifyRules"] });
      notifications.show({ color: "teal", message: t("Rule saved") });
      props.onClose();
    },
  });
  const type = r.type ?? "new_alert";
  const idOK = ID_RE.test(r.id ?? "");
  const disabled = props.readOnly;
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={editing ? t("Edit rule") : t("New rule")} size="lg">
      <Stack gap="sm">
        <TextInput
          label={t("Name")}
          value={r.name}
          disabled={disabled}
          onChange={(e) => {
            const name = e.currentTarget.value;
            setR((old) => ({ ...old, name, id: editing || (old.id && old.id !== slug(old.name ?? "")) ? old.id : slug(name) }));
          }}
          required
          data-autofocus
        />
        <TextInput
          label={t("Id")}
          description={t("Lowercase letters, digits, - and _ (cannot be changed later).")}
          value={r.id}
          onChange={(e) => set("id", e.currentTarget.value)}
          disabled={editing || disabled}
          error={r.id && !idOK ? t("Invalid id") : undefined}
          className="mono-input"
        />
        <Group grow align="flex-start">
          <Select
            label={t("Type")}
            data={RULE_TYPES.map((x) => ({ value: x.value, label: t(x.label) }))}
            value={type}
            onChange={(v) => set("type", v ?? "new_alert")}
            allowDeselect={false}
            disabled={disabled}
            description={t(RULE_TYPES.find((x) => x.value === type)?.description ?? "")}
          />
          <Select
            label={t("Severity")}
            data={[{ value: "", label: t("Default for the type") }, ...SEVERITIES.map((s) => ({ value: s, label: t(s) }))]}
            value={r.severity ?? ""}
            onChange={(v) => set("severity", v ?? "")}
            allowDeselect={false}
            disabled={disabled}
          />
        </Group>
        {QUERY_TYPES.includes(type) && (
          <TextInput
            label={t("Alert query")}
            description={t("Alert search syntax, e.g. scenario:ssh country=CN -node=lab (empty: every alert).")}
            value={r.query}
            onChange={(e) => set("query", e.currentTarget.value)}
            className="mono-input"
            disabled={disabled}
          />
        )}
        {(type === "alert_threshold" || type === "alert_spike") && (
          <Group grow>
            <NumberInput
              label={type === "alert_spike" ? t("Minimum alerts") : t("Threshold (alerts)")}
              min={1}
              value={r.threshold}
              onChange={(v) => set("threshold", Number(v) || 0)}
              disabled={disabled}
            />
            <NumberInput label={t("Window (seconds)")} min={60} value={r.windowSeconds} onChange={(v) => set("windowSeconds", Number(v) || 0)} disabled={disabled} />
            {type === "alert_spike" && (
              <NumberInput
                label={t("Spike factor")}
                min={1.1}
                step={0.5}
                decimalScale={1}
                value={r.spikeFactor}
                onChange={(v) => set("spikeFactor", Number(v) || 0)}
                disabled={disabled}
              />
            )}
          </Group>
        )}
        {type === "node_offline" && (
          <NumberInput
            label={t("Offline after (seconds)")}
            min={60}
            value={r.windowSeconds}
            onChange={(v) => set("windowSeconds", Number(v) || 0)}
            disabled={disabled}
          />
        )}
        {type === "ip_ban" && (
          <TagsInput
            label={t("Only these addresses or CIDRs")}
            description={t("Empty: every ban.")}
            value={r.ipFilters ?? []}
            onChange={(v) => set("ipFilters", v)}
            disabled={disabled}
          />
        )}
        <NumberInput
          label={t("Cooldown (seconds)")}
          description={t("The rule fires at most once per subject (IP, node...) in this period.")}
          min={0}
          value={r.cooldownSeconds}
          onChange={(v) => set("cooldownSeconds", Number(v) || 0)}
          disabled={disabled}
        />
        <MultiSelect
          label={t("Destinations")}
          description={t("Notifications always appear in the inbox; destinations also receive them.")}
          data={props.destinations.map((d) => ({ value: d.id, label: d.name }))}
          value={r.destinations ?? []}
          onChange={(v) => set("destinations", v)}
          disabled={disabled}
          clearable
        />
        <Group>
          <Switch label={t("Enabled")} checked={r.enabled ?? true} onChange={(e) => set("enabled", e.currentTarget.checked)} disabled={disabled} />
          {QUERY_TYPES.includes(type) && (
            <Switch
              label={t("Include simulated alerts")}
              checked={r.includeSimulated ?? false}
              onChange={(e) => set("includeSimulated", e.currentTarget.checked)}
              disabled={disabled}
            />
          )}
        </Group>
        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {disabled ? t("Close") : t("Cancel")}
          </Button>
          {!disabled && (
            <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!r.name?.trim() || !idOK}>
              {t("Save")}
            </Button>
          )}
        </Group>
      </Stack>
    </Modal>
  );
}

interface FieldSpec {
  key: string;
  label: string;
  secret?: boolean;
  required?: boolean;
  placeholder?: string;
  kind?: "text" | "textarea" | "select";
  options?: string[];
  description?: string;
}

export const DESTINATION_TYPES: { value: string; label: string; fields: FieldSpec[] }[] = [
  {
    value: "webhook",
    label: "Webhook",
    fields: [
      { key: "url", label: "URL", required: true, placeholder: "https://example.com/hook" },
      { key: "method", label: "Method", kind: "select", options: ["POST", "PUT", "PATCH"] },
      { key: "content_type", label: "Content type", placeholder: "application/json" },
      {
        key: "template",
        label: "Body template",
        kind: "textarea",
        description:
          "Go template; empty sends the notification as JSON. Fields: {{.Title}} {{.Body}} {{.Severity}} {{.Subject}} {{.Link}} {{.Rule}} {{.Time}}; {{json .Title}} quotes a value for JSON.",
      },
      { key: "authorization", label: "Authorization header", secret: true, placeholder: "Bearer …" },
      { key: "headers", label: "Extra headers", secret: true, kind: "textarea", description: "One \"Name: value\" per line." },
    ],
  },
  { value: "slack", label: "Slack", fields: [{ key: "webhook_url", label: "Incoming webhook URL", secret: true, required: true }] },
  { value: "discord", label: "Discord", fields: [{ key: "webhook_url", label: "Webhook URL", secret: true, required: true }] },
  {
    value: "ntfy",
    label: "ntfy",
    fields: [
      { key: "url", label: "Server URL", required: true, placeholder: "https://ntfy.sh" },
      { key: "topic", label: "Topic", required: true },
      { key: "token", label: "Access token", secret: true },
    ],
  },
  {
    value: "gotify",
    label: "Gotify",
    fields: [
      { key: "url", label: "Server URL", required: true },
      { key: "token", label: "Application token", secret: true, required: true },
    ],
  },
  {
    value: "email",
    label: "Email (SMTP)",
    fields: [
      { key: "host", label: "SMTP host", required: true },
      { key: "port", label: "Port", placeholder: "587 (465 with TLS)" },
      { key: "tls", label: "Encryption", kind: "select", options: ["starttls", "tls", "none"] },
      { key: "from", label: "From", required: true, placeholder: "OpenPicket <openpicket@example.com>" },
      { key: "to", label: "To", required: true, placeholder: "soc@example.com, oncall@example.com" },
      { key: "username", label: "Username" },
      { key: "password", label: "Password", secret: true },
    ],
  },
  {
    value: "mqtt",
    label: "MQTT",
    fields: [
      { key: "url", label: "Broker URL", required: true, placeholder: "mqtt://broker:1883 or mqtts://broker:8883" },
      { key: "topic", label: "Topic", required: true, placeholder: "openpicket/notifications" },
      { key: "username", label: "Username" },
      { key: "password", label: "Password", secret: true },
      { key: "client_id", label: "Client id" },
      { key: "qos", label: "QoS", kind: "select", options: ["0", "1"] },
      { key: "retain", label: "Retain", kind: "select", options: ["false", "true"] },
    ],
  },
];

export function destinationTypeLabel(type: string): string {
  return t(DESTINATION_TYPES.find((d) => d.value === type)?.label ?? type);
}

interface DestForm {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  config: Record<string, string>;
  secrets: Record<string, string>;
  secretKeys: string[];
  minSeverity: string[];
}

const emptyDest = (): DestForm => ({ id: "", name: "", type: "webhook", enabled: true, config: {}, secrets: {}, secretKeys: [], minSeverity: [] });

export function DestinationModal(props: { opened: boolean; onClose: () => void; destination?: Destination; canEdit: boolean }) {
  const editing = !!props.destination;
  const [d, setD] = useState<DestForm>(emptyDest());
  const [test, setTest] = useState<{ ok: boolean; error: string } | null>(null);
  useEffect(() => {
    if (!props.opened) return;
    setTest(null);
    const x = props.destination;
    setD(
      x
        ? { id: x.id, name: x.name, type: x.type, enabled: x.enabled, config: { ...x.config }, secrets: {}, secretKeys: [...x.secretKeys], minSeverity: [...x.minSeverity] }
        : emptyDest(),
    );
  }, [props.opened, props.destination]);
  const spec = DESTINATION_TYPES.find((x) => x.value === d.type) ?? DESTINATION_TYPES[0];
  const body = () => {
    // Only the fields of the current type are sent.
    const config: Record<string, string> = {};
    const secrets: Record<string, string> = {};
    for (const f of spec.fields) {
      if (f.secret) {
        if (d.secrets[f.key]) secrets[f.key] = d.secrets[f.key];
      } else if (d.config[f.key]) config[f.key] = d.config[f.key];
    }
    return { id: d.id, name: d.name, type: d.type, enabled: d.enabled, config, secrets, minSeverity: d.minSeverity };
  };
  const save = useMutation({
    mutationFn: () => api.notifications.putDestination({ destination: body() }),
    meta: { errorTitle: t("Could not save the destination") },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifyDestinations"] });
      notifications.show({ color: "teal", message: t("Destination saved") });
      props.onClose();
    },
  });
  const send = useMutation({
    mutationFn: () => api.notifications.testDestination({ destination: body() }),
    meta: { silent: true },
    onSuccess: (res) => setTest({ ok: res.ok, error: res.error }),
    onError: (err) => setTest({ ok: false, error: errorMessage(err) }),
  });
  const idOK = ID_RE.test(d.id);
  const ro = !props.canEdit;
  const missing = spec.fields.some((f) =>
    f.required ? (f.secret ? !d.secrets[f.key] && !d.secretKeys.includes(f.key) : !d.config[f.key]) : false,
  );
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={editing ? t("Edit destination") : t("New destination")} size="lg">
      <Stack gap="sm">
        <Group grow align="flex-start">
          <TextInput
            label={t("Name")}
            value={d.name}
            disabled={ro}
            onChange={(e) => {
              const name = e.currentTarget.value;
              setD((old) => ({ ...old, name, id: editing || (old.id && old.id !== slug(old.name)) ? old.id : slug(name) }));
            }}
            required
            data-autofocus
          />
          <TextInput
            label={t("Id")}
            value={d.id}
            onChange={(e) => {
              const id = e.currentTarget.value;
              setD((old) => ({ ...old, id }));
            }}
            disabled={editing || ro}
            error={d.id && !idOK ? t("Invalid id") : undefined}
            className="mono-input"
          />
        </Group>
        <Group grow align="flex-start">
          <Select
            label={t("Type")}
            data={DESTINATION_TYPES.map((x) => ({ value: x.value, label: t(x.label) }))}
            value={d.type}
            onChange={(v) => setD((old) => ({ ...old, type: v ?? "webhook" }))}
            allowDeselect={false}
            disabled={editing || ro}
          />
          <MultiSelect
            label={t("Severities")}
            description={t("Empty: every severity.")}
            data={SEVERITIES.map((s) => ({ value: s, label: t(s) }))}
            value={d.minSeverity}
            onChange={(v) => setD((old) => ({ ...old, minSeverity: v }))}
            disabled={ro}
            clearable
          />
        </Group>
        {spec.fields.map((f) => {
          const isSet = d.secretKeys.includes(f.key);
          const value = f.secret ? (d.secrets[f.key] ?? "") : (d.config[f.key] ?? "");
          const onChange = (v: string) =>
            setD((old) =>
              f.secret ? { ...old, secrets: { ...old.secrets, [f.key]: v } } : { ...old, config: { ...old.config, [f.key]: v } },
            );
          const label = t(f.label);
          const description = f.description ? t(f.description) : f.secret && isSet ? t("Stored; leave empty to keep it.") : undefined;
          const placeholder = f.secret && isSet ? t("(unchanged)") : f.placeholder;
          if (f.kind === "select") {
            return (
              <Select
                key={f.key}
                label={label}
                data={f.options ?? []}
                value={value || null}
                onChange={(v) => onChange(v ?? "")}
                clearable
                disabled={ro}
              />
            );
          }
          if (f.kind === "textarea") {
            return (
              <Textarea
                key={f.key}
                label={label}
                description={description}
                value={value}
                placeholder={placeholder}
                onChange={(e) => onChange(e.currentTarget.value)}
                autosize
                minRows={2}
                className="mono-input"
                disabled={ro}
              />
            );
          }
          if (f.secret) {
            return (
              <PasswordInput
                key={f.key}
                label={label}
                description={description}
                value={value}
                placeholder={placeholder}
                onChange={(e) => onChange(e.currentTarget.value)}
                required={f.required && !isSet}
                disabled={ro}
              />
            );
          }
          return (
            <TextInput
              key={f.key}
              label={label}
              description={description}
              value={value}
              placeholder={placeholder}
              onChange={(e) => onChange(e.currentTarget.value)}
              required={f.required}
              disabled={ro}
            />
          );
        })}
        <Switch label={t("Enabled")} checked={d.enabled} onChange={(e) => setD((old) => ({ ...old, enabled: e.currentTarget.checked }))} disabled={ro} />
        {test && (
          <Alert color={test.ok ? "teal" : "red"} icon={test.ok ? <IconCheck size={16} /> : <IconX size={16} />}>
            {test.ok ? t("The test notification was sent.") : <Text size="sm" style={{ wordBreak: "break-word" }}>{test.error}</Text>}
          </Alert>
        )}
        {d.type === "webhook" && (
          <Text size="xs" c="dimmed">
            {t("Example template")}: <Code>{'{"text": {{json .Title}}, "severity": "{{.Severity}}"}'}</Code>
          </Text>
        )}
        <Group justify="space-between">
          <Button variant="light" onClick={() => send.mutate()} loading={send.isPending} disabled={ro || missing || !d.name}>
            {t("Send test")}
          </Button>
          <Group>
            <Button variant="default" onClick={props.onClose}>
              {ro ? t("Close") : t("Cancel")}
            </Button>
            {!ro && (
              <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!d.name.trim() || !idOK || missing}>
                {t("Save")}
              </Button>
            )}
          </Group>
        </Group>
      </Stack>
    </Modal>
  );
}
