import { useEffect, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Checkbox,
  Group,
  Menu,
  Modal,
  SegmentedControl,
  Select,
  Stack,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowDownLeft, IconArrowsLeftRight, IconArrowUpRight, IconColumns, IconFlask } from "@tabler/icons-react";
import { useMutation } from "@tanstack/react-query";
import type { InstanceError } from "../gen/openpicket/api/v1/crowdsec_pb";
import { api } from "../api/client";
import { queryClient } from "../api/queryClient";
import { useAccess, useUISettings } from "../api/hooks";
import { setPref, usePrefs } from "../lib/prefs";
import { useInstance } from "../lib/scope";
import { toNumber } from "../lib/format";
import { t } from "../lib/i18n";

const directionMeta: Record<string, { color: string; icon: typeof IconArrowDownLeft; label: string }> = {
  inbound: { color: "orange", icon: IconArrowDownLeft, label: "inbound" },
  outbound: { color: "red", icon: IconArrowUpRight, label: "outbound" },
  internal: { color: "grape", icon: IconArrowsLeftRight, label: "internal" },
  both: { color: "red", icon: IconArrowsLeftRight, label: "both ways" },
};

/** Traffic direction of an alert, or the edge direction of a decision. */
export function DirectionBadge(props: { direction: string }) {
  const m = directionMeta[props.direction];
  if (!m) return <Text span size="sm" c="dimmed">-</Text>;
  return (
    <Badge color={m.color} variant="light" size="sm" leftSection={<m.icon size={12} />}>
      {t(m.label)}
    </Badge>
  );
}

/** "crowdsecurity/ssh-bf" with the author dimmed. */
export function Scenario(props: { name: string }) {
  const i = props.name.indexOf("/");
  if (i < 0) return <Text span size="sm">{props.name}</Text>;
  return (
    <Text span size="sm" style={{ whiteSpace: "nowrap" }}>
      <Text span c="dimmed" size="sm">
        {props.name.slice(0, i + 1)}
      </Text>
      {props.name.slice(i + 1)}
    </Text>
  );
}

export function SimulatedBadge() {
  return (
    <Tooltip label={t("Simulation mode: no decision is applied")} withArrow>
      <Badge size="xs" color="gray" variant="outline" leftSection={<IconFlask size={10} />}>
        {t("simulated")}
      </Badge>
    </Tooltip>
  );
}

/** Reports per-instance failures of a combined action. */
export function reportInstanceErrors(errors: InstanceError[], okMessage: string) {
  if (errors.length === 0) {
    notifications.show({ color: "teal", message: okMessage });
    return;
  }
  notifications.show({
    color: "orange",
    title: t("Partly failed"),
    message: errors.map((e) => `${e.instance}: ${e.error}`).join("\n"),
    autoClose: 12000,
  });
}

const DURATIONS = ["1h", "4h", "24h", "7d", "30d", "365d"];

/** Adds a manual decision (on every instance in the combined scope). */
export function AddDecisionModal(props: { opened: boolean; onClose: () => void; initialValue?: string }) {
  const ui = useUISettings();
  const instance = useInstance();
  const access = useAccess();
  const scenarios = ui.data?.manualScenarios ?? ["openpicket/manual"];
  const [scope, setScope] = useState("Ip");
  const [value, setValue] = useState(props.initialValue ?? "");
  const [duration, setDuration] = useState("4h");
  const [type, setType] = useState("ban");
  const [scenario, setScenario] = useState(scenarios[0] ?? "openpicket/manual");
  const [reason, setReason] = useState("");
  useEffect(() => {
    if (props.opened) setValue(props.initialValue ?? "");
  }, [props.opened, props.initialValue]);
  const add = useMutation({
    mutationFn: () => api.decisions.addDecision({ scope, value: value.trim(), duration, type, scenario, reason, instance }),
    meta: { errorTitle: t("Could not add the decision") },
    onSuccess: (res) => {
      reportInstanceErrors(res.errors, t("Decision added for {value}", { value }));
      void queryClient.invalidateQueries({ queryKey: ["decisions"] });
      void queryClient.invalidateQueries({ queryKey: ["ip"] });
      props.onClose();
    },
  });
  const instances = access.features?.lapiInstances ?? [];
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={t("Add decision")} size="lg">
      <Stack>
        <SegmentedControl
          value={scope}
          onChange={setScope}
          data={[
            { value: "Ip", label: t("IP") },
            { value: "Range", label: t("Range") },
            { value: "Country", label: t("Country") },
            { value: "AS", label: t("AS") },
          ]}
        />
        <TextInput
          label={t("Value")}
          placeholder={{ Ip: "198.51.100.4", Range: "198.51.100.0/24", Country: "CN", AS: "4134" }[scope]}
          value={value}
          onChange={(e) => setValue(e.currentTarget.value)}
          required
          data-autofocus
          className="mono-input"
        />
        {(scope === "Country" || scope === "AS") && (
          <Alert color="blue" variant="light">
            {t("Country and AS decisions are enforced by L7 bouncers only; the edge blocks IPs and ranges.")}
          </Alert>
        )}
        <Group grow align="flex-start">
          <Select
            label={t("Duration")}
            data={DURATIONS}
            value={duration}
            onChange={(v) => setDuration(v ?? "4h")}
            searchable
            allowDeselect={false}
            description={t("Or type e.g. 90m, 12h, 14d")}
            onSearchChange={(s) => /^\d+(m|h|d)$/.test(s) && setDuration(s)}
          />
          <Select label={t("Type")} data={["ban", "captcha", "throttle"]} value={type} onChange={(v) => setType(v ?? "ban")} allowDeselect={false} />
        </Group>
        <Select
          label={t("Scenario")}
          description={t("openpicket/manual-both blocks traffic in both directions at the edge")}
          data={scenarios}
          value={scenario}
          onChange={(v) => setScenario(v ?? scenarios[0])}
          allowDeselect={false}
        />
        <TextInput label={t("Reason")} value={reason} onChange={(e) => setReason(e.currentTarget.value)} maxLength={512} />
        {!instance && instances.length > 1 && (
          <Text size="sm" c="dimmed">
            {t("The decision is added on every LAPI instance ({n}).", { n: instances.length })}
          </Text>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {t("Cancel")}
          </Button>
          <Button color="red" disabled={!value.trim()} loading={add.isPending} onClick={() => add.mutate()}>
            {t("Add decision")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

/** Deletes every decision (and optionally alert) of an IP. */
export function CleanupIpModal(props: { opened: boolean; onClose: () => void; ip?: string }) {
  const instance = useInstance();
  const [ip, setIp] = useState(props.ip ?? "");
  const [alerts, setAlerts] = useState(false);
  useEffect(() => {
    if (props.opened) setIp(props.ip ?? "");
  }, [props.opened, props.ip]);
  const cleanup = useMutation({
    mutationFn: () => api.decisions.cleanupIP({ ip: ip.trim(), deleteAlerts: alerts, instance }),
    meta: { errorTitle: t("Cleanup failed") },
    onSuccess: (res) => {
      reportInstanceErrors(
        res.errors,
        t("Removed {d} decisions and {a} alerts of {ip}", { d: toNumber(res.decisionsDeleted), a: toNumber(res.alertsDeleted), ip }),
      );
      for (const k of ["decisions", "alerts", "ip", "summary", "facets"]) void queryClient.invalidateQueries({ queryKey: [k] });
      props.onClose();
    },
  });
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={t("Clean up an IP")}>
      <Stack>
        <TextInput label={t("IP address")} value={ip} onChange={(e) => setIp(e.currentTarget.value)} className="mono-input" data-autofocus />
        <Checkbox label={t("Also delete its alerts")} checked={alerts} onChange={(e) => setAlerts(e.currentTarget.checked)} />
        <Text size="sm" c="dimmed">
          {t("Every decision on this address is deleted; nodes unblock it within seconds.")}
        </Text>
        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {t("Cancel")}
          </Button>
          <Button color="red" disabled={!ip.trim()} loading={cleanup.isPending} onClick={() => cleanup.mutate()}>
            {t("Clean up")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

export interface Column {
  key: string;
  label: string;
  /** Shown unless the user hides it. */
  default: boolean;
}

/** Visible columns of a table, remembered per browser. */
export function useColumns(table: string, columns: Column[]): [Set<string>, (key: string, on: boolean) => void] {
  const p = usePrefs();
  const saved = p.columns[table];
  const visible = new Set(saved ?? columns.filter((c) => c.default).map((c) => c.key));
  const set = (key: string, on: boolean) => {
    const next = new Set(visible);
    if (on) next.add(key);
    else next.delete(key);
    setPref("columns", { ...p.columns, [table]: columns.map((c) => c.key).filter((k) => next.has(k)) });
  };
  return [visible, set];
}

export function ColumnPicker(props: { columns: Column[]; visible: Set<string>; onToggle: (key: string, on: boolean) => void }) {
  return (
    <Menu position="bottom-end" withArrow closeOnItemClick={false}>
      <Menu.Target>
        <Tooltip label={t("Columns")} withArrow>
          <ActionIcon variant="default" size="lg" aria-label={t("Columns")}>
            <IconColumns size={18} />
          </ActionIcon>
        </Tooltip>
      </Menu.Target>
      <Menu.Dropdown>
        {props.columns.map((c) => (
          <Menu.Item key={c.key} onClick={() => props.onToggle(c.key, !props.visible.has(c.key))}>
            <Checkbox size="xs" label={t(c.label)} checked={props.visible.has(c.key)} readOnly />
          </Menu.Item>
        ))}
      </Menu.Dropdown>
    </Menu>
  );
}
