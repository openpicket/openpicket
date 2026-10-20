import { useMemo, useState } from "react";
import {
  ActionIcon,
  Alert,
  Button,
  Code,
  Divider,
  Group,
  List,
  Modal,
  MultiSelect,
  Paper,
  Select,
  Stack,
  Switch,
  TagsInput,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowDown, IconArrowUp, IconPlus, IconTrash } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useNodes } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import type { AddressList, Policy, PortRange, PreviewBundleResponse } from "../gen/openpicket/api/v1/policies_pb";
import { allCountries } from "../lib/countries";
import { formatNumber } from "../lib/format";
import { t } from "../lib/i18n";
import { ListValue } from "./nodes";

export const ACTIONS = ["accept", "drop", "reject"];

export function formatPorts(ports: PortRange[]): string {
  return ports.map((p) => (p.from === p.to ? String(p.from) : `${p.from}-${p.to}`)).join(", ");
}

/** Parses "443, 8000-8080"; returns an error message on invalid input. */
export function parsePorts(s: string): { ports: { from: number; to: number }[]; error?: string } {
  const ports: { from: number; to: number }[] = [];
  for (const raw of s.split(",")) {
    const part = raw.trim();
    if (!part) continue;
    const m = /^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/.exec(part);
    if (!m) return { ports, error: t("Invalid port {p}", { p: part }) };
    const from = Number(m[1]);
    const to = m[2] ? Number(m[2]) : from;
    if (from < 1 || to > 65535 || to < from) return { ports, error: t("Invalid port range {p}", { p: part }) };
    ports.push({ from, to });
  }
  if (ports.length === 0) return { ports, error: t("At least one port is required") };
  return { ports };
}

export function scopeSummary(p: Policy): string {
  const nodes = p.scope?.nodes ?? [];
  const labels = Object.entries(p.scope?.labels ?? {}).map(([k, v]) => `${k}=${v.values.join("|")}`);
  if (nodes.length === 0 && labels.length === 0) return t("all nodes");
  return [...nodes, ...labels].join(", ");
}

const actionColor: Record<string, string> = { accept: "teal", drop: "red", reject: "orange" };
export function actionColorOf(a: string): string {
  return actionColor[a] ?? "gray";
}

interface RuleDraft {
  action: string;
  countries: string[];
  asns: string[];
  lists: string[];
  cidrs: string[];
}

interface LabelDraft {
  key: string;
  values: string[];
}

function toDraftRules(p?: Policy): RuleDraft[] {
  return (p?.rules ?? []).map((r) => ({
    action: r.action,
    countries: r.source?.countries ?? [],
    asns: (r.source?.asns ?? []).map(String),
    lists: r.source?.lists ?? [],
    cidrs: r.source?.cidrs ?? [],
  }));
}

function move<T>(xs: T[], i: number, d: number): T[] {
  const j = i + d;
  if (j < 0 || j >= xs.length) return xs;
  const out = [...xs];
  [out[i], out[j]] = [out[j], out[i]];
  return out;
}

const idRe = /^[a-z0-9_]{1,32}$/;

/** Create or edit a port policy. */
export function PolicyEditorModal(props: { opened: boolean; onClose: () => void; policy?: Policy }) {
  const p = props.policy;
  const creating = !p;
  const [id, setId] = useState(p?.id ?? "");
  const [description, setDescription] = useState(p?.description ?? "");
  const [enabled, setEnabled] = useState(p?.enabled ?? true);
  const [mode, setMode] = useState(p?.mode || "enforce");
  const [proto, setProto] = useState(p?.proto || "tcp");
  const [ports, setPorts] = useState(p ? formatPorts(p.ports) : "");
  const [defaultAction, setDefaultAction] = useState(p?.defaultAction || "accept");
  const [logDrops, setLogDrops] = useState(p?.logDrops ?? false);
  const [nodes, setNodes] = useState<string[]>(p?.scope?.nodes ?? []);
  const [labels, setLabels] = useState<LabelDraft[]>(Object.entries(p?.scope?.labels ?? {}).map(([key, v]) => ({ key, values: v.values })));
  const [rules, setRules] = useState<RuleDraft[]>(toDraftRules(p));
  const nodeList = useNodes(false);
  const lists = useQuery({ queryKey: ["addressLists"], queryFn: async () => (await api.policies.listAddressLists({})).lists });
  const countries = useMemo(() => allCountries(), []);
  const parsed = parsePorts(ports);
  const idError = creating && id && !idRe.test(id) ? t("Lowercase letters, digits and _ (1-32)") : undefined;
  const badAsn = rules.some((r) => r.asns.some((a) => !/^\d+$/.test(a.replace(/^AS/i, ""))));
  const save = useMutation({
    mutationFn: () =>
      api.policies.putPolicy({
        policy: {
          id,
          description,
          enabled,
          mode,
          proto,
          ports: parsed.ports,
          defaultAction,
          logDrops,
          scope: {
            nodes,
            labels: Object.fromEntries(labels.filter((l) => l.key.trim()).map((l) => [l.key.trim(), { values: l.values }])),
          },
          rules: rules.map((r) => ({
            action: r.action,
            source: { countries: r.countries, asns: r.asns.map((a) => Number(a.replace(/^AS/i, ""))), lists: r.lists, cidrs: r.cidrs },
          })),
        },
      }),
    meta: { errorTitle: t("Could not save the policy") },
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["policies"] });
      void queryClient.invalidateQueries({ queryKey: ["policyHistory"] });
      void queryClient.invalidateQueries({ queryKey: ["addressLists"] });
      notifications.show({ color: "teal", message: t("Policy {id} saved (version {v})", { id, v: formatNumber(res.version) }) });
      props.onClose();
    },
  });
  const setRule = (i: number, patch: Partial<RuleDraft>) => setRules(rules.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const actionData = ACTIONS.map((a) => ({ value: a, label: t(a) }));
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={creating ? t("New port policy") : t("Edit {id}", { id })} size="xl">
      <Stack>
        <Group grow align="flex-start">
          <TextInput
            label={t("Id")}
            value={id}
            onChange={(e) => setId(e.currentTarget.value)}
            disabled={!creating}
            error={idError}
            className="mono-input"
            required
          />
          <TextInput label={t("Description")} value={description} onChange={(e) => setDescription(e.currentTarget.value)} />
        </Group>
        <Group grow align="flex-start">
          <Select
            label={t("Mode")}
            data={[
              { value: "enforce", label: t("enforce") },
              { value: "observe", label: t("observe (count only)") },
            ]}
            value={mode}
            onChange={(v) => v && setMode(v)}
            allowDeselect={false}
          />
          <Select label={t("Protocol")} data={["tcp", "udp"]} value={proto} onChange={(v) => v && setProto(v)} allowDeselect={false} />
          <TextInput
            label={t("Public ports")}
            description={t("Before DNAT, e.g. 443, 8000-8080")}
            value={ports}
            onChange={(e) => setPorts(e.currentTarget.value)}
            error={ports ? parsed.error : undefined}
            className="mono-input"
            required
          />
        </Group>
        <Group>
          <Switch label={t("Enabled")} checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
          <Switch label={t("Log dropped packets (NFLOG)")} checked={logDrops} onChange={(e) => setLogDrops(e.currentTarget.checked)} />
        </Group>

        <Divider label={t("Rules (first match wins)")} labelPosition="left" />
        {rules.length === 0 && (
          <Text size="sm" c="dimmed">
            {t("No rules: every source gets the default action.")}
          </Text>
        )}
        {rules.map((r, i) => (
          <Paper key={i} withBorder p="sm" radius="md">
            <Group justify="space-between" mb="xs">
              <Group gap="xs">
                <Text size="sm" fw={600}>
                  {t("Rule {n}", { n: i + 1 })}
                </Text>
                <Select size="xs" w={120} data={actionData} value={r.action} onChange={(v) => v && setRule(i, { action: v })} allowDeselect={false} />
              </Group>
              <Group gap={4}>
                <ActionIcon variant="subtle" disabled={i === 0} onClick={() => setRules(move(rules, i, -1))} aria-label={t("Move up")}>
                  <IconArrowUp size={16} />
                </ActionIcon>
                <ActionIcon variant="subtle" disabled={i === rules.length - 1} onClick={() => setRules(move(rules, i, 1))} aria-label={t("Move down")}>
                  <IconArrowDown size={16} />
                </ActionIcon>
                <ActionIcon variant="subtle" color="red" onClick={() => setRules(rules.filter((_, j) => j !== i))} aria-label={t("Remove rule")}>
                  <IconTrash size={16} />
                </ActionIcon>
              </Group>
            </Group>
            <Text size="xs" c="dimmed" mb={4}>
              {t("Matches a source in any of:")}
            </Text>
            <Stack gap="xs">
              <MultiSelect
                label={t("Countries")}
                data={countries}
                value={r.countries}
                onChange={(v) => setRule(i, { countries: v })}
                searchable
                clearable
              />
              <TagsInput
                label={t("AS numbers")}
                value={r.asns}
                onChange={(v) => setRule(i, { asns: v })}
                placeholder="15169"
                error={r.asns.some((a) => !/^\d+$/.test(a.replace(/^AS/i, ""))) ? t("AS numbers only") : undefined}
              />
              <MultiSelect
                label={t("Address lists")}
                data={(lists.data ?? []).map((l) => ({ value: l.name, label: l.description ? `${l.name} — ${l.description}` : l.name }))}
                value={r.lists}
                onChange={(v) => setRule(i, { lists: v })}
                searchable
                clearable
              />
              <TagsInput label={t("CIDRs")} value={r.cidrs} onChange={(v) => setRule(i, { cidrs: v })} placeholder="203.0.113.0/24" />
            </Stack>
          </Paper>
        ))}
        <Group>
          <Button
            size="xs"
            variant="light"
            leftSection={<IconPlus size={14} />}
            onClick={() => setRules([...rules, { action: defaultAction === "accept" ? "drop" : "accept", countries: [], asns: [], lists: [], cidrs: [] }])}
          >
            {t("Add rule")}
          </Button>
        </Group>
        <Select
          label={t("Default action")}
          description={t("For sources no rule matches")}
          data={actionData}
          value={defaultAction}
          onChange={(v) => v && setDefaultAction(v)}
          allowDeselect={false}
          w={220}
        />

        <Divider label={t("Scope")} labelPosition="left" />
        <Text size="xs" c="dimmed">
          {t("Without nodes or labels the policy applies to every node. A node is in scope when it is listed or has every label (one of the values each).")}
        </Text>
        <MultiSelect
          label={t("Nodes")}
          data={(nodeList.data ?? []).map((n) => n.id)}
          value={nodes}
          onChange={setNodes}
          searchable
          clearable
        />
        {labels.map((l, i) => (
          <Group key={i} gap="xs" align="flex-end" wrap="nowrap">
            <TextInput
              label={i === 0 ? t("Label") : undefined}
              placeholder="site"
              value={l.key}
              onChange={(e) => {
                const key = e.currentTarget.value;
                setLabels(labels.map((x, j) => (j === i ? { ...x, key } : x)));
              }}
              className="mono-input"
              w={180}
            />
            <TagsInput
              label={i === 0 ? t("Values") : undefined}
              placeholder="seoul"
              value={l.values}
              onChange={(v) => setLabels(labels.map((x, j) => (j === i ? { ...x, values: v } : x)))}
              style={{ flex: 1 }}
            />
            <ActionIcon variant="subtle" color="red" mb={6} onClick={() => setLabels(labels.filter((_, j) => j !== i))} aria-label={t("Remove label")}>
              <IconTrash size={16} />
            </ActionIcon>
          </Group>
        ))}
        <Group>
          <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setLabels([...labels, { key: "", values: [] }])}>
            {t("Add label condition")}
          </Button>
        </Group>

        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {t("Cancel")}
          </Button>
          <Button disabled={!id || !!idError || !!parsed.error || badAsn} loading={save.isPending} onClick={() => save.mutate()}>
            {t("Save")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

/** Create or edit a named address list. */
export function AddressListModal(props: { opened: boolean; onClose: () => void; list?: AddressList }) {
  const l = props.list;
  const creating = !l;
  const [name, setName] = useState(l?.name ?? "");
  const [description, setDescription] = useState(l?.description ?? "");
  const [cidrs, setCidrs] = useState((l?.cidrs ?? []).join("\n"));
  const [asns, setAsns] = useState<string[]>((l?.asns ?? []).map(String));
  const badAsn = asns.some((a) => !/^\d+$/.test(a.replace(/^AS/i, "")));
  const save = useMutation({
    mutationFn: () =>
      api.policies.putAddressList({
        list: {
          name: name.trim(),
          description,
          cidrs: cidrs
            .split(/[\n,]/)
            .map((s) => s.trim())
            .filter(Boolean),
          asns: asns.map((a) => Number(a.replace(/^AS/i, ""))),
        },
      }),
    meta: { errorTitle: t("Could not save the list") },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["addressLists"] });
      void queryClient.invalidateQueries({ queryKey: ["policyHistory"] });
      notifications.show({ color: "teal", message: t("List {name} saved", { name }) });
      props.onClose();
    },
  });
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={creating ? t("New address list") : t("Edit {id}", { id: name })} size="lg">
      <Stack>
        <TextInput label={t("Name")} value={name} onChange={(e) => setName(e.currentTarget.value)} disabled={!creating} required className="mono-input" />
        <TextInput label={t("Description")} value={description} onChange={(e) => setDescription(e.currentTarget.value)} />
        <Textarea
          label={t("CIDRs")}
          description={t("One per line")}
          value={cidrs}
          onChange={(e) => setCidrs(e.currentTarget.value)}
          autosize
          minRows={4}
          maxRows={14}
          className="mono-input"
        />
        <TagsInput label={t("AS numbers")} value={asns} onChange={setAsns} placeholder="15169" error={badAsn ? t("AS numbers only") : undefined} />
        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {t("Cancel")}
          </Button>
          <Button disabled={!name.trim() || badAsn} loading={save.isPending} onClick={() => save.mutate()}>
            {t("Save")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

/** The policy bundle a node would receive. */
export function BundlePreview(props: { preview: PreviewBundleResponse }) {
  const p = props.preview;
  return (
    <Stack gap="xs">
      <Group gap="lg">
        <Text size="sm">
          {t("Version")}: <b>{formatNumber(p.version)}</b>
        </Text>
        <Text size="sm">
          {t("Set elements")}: <b>{formatNumber(p.elements)}</b>
        </Text>
      </Group>
      <div>
        <Text size="sm" fw={500}>
          {t("Policies in the bundle")}
        </Text>
        <ListValue values={p.policies} />
      </div>
      {p.skipped.length > 0 && (
        <Alert color="orange" title={t("Skipped policies")}>
          <List size="sm">
            {p.skipped.map((s) => (
              <List.Item key={s.policyId}>
                <Code>{s.policyId}</Code>: {s.reason}
              </List.Item>
            ))}
          </List>
        </Alert>
      )}
      <Code block style={{ maxHeight: 360, overflow: "auto" }}>
        {p.bundleJson}
      </Code>
    </Stack>
  );
}

export function DeleteListButton(props: { list: AddressList; onDelete: () => void; disabled?: boolean }) {
  const used = props.list.usedBy.length > 0;
  return (
    <Tooltip label={used ? t("Used by {ids}", { ids: props.list.usedBy.join(", ") }) : t("Delete")} withArrow>
      <ActionIcon
        variant="subtle"
        color="red"
        disabled={used || props.disabled}
        onClick={(e) => {
          e.stopPropagation();
          props.onDelete();
        }}
        aria-label={t("Delete")}
      >
        <IconTrash size={16} />
      </ActionIcon>
    </Tooltip>
  );
}
