import { ActionIcon, Badge, Button, Group, Stack, Text, TextInput, Tooltip } from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import type { SyncState } from "../gen/openpicket/api/v1/nodes_pb";
import { toNumber } from "../lib/format";
import { t } from "../lib/i18n";

export type LabelRow = { key: string; value: string };

export function labelsToRows(labels: { [key: string]: string } | undefined): LabelRow[] {
  return Object.entries(labels ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => ({ key, value }));
}

export function rowsToLabels(rows: LabelRow[]): { [key: string]: string } {
  const out: { [key: string]: string } = {};
  for (const r of rows) {
    const k = r.key.trim();
    if (k) out[k] = r.value.trim();
  }
  return out;
}

/** Key/value rows editor for node labels. */
export function LabelsEditor(props: { value: LabelRow[]; onChange: (rows: LabelRow[]) => void; disabled?: boolean }) {
  const set = (i: number, patch: Partial<LabelRow>) => props.onChange(props.value.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <Stack gap={6}>
      <Text size="sm" fw={500}>
        {t("Labels")}
      </Text>
      {props.value.length === 0 && (
        <Text size="xs" c="dimmed">
          {t("No labels. Policies can select nodes by label (for example site=seoul).")}
        </Text>
      )}
      {props.value.map((r, i) => (
        <Group key={i} gap="xs" wrap="nowrap">
          <TextInput
            placeholder={t("key")}
            value={r.key}
            disabled={props.disabled}
            onChange={(e) => set(i, { key: e.currentTarget.value })}
            style={{ flex: 1 }}
            className="mono-input"
          />
          <TextInput
            placeholder={t("value")}
            value={r.value}
            disabled={props.disabled}
            onChange={(e) => set(i, { value: e.currentTarget.value })}
            style={{ flex: 1 }}
            className="mono-input"
          />
          <ActionIcon
            variant="subtle"
            color="red"
            disabled={props.disabled}
            onClick={() => props.onChange(props.value.filter((_, j) => j !== i))}
            aria-label={t("Remove label")}
          >
            <IconTrash size={16} />
          </ActionIcon>
        </Group>
      ))}
      <Group>
        <Button
          size="xs"
          variant="light"
          leftSection={<IconPlus size={14} />}
          disabled={props.disabled}
          onClick={() => props.onChange([...props.value, { key: "", value: "" }])}
        >
          {t("Add label")}
        </Button>
      </Group>
    </Stack>
  );
}

export function LabelBadges(props: { labels: { [key: string]: string } | undefined }) {
  const rows = labelsToRows(props.labels);
  if (rows.length === 0) {
    return (
      <Text size="xs" c="dimmed">
        -
      </Text>
    );
  }
  return (
    <Group gap={4}>
      {rows.map((r) => (
        <Badge key={r.key} variant="outline" size="sm" tt="none" ff="monospace">
          {r.key}={r.value}
        </Badge>
      ))}
    </Group>
  );
}

/** Version acknowledged by the node against the cluster version. */
export function SyncBadge(props: { state?: SyncState; extra?: string }) {
  const s = props.state;
  if (!s) {
    return (
      <Text size="xs" c="dimmed">
        -
      </Text>
    );
  }
  const version = toNumber(s.version);
  const current = toNumber(s.current);
  const lag = Math.max(0, current - version);
  let color = "teal";
  let label = t("in sync");
  if (s.error) {
    color = "red";
    label = t("error");
  } else if (version === 0 && current > 0) {
    color = "gray";
    label = t("never applied");
  } else if (lag > 0) {
    color = "orange";
    label = t("{n} behind", { n: lag });
  }
  const tip = [`${t("Node")} v${version} / ${t("cluster")} v${current}`, s.error, props.extra].filter(Boolean).join("\n");
  return (
    <Tooltip label={<span style={{ whiteSpace: "pre-wrap" }}>{tip}</span>} withArrow multiline maw={360}>
      <Badge color={color} variant="light" size="sm">
        {label}
      </Badge>
    </Tooltip>
  );
}

export function ListValue(props: { values: string[] | undefined }) {
  if (!props.values || props.values.length === 0) {
    return (
      <Text size="sm" c="dimmed">
        -
      </Text>
    );
  }
  return (
    <Group gap={4}>
      {props.values.map((v) => (
        <Badge key={v} variant="outline" size="sm" tt="none" ff="monospace">
          {v}
        </Badge>
      ))}
    </Group>
  );
}

const REFUSAL_PATTERNS: [RegExp, string][] = [
  [/^overlaps the allowlist \((.+)\)$/, "overlaps the node's allowlist ({v})"],
  [/^overlaps a local network \((.+)\)$/, "overlaps a local network of the node ({v})"],
  [/^over the element limit \((\d+)\)$/, "over the node's element limit ({v})"],
  [/^range (.+) is too wide$/, "range {v} is too wide"],
  [/^invalid (?:range|address) (.+)$/, "invalid value {v}"],
];

/** A node's reason for not applying a decision, translated. */
export function refusalReason(reason: string): string {
  for (const [re, msg] of REFUSAL_PATTERNS) {
    const m = re.exec(reason);
    if (m) return t(msg, { v: m[1] });
  }
  return t(reason);
}
