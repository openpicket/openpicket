import type { ReactNode } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Center,
  CopyButton,
  Group,
  Loader,
  Paper,
  Stack,
  Text,
  Title,
  Tooltip,
  type MantineColor,
  type MantineSize,
} from "@mantine/core";
import { IconAlertTriangle, IconCheck, IconCopy, IconInbox } from "@tabler/icons-react";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { codeName, errorMessage } from "../api/errors";
import { formatDateTime, relativeTime, remaining, tsDate } from "../lib/format";
import { useNow } from "../lib/useNow";
import { t } from "../lib/i18n";

export function PageHeader(props: { title: ReactNode; description?: ReactNode; right?: ReactNode }) {
  return (
    <Group justify="space-between" align="flex-start" mb="md" wrap="wrap" gap="sm">
      <div style={{ minWidth: 0 }}>
        <Title order={2}>{props.title}</Title>
        {props.description && (
          <Text c="dimmed" size="sm" mt={4} component="div">
            {props.description}
          </Text>
        )}
      </div>
      {props.right && <Group gap="xs">{props.right}</Group>}
    </Group>
  );
}

export function LoadingBlock(props: { label?: string; h?: number | string }) {
  return (
    <Center h={props.h ?? 160}>
      <Stack align="center" gap="xs">
        <Loader size="sm" />
        {props.label && (
          <Text size="sm" c="dimmed">
            {props.label}
          </Text>
        )}
      </Stack>
    </Center>
  );
}

export function ErrorAlert(props: { error: unknown; title?: string; onRetry?: () => void }) {
  const code = codeName(props.error);
  return (
    <Alert color="red" icon={<IconAlertTriangle size={18} />} title={props.title ?? t("Failed to load")}>
      <Text size="sm" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
        {errorMessage(props.error)}
      </Text>
      {(code || props.onRetry) && (
        <Group gap="xs" mt={6}>
          {code && (
            <Text size="xs" c="dimmed">
              ({code})
            </Text>
          )}
          {props.onRetry && (
            <Text size="xs" c="blue" style={{ cursor: "pointer" }} onClick={props.onRetry}>
              {t("Retry")}
            </Text>
          )}
        </Group>
      )}
    </Alert>
  );
}

export function EmptyState(props: { title: ReactNode; description?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <Paper withBorder p="xl" radius="md">
      <Stack align="center" gap="xs">
        {props.icon ?? <IconInbox size={32} stroke={1.4} color="var(--mantine-color-dimmed)" />}
        <Text fw={600}>{props.title}</Text>
        {props.description && (
          <Text size="sm" c="dimmed" ta="center" maw={520}>
            {props.description}
          </Text>
        )}
        {props.action}
      </Stack>
    </Paper>
  );
}

/** Relative time with the absolute time in a tooltip. */
export function TimeAgo(props: { ts?: Timestamp; date?: Date; size?: MantineSize; c?: string }) {
  const now = useNow();
  const d = props.date ?? tsDate(props.ts);
  if (!d) {
    return (
      <Text span size={props.size ?? "sm"} c="dimmed">
        {t("never")}
      </Text>
    );
  }
  return (
    <Tooltip label={formatDateTime(d)} withArrow openDelay={300}>
      <Text span size={props.size ?? "sm"} c={props.c} style={{ whiteSpace: "nowrap" }}>
        {relativeTime(d, now)}
      </Text>
    </Tooltip>
  );
}

/** Time left until ts, with the absolute time in a tooltip. */
export function TimeLeft(props: { ts?: Timestamp; size?: MantineSize }) {
  const now = useNow();
  const d = tsDate(props.ts);
  const left = remaining(d, now);
  return (
    <Tooltip label={formatDateTime(d)} withArrow openDelay={300}>
      <Text span size={props.size ?? "sm"} c={left === "expired" ? "dimmed" : undefined} style={{ whiteSpace: "nowrap" }}>
        {left === "expired" ? t("expired") : left}
      </Text>
    </Tooltip>
  );
}

export function CopyIcon(props: { value: string; label?: string }) {
  return (
    <CopyButton value={props.value} timeout={1500}>
      {({ copied, copy }) => (
        <Tooltip label={copied ? t("Copied") : (props.label ?? t("Copy"))} withArrow>
          <ActionIcon
            variant="subtle"
            color={copied ? "teal" : "gray"}
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              copy();
            }}
          >
            {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
          </ActionIcon>
        </Tooltip>
      )}
    </CopyButton>
  );
}

/** Monospace value with a copy button. */
export function CopyText(props: { value: string; display?: ReactNode; wrap?: boolean; size?: MantineSize }) {
  return (
    <Group gap={4} wrap="nowrap" align="flex-start">
      <Text
        size={props.size ?? "sm"}
        ff="monospace"
        style={{ wordBreak: "break-all", whiteSpace: props.wrap === false ? "nowrap" : "normal", minWidth: 0 }}
      >
        {props.display ?? props.value}
      </Text>
      {props.value && <CopyIcon value={props.value} />}
    </Group>
  );
}

export function StatusDot(props: { color: MantineColor; label: ReactNode }) {
  return (
    <Group gap={6} wrap="nowrap">
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: 4,
          display: "inline-block",
          background: `var(--mantine-color-${props.color}-filled)`,
          flex: "none",
        }}
      />
      <Text size="sm" component="div">
        {props.label}
      </Text>
    </Group>
  );
}

const severityColor: Record<string, MantineColor> = { info: "blue", warning: "orange", critical: "red" };

export function SeverityBadge(props: { severity: string }) {
  return (
    <Badge color={severityColor[props.severity] ?? "gray"} variant="light" size="sm">
      {t(props.severity)}
    </Badge>
  );
}

/** Label/value rows. */
export function KeyValue(props: { rows: [ReactNode, ReactNode][]; labelWidth?: number }) {
  return (
    <Stack gap={6}>
      {props.rows.map(([k, v], i) => (
        <Group key={i} gap="sm" wrap="nowrap" align="flex-start">
          <Text size="sm" c="dimmed" w={props.labelWidth ?? 150} style={{ flex: "none" }}>
            {k}
          </Text>
          <div style={{ minWidth: 0, flex: 1, fontSize: "var(--mantine-font-size-sm)" }}>{v}</div>
        </Group>
      ))}
    </Stack>
  );
}
