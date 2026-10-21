import { useEffect, useMemo, useState } from "react";
import {
  Badge,
  Button,
  Code,
  Collapse,
  Group,
  MultiSelect,
  Paper,
  Select,
  Stack,
  Switch,
  Text,
  Textarea,
  TextInput,
  UnstyledButton,
} from "@mantine/core";
import { IconPlayerPlay, IconSearch } from "@tabler/icons-react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { create } from "@bufbuild/protobuf";
import { api } from "../api/client";
import { Code as ErrCode, isCode } from "../api/errors";
import { CopyIcon, EmptyState, ErrorAlert, KeyValue, LoadingBlock, PageHeader } from "../components/common";
import { TimeRange, rangeTimestamps } from "../components/TimeRange";
import { LogFilterSchema, type LogEntry, type LogFilter } from "../gen/openpicket/api/v1/logs_pb";
import { formatDateTime, tsDate } from "../lib/format";
import { t, useLanguage } from "../lib/i18n";
import { useUrlState } from "../lib/urlState";

const TYPES = ["eve", "nflog", "suricata", "agent"];
const MAX_TAIL = 2000;

function splitList(v: string): string[] {
  return v ? v.split(",").filter(Boolean) : [];
}

function useLabelValues(label: string) {
  return useQuery({
    queryKey: ["logLabels", label],
    queryFn: async () => (await api.logs.logLabelValues({ label })).values,
    staleTime: 60_000,
    retry: false,
  });
}

function pretty(line: string): string {
  try {
    return JSON.stringify(JSON.parse(line), null, 2);
  } catch {
    return line;
  }
}

function entryKey(e: LogEntry): string {
  const d = tsDate(e.time);
  return `${d?.getTime() ?? 0}:${e.line}`;
}

function LogRow(props: { entry: LogEntry }) {
  const [open, setOpen] = useState(false);
  const e = props.entry;
  const labels = e.labels;
  return (
    <Paper withBorder px="xs" py={4} radius="sm">
      <Group gap="xs" wrap="nowrap" align="flex-start">
        <UnstyledButton style={{ flex: 1, minWidth: 0 }} onClick={() => setOpen((o) => !o)}>
          <Group gap={6} wrap="nowrap">
            <Text size="xs" c="dimmed" ff="monospace" style={{ flex: "none", whiteSpace: "nowrap" }}>
              {formatDateTime(tsDate(e.time))}
            </Text>
            {labels.node && (
              <Badge size="xs" variant="light" style={{ flex: "none" }}>
                {labels.node}
              </Badge>
            )}
            {labels.type && (
              <Badge size="xs" variant="outline" color="gray" style={{ flex: "none" }}>
                {labels.type}
              </Badge>
            )}
            {labels.event_type && (
              <Badge size="xs" variant="light" color="grape" style={{ flex: "none" }}>
                {labels.event_type}
              </Badge>
            )}
            <Text className="log-line" truncate style={{ minWidth: 0, whiteSpace: "nowrap" }}>
              {e.line}
            </Text>
          </Group>
        </UnstyledButton>
        <CopyIcon value={e.line} label={t("Copy line")} />
      </Group>
      <Collapse in={open}>
        <Stack gap="xs" mt="xs">
          <Code block>
            <pre className="json">{pretty(e.line)}</pre>
          </Code>
          <KeyValue
            labelWidth={140}
            rows={Object.keys(labels)
              .sort()
              .map((k) => [k, <Text key={k} size="sm" ff="monospace" style={{ wordBreak: "break-all" }}>{labels[k]}</Text>])}
          />
        </Stack>
      </Collapse>
    </Paper>
  );
}

export default function LogsPage() {
  useLanguage();
  const [ip, setIp] = useUrlState("ip");
  const [node, setNode] = useUrlState("node");
  const [type, setType] = useUrlState("type");
  const [eventType, setEventType] = useUrlState("event");
  const [text, setText] = useUrlState("text");
  const [direction, setDirection] = useUrlState("direction");
  const [range, setRange] = useUrlState("range", "1h");
  const [logql, setLogql] = useUrlState("logql");
  const [limit, setLimit] = useState("200");
  const [advanced, setAdvanced] = useState(logql !== "");
  const [draftIp, setDraftIp] = useState(ip);
  const [draftText, setDraftText] = useState(text);
  const [draftLogql, setDraftLogql] = useState(logql);
  const [live, setLive] = useState(false);
  const [tail, setTail] = useState<LogEntry[]>([]);
  const [tailError, setTailError] = useState<unknown>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => setDraftIp(ip), [ip]);
  useEffect(() => setDraftText(text), [text]);
  useEffect(() => setDraftLogql(logql), [logql]);

  const nodes = useLabelValues("node");
  const eventTypes = useLabelValues("event_type");

  const filter: LogFilter = useMemo(
    () =>
      create(LogFilterSchema, {
        nodes: splitList(node),
        types: splitList(type),
        eventTypes: splitList(eventType),
        ip,
        text,
        direction,
        logql: advanced ? logql : "",
      }),
    [node, type, eventType, ip, text, direction, logql, advanced],
  );

  const query = useQuery({
    queryKey: ["logs", filter, range, limit, nonce],
    enabled: !live,
    placeholderData: keepPreviousData,
    queryFn: () => api.logs.queryLogs({ filter, ...rangeTimestamps(range), limit: Number(limit) }),
  });

  // Live tail: a server stream, restarted when the filter changes.
  useEffect(() => {
    if (!live) return;
    const ctrl = new AbortController();
    setTail([]);
    setTailError(null);
    (async () => {
      try {
        for await (const res of api.logs.tailLogs({ filter }, { signal: ctrl.signal })) {
          const fresh = [...res.entries].reverse();
          setTail((old) => [...fresh, ...old].slice(0, MAX_TAIL));
        }
      } catch (err) {
        if (!ctrl.signal.aborted) setTailError(err);
      }
    })();
    return () => ctrl.abort();
  }, [live, filter]);

  const apply = () => {
    setIp(draftIp.trim());
    setText(draftText);
    if (advanced) setLogql(draftLogql.trim());
    setNonce((n) => n + 1);
  };

  const notConfigured = isCode(query.error, ErrCode.FailedPrecondition) || isCode(tailError, ErrCode.FailedPrecondition);
  const entries = live ? tail : (query.data?.entries ?? []);
  const lastLogql = query.data?.logql ?? "";

  if (notConfigured) {
    return (
      <>
        <PageHeader title={t("Logs")} />
        <EmptyState
          title={t("The log explorer is not configured")}
          description={t("Set OPENPICKET_LOKI_URL (and OPENPICKET_LOKI_QUERY_URL if reads go to another endpoint) on openpicket-manager.")}
        />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title={t("Logs")}
        description={t("Raw eve, NFLOG, Suricata and agent logs stored in Loki.")}
        right={
          <Group gap="xs">
            {live && (
              <Badge color="red" variant="dot" className="live-badge" style={{ animation: "pulse 1.5s infinite" }}>
                {t("live")}
              </Badge>
            )}
            <Switch label={t("Live tail")} checked={live} onChange={(e) => setLive(e.currentTarget.checked)} />
          </Group>
        }
      />
      <style>{"@keyframes pulse { 0%,100% { opacity: 1 } 50% { opacity: .4 } }"}</style>
      <Paper withBorder p="sm" mb="md" radius="md">
        <Stack gap="xs">
          {!advanced ? (
            <Group gap="xs" align="flex-end" wrap="wrap">
              <MultiSelect
                label={t("Nodes")}
                data={nodes.data ?? []}
                value={splitList(node)}
                onChange={(v) => setNode(v.join(","))}
                searchable
                clearable
                w={200}
              />
              <MultiSelect label={t("Types")} data={TYPES} value={splitList(type)} onChange={(v) => setType(v.join(","))} clearable w={180} />
              <MultiSelect
                label={t("Event types")}
                data={eventTypes.data ?? []}
                value={splitList(eventType)}
                onChange={(v) => setEventType(v.join(","))}
                searchable
                clearable
                w={200}
              />
              <TextInput
                label={t("IP")}
                value={draftIp}
                onChange={(e) => setDraftIp(e.currentTarget.value)}
                onKeyDown={(e) => e.key === "Enter" && apply()}
                w={160}
                className="mono-input"
              />
              <TextInput
                label={t("Text")}
                value={draftText}
                onChange={(e) => setDraftText(e.currentTarget.value)}
                onKeyDown={(e) => e.key === "Enter" && apply()}
                w={200}
              />
              <Select
                label={t("Direction")}
                data={[
                  { value: "inbound", label: t("inbound") },
                  { value: "outbound", label: t("outbound") },
                  { value: "internal", label: t("internal") },
                ]}
                value={direction || null}
                onChange={(v) => setDirection(v ?? "")}
                clearable
                w={140}
              />
            </Group>
          ) : (
            <Textarea
              label={t("LogQL query")}
              description={t("A Loki log query; it replaces the filters.")}
              value={draftLogql}
              onChange={(e) => setDraftLogql(e.currentTarget.value)}
              autosize
              minRows={2}
              className="mono-input"
              placeholder={lastLogql || '{job="openpicket"}'}
            />
          )}
          <Group gap="xs" justify="space-between" wrap="wrap">
            <Group gap="xs">
              <TimeRange value={range} onChange={setRange} />
              <Select
                data={["100", "200", "500", "1000"].map((v) => ({ value: v, label: t("{n} lines", { n: v }) }))}
                value={limit}
                onChange={(v) => setLimit(v ?? "200")}
                allowDeselect={false}
                w={120}
                disabled={live}
              />
              <Switch
                label={t("Advanced: LogQL")}
                checked={advanced}
                onChange={(e) => {
                  const on = e.currentTarget.checked;
                  setAdvanced(on);
                  if (on && !draftLogql) setDraftLogql(lastLogql);
                  if (!on) setLogql("");
                }}
              />
            </Group>
            <Button leftSection={live ? <IconPlayerPlay size={16} /> : <IconSearch size={16} />} onClick={apply}>
              {t("Search")}
            </Button>
          </Group>
          {!advanced && lastLogql && (
            <Text size="xs" c="dimmed" ff="monospace" style={{ wordBreak: "break-all" }}>
              {lastLogql}
            </Text>
          )}
        </Stack>
      </Paper>
      {!live && query.isError && <ErrorAlert error={query.error} onRetry={() => query.refetch()} />}
      {live && tailError != null && <ErrorAlert error={tailError} title={t("Live tail stopped")} />}
      {!live && query.isPending && <LoadingBlock />}
      {!query.isPending && entries.length === 0 && !query.isError && (
        <EmptyState
          title={live ? t("Waiting for new lines…") : t("No log lines")}
          description={live ? undefined : t("Nothing matched in this time range. Widen the range or relax the filters.")}
        />
      )}
      <Stack gap={4}>
        {entries.map((e, i) => (
          <LogRow key={`${entryKey(e)}:${i}`} entry={e} />
        ))}
      </Stack>
      {!live && entries.length > 0 && (
        <Text size="xs" c="dimmed" mt="xs">
          {t("{n} lines shown", { n: entries.length })}
        </Text>
      )}
    </>
  );
}
