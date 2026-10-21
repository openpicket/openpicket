import { useState } from "react";
import { Accordion, Badge, Button, Code, Group, Paper, ScrollArea, Stack, Table, Text, Title } from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconBan, IconExternalLink, IconFileText, IconSearch, IconTrash } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";
import { api } from "../api/client";
import { queryClient } from "../api/queryClient";
import { useAccess } from "../api/hooks";
import { CopyText, ErrorAlert, KeyValue, LoadingBlock, TimeAgo, TimeLeft } from "./common";
import { Country } from "./geo";
import { AddDecisionModal, DirectionBadge, Scenario, SimulatedBadge, reportInstanceErrors } from "./crowdsec";
import { formatDateTime, tsDate } from "../lib/format";
import { t } from "../lib/i18n";

interface EventMeta {
  key: string;
  value: string;
}

/** Full view of one alert: source, context, decisions, events, actions. */
export function AlertDetail(props: { instance: string; id: bigint; onDeleted?: () => void }) {
  const access = useAccess();
  const navigate = useNavigate();
  const [ban, setBan] = useState(false);
  const q = useQuery({
    queryKey: ["alert", props.instance, props.id.toString()],
    queryFn: () => api.alerts.getAlert({ instance: props.instance, id: props.id }),
  });
  const del = useMutation({
    mutationFn: () => api.alerts.deleteAlerts({ instance: props.instance, ids: [props.id] }),
    meta: { errorTitle: t("Could not delete the alert") },
    onSuccess: (res) => {
      reportInstanceErrors(res.errors, t("Alert deleted"));
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      props.onDeleted?.();
    },
  });
  const deleteDecision = useMutation({
    mutationFn: (id: bigint) => api.decisions.deleteDecisions({ instance: props.instance, ids: [id] }),
    meta: { errorTitle: t("Could not delete the decision") },
    onSuccess: (res) => {
      reportInstanceErrors(res.errors, t("Decision deleted"));
      void queryClient.invalidateQueries({ queryKey: ["alert"] });
      void queryClient.invalidateQueries({ queryKey: ["decisions"] });
    },
  });
  if (q.isPending) return <LoadingBlock />;
  if (q.isError) return <ErrorAlert error={q.error} onRetry={() => q.refetch()} />;
  const a = q.data.alert!;
  const src = a.source;
  let events: { timestamp?: string; meta?: EventMeta[] }[] = [];
  try {
    events = JSON.parse(q.data.eventsJson || "[]");
  } catch {
    events = [];
  }
  const isIP = src?.scope?.toLowerCase() === "ip";
  return (
    <Stack>
      <Group justify="space-between" align="flex-start" wrap="wrap">
        <Stack gap={4}>
          <Group gap="xs">
            <Title order={4}>
              <Scenario name={a.scenario} />
            </Title>
            {a.simulated && <SimulatedBadge />}
            <DirectionBadge direction={a.direction} />
          </Group>
          <Text size="sm" c="dimmed">
            {a.message}
          </Text>
        </Stack>
        <Group gap="xs">
          {isIP && (
            <Button size="xs" variant="light" leftSection={<IconSearch size={14} />} component={Link} to={`/ip/${encodeURIComponent(src!.value)}`}>
              {t("IP details")}
            </Button>
          )}
          {access.features?.logs && isIP && (
            <Button size="xs" variant="light" leftSection={<IconFileText size={14} />} component={Link} to={`/logs?ip=${encodeURIComponent(src!.value)}`}>
              {t("Logs")}
            </Button>
          )}
          {access.canOperate && isIP && (
            <Button size="xs" color="red" variant="light" leftSection={<IconBan size={14} />} onClick={() => setBan(true)}>
              {t("Ban")}
            </Button>
          )}
          {access.canOperate && (
            <Button
              size="xs"
              color="red"
              variant="subtle"
              leftSection={<IconTrash size={14} />}
              loading={del.isPending}
              onClick={() =>
                modals.openConfirmModal({
                  title: t("Delete alert #{id}?", { id: a.id.toString() }),
                  children: <Text size="sm">{t("The alert and its decisions are deleted from the LAPI.")}</Text>,
                  labels: { confirm: t("Delete"), cancel: t("Cancel") },
                  confirmProps: { color: "red" },
                  onConfirm: () => del.mutate(),
                })
              }
            >
              {t("Delete")}
            </Button>
          )}
        </Group>
      </Group>
      <Paper withBorder p="md" radius="md">
        <KeyValue
          rows={[
            [t("Source"), <CopyText key="v" value={src?.value ?? ""} />],
            [t("Scope"), src?.scope],
            [t("Country"), <Country key="c" cc={src?.country} name />],
            [t("AS"), src?.asName ? `${src.asName} (AS${src.asNumber})` : "-"],
            [t("Node"), a.nodeId ? <Link to={`/nodes/${encodeURIComponent(a.nodeId)}`}>{a.nodeId}</Link> : "-"],
            [t("Events"), a.eventsCount],
            [t("Started"), formatDateTime(tsDate(a.startAt))],
            [t("Stopped"), formatDateTime(tsDate(a.stopAt))],
            [t("Created"), <TimeAgo key="t" ts={a.createdAt} />],
            [t("Machine"), a.machineId],
            [t("Instance"), `${a.instance} #${a.id}`],
          ]}
        />
      </Paper>
      {a.meta.length > 0 && (
        <Paper withBorder p="md" radius="md">
          <Text fw={600} mb="xs">
            {t("Alert context")}
          </Text>
          <KeyValue
            rows={a.meta.map((m) => [
              m.key,
              <Group key={m.key} gap={4}>
                {m.values.map((v) => (
                  <Badge
                    key={v}
                    variant="light"
                    color="gray"
                    style={{ textTransform: "none", cursor: "pointer" }}
                    onClick={() => navigate(`/alerts?q=${encodeURIComponent(`meta.${m.key}=${JSON.stringify(v)}`)}`)}
                  >
                    {v}
                  </Badge>
                ))}
              </Group>,
            ])}
          />
        </Paper>
      )}
      <Paper withBorder p="md" radius="md">
        <Text fw={600} mb="xs">
          {t("Decisions")}
        </Text>
        {a.decisions.length === 0 ? (
          <Text size="sm" c="dimmed">
            {t("No decision")}
          </Text>
        ) : (
          <Table.ScrollContainer minWidth={560}>
            <Table fz="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("Type")}</Table.Th>
                  <Table.Th>{t("Value")}</Table.Th>
                  <Table.Th>{t("Origin")}</Table.Th>
                  <Table.Th>{t("Expires")}</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {a.decisions.map((d) => (
                  <Table.Tr key={d.id.toString()}>
                    <Table.Td>
                      <Badge color={d.active ? "red" : "gray"} variant="light" size="sm">
                        {d.type}
                      </Badge>
                    </Table.Td>
                    <Table.Td ff="monospace">
                      {d.scope}:{d.value}
                    </Table.Td>
                    <Table.Td>{d.origin}</Table.Td>
                    <Table.Td>
                      <TimeLeft ts={d.until} />
                    </Table.Td>
                    <Table.Td>
                      {access.canOperate && d.active && (
                        <Button size="compact-xs" variant="subtle" color="red" onClick={() => deleteDecision.mutate(d.id)}>
                          {t("Remove")}
                        </Button>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      {events.length > 0 && (
        <Paper withBorder p="md" radius="md">
          <Text fw={600} mb="xs">
            {t("Events ({n})", { n: events.length })}
          </Text>
          <Accordion variant="separated">
            {events.map((e, i) => {
              const meta = e.meta ?? [];
              const summary = ["dest_port", "service", "log_type", "target_fqdn"]
                .map((k) => meta.find((m) => m.key === k))
                .filter(Boolean)
                .map((m) => `${m!.key}=${m!.value}`)
                .join(" ");
              return (
                <Accordion.Item key={i} value={String(i)}>
                  <Accordion.Control>
                    <Group gap="xs">
                      <Text size="sm">{e.timestamp ? formatDateTime(new Date(e.timestamp)) : `#${i + 1}`}</Text>
                      <Text size="xs" c="dimmed" ff="monospace" truncate>
                        {summary}
                      </Text>
                    </Group>
                  </Accordion.Control>
                  <Accordion.Panel>
                    <ScrollArea.Autosize mah={320}>
                      <KeyValue rows={meta.map((m) => [m.key, <Code key={m.key}>{m.value}</Code>])} />
                    </ScrollArea.Autosize>
                  </Accordion.Panel>
                </Accordion.Item>
              );
            })}
          </Accordion>
        </Paper>
      )}
      <Group justify="flex-end">
        <Button
          size="xs"
          variant="subtle"
          rightSection={<IconExternalLink size={14} />}
          component={Link}
          to={`/alerts/${encodeURIComponent(a.instance)}/${a.id}`}
          onClick={() => notifications.clean()}
        >
          {t("Permalink")}
        </Button>
      </Group>
      <AddDecisionModal opened={ban} onClose={() => setBan(false)} initialValue={src?.value} />
    </Stack>
  );
}
