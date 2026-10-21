import { useState } from "react";
import {
  ActionIcon,
  Badge,
  Button,
  Checkbox,
  Drawer,
  Grid,
  Group,
  Menu,
  Pagination,
  Paper,
  Select,
  Switch,
  Table,
  Text,
  Tooltip,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { IconAdjustmentsHorizontal, IconDownload, IconLayoutSidebarRightCollapse, IconTrash } from "@tabler/icons-react";
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { queryError } from "../api/errors";
import { queryClient } from "../api/queryClient";
import { useAccess } from "../api/hooks";
import type { Alert } from "../gen/openpicket/api/v1/crowdsec_pb";
import { EmptyState, ErrorAlert, LoadingBlock, PageHeader, TimeAgo } from "../components/common";
import { SearchBar } from "../components/SearchBar";
import { TimeRange, rangeTimestamps } from "../components/TimeRange";
import { Facets } from "../components/Facets";
import { Country } from "../components/geo";
import { AlertDetail } from "../components/AlertDetail";
import {
  ColumnPicker,
  DirectionBadge,
  Scenario,
  SimulatedBadge,
  reportInstanceErrors,
  useColumns,
  type Column,
} from "../components/crowdsec";
import { ALERT_FIELDS } from "../lib/searchFields";
import { addTerm, formatDateTime, formatNumber, toNumber, tsDate } from "../lib/format";
import { useUrlState } from "../lib/urlState";
import { useInstance } from "../lib/scope";
import { setPref, usePrefs } from "../lib/prefs";
import { t } from "../lib/i18n";

const PAGE = 50;

const COLUMNS: Column[] = [
  { key: "time", label: "Time", default: true },
  { key: "scenario", label: "Scenario", default: true },
  { key: "source", label: "Source", default: true },
  { key: "country", label: "Country", default: true },
  { key: "as", label: "AS", default: true },
  { key: "node", label: "Node", default: true },
  { key: "direction", label: "Direction", default: true },
  { key: "target", label: "Target", default: true },
  { key: "events", label: "Events", default: true },
  { key: "decisions", label: "Decisions", default: true },
  { key: "id", label: "ID", default: false },
  { key: "machine", label: "Machine", default: false },
  { key: "origin", label: "Origin", default: false },
  { key: "instance", label: "Instance", default: false },
];

function metaValue(a: Alert, key: string): string {
  return a.meta.find((m) => m.key === key)?.values[0] ?? "";
}

function cell(a: Alert, key: string, filter: (field: string, value: string) => void) {
  const click = (field: string, value: string) => (e: React.MouseEvent) => {
    if (!value) return;
    e.stopPropagation();
    filter(field, value);
  };
  switch (key) {
    case "time":
      return <TimeAgo ts={a.createdAt} />;
    case "scenario":
      return (
        <Group gap={4} wrap="nowrap">
          <span onClick={click("scenario", a.scenario)}>
            <Scenario name={a.scenario} />
          </span>
          {a.simulated && <SimulatedBadge />}
        </Group>
      );
    case "source":
      return (
        <Text size="sm" ff="monospace" onClick={click("value", a.source?.value ?? "")}>
          {a.source?.scope && a.source.scope !== "Ip" ? `${a.source.scope}:` : ""}
          {a.source?.value}
        </Text>
      );
    case "country":
      return (
        <span onClick={click("country", a.source?.country ?? "")}>
          <Country cc={a.source?.country} />
        </span>
      );
    case "as":
      return (
        <Text size="sm" truncate maw={180} onClick={click("as", a.source?.asName ?? "")}>
          {a.source?.asName || "-"}
        </Text>
      );
    case "node":
      return (
        <Text size="sm" onClick={click("node", a.nodeId)}>
          {a.nodeId || "-"}
        </Text>
      );
    case "direction":
      return <DirectionBadge direction={a.direction} />;
    case "target": {
      const v = metaValue(a, "dst_ip");
      const port = metaValue(a, "dst_port");
      return (
        <Text size="sm" ff="monospace" onClick={click("target", v)}>
          {v ? `${v}${port ? `:${port}` : ""}` : "-"}
        </Text>
      );
    }
    case "events":
      return formatNumber(a.eventsCount);
    case "decisions": {
      const active = a.decisions.filter((d) => d.active);
      if (a.decisions.length === 0) return <Text size="sm" c="dimmed">-</Text>;
      return (
        <Badge color={active.length > 0 ? "red" : "gray"} variant="light" size="sm">
          {active.length > 0 ? `${active[0].type}` : t("expired")}
          {a.decisions.length > 1 ? ` +${a.decisions.length - 1}` : ""}
        </Badge>
      );
    }
    case "id":
      return a.id.toString();
    case "machine":
      return a.machineId;
    case "origin":
      return [...new Set(a.decisions.map((d) => d.origin))].join(", ") || "-";
    case "instance":
      return a.instance;
  }
  return null;
}

function download(name: string, type: string, body: string) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const el = document.createElement("a");
  el.href = url;
  el.download = name;
  el.click();
  URL.revokeObjectURL(url);
}

function exportAlerts(alerts: Alert[], format: "csv" | "json") {
  const rows = alerts.map((a) => ({
    instance: a.instance,
    id: a.id.toString(),
    created_at: tsDate(a.createdAt)?.toISOString() ?? "",
    scenario: a.scenario,
    source_scope: a.source?.scope ?? "",
    source_value: a.source?.value ?? "",
    country: a.source?.country ?? "",
    as_name: a.source?.asName ?? "",
    as_number: a.source?.asNumber ?? "",
    node: a.nodeId,
    direction: a.direction,
    target: metaValue(a, "dst_ip"),
    events: a.eventsCount,
    simulated: a.simulated,
    decisions: a.decisions.map((d) => `${d.type}:${d.value}`).join(" "),
  }));
  if (format === "json") {
    download("alerts.json", "application/json", JSON.stringify(rows, null, 2));
    return;
  }
  const head = Object.keys(rows[0] ?? { id: "" });
  const esc = (v: unknown) => `"${String(v).replace(/"/g, '""')}"`;
  download("alerts.csv", "text/csv", [head.join(","), ...rows.map((r) => head.map((h) => esc(r[h as keyof typeof r])).join(","))].join("\n"));
}

export default function AlertsPage() {
  const access = useAccess();
  const instance = useInstance();
  const prefs = usePrefs();
  const [query, setQuery] = useUrlState("q");
  const [range, setRange] = useUrlState("range", "24h");
  const [order, setOrder] = useUrlState("order", "created_at");
  const [pageStr, setPageStr] = useUrlState("page", "1");
  const [simulated, setSimulated] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [open, setOpen] = useState<Alert | null>(null);
  const [facetsMobile, setFacetsMobile] = useState(false);
  const showFacets = prefs.facets.alerts ?? true;
  const page = Math.max(1, Number(pageStr) || 1);
  const [visible, toggleColumn] = useColumns("alerts", COLUMNS);
  const cols = COLUMNS.filter((c) => visible.has(c.key));
  const search = (q: string) => {
    setQuery(q);
    setPageStr("1");
    setSelected(new Set());
  };
  const list = useQuery({
    queryKey: ["alerts", query, range, instance, simulated, order, page],
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
    queryFn: () =>
      api.alerts.searchAlerts({
        query,
        ...rangeTimestamps(range),
        instance,
        includeSimulated: simulated,
        orderBy: order,
        limit: PAGE,
        offset: (page - 1) * PAGE,
      }),
  });
  const del = useMutation({
    mutationFn: async (alerts: Alert[]) => {
      const byInstance = new Map<string, bigint[]>();
      for (const a of alerts) byInstance.set(a.instance, [...(byInstance.get(a.instance) ?? []), a.id]);
      const errors = [];
      for (const [inst, ids] of byInstance) errors.push(...(await api.alerts.deleteAlerts({ instance: inst, ids })).errors);
      return errors;
    },
    meta: { errorTitle: t("Could not delete alerts") },
    onSuccess: (errors) => {
      reportInstanceErrors(errors, t("Alerts deleted"));
      setSelected(new Set());
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });
  const alerts = list.data?.alerts ?? [];
  const total = toNumber(list.data?.total);
  const key = (a: Alert) => `${a.instance}/${a.id}`;
  const filter = (field: string, value: string) => search(addTerm(query, field, value));
  const facets = (
    <Facets scope={{ query, range, instance, includeSimulated: simulated }} onAdd={(f, v, neg) => search(addTerm(query, f, v, "=", neg))} />
  );
  return (
    <>
      <PageHeader
        title={t("Alerts")}
        description={list.data ? t("{n} alerts", { n: formatNumber(total) }) : undefined}
        right={
          <>
            {access.canOperate && selected.size > 0 && (
              <Button
                color="red"
                variant="light"
                leftSection={<IconTrash size={16} />}
                loading={del.isPending}
                onClick={() =>
                  modals.openConfirmModal({
                    title: t("Delete {n} alerts?", { n: selected.size }),
                    children: <Text size="sm">{t("The alerts and their decisions are deleted from the LAPI.")}</Text>,
                    labels: { confirm: t("Delete"), cancel: t("Cancel") },
                    confirmProps: { color: "red" },
                    onConfirm: () => del.mutate(alerts.filter((a) => selected.has(key(a)))),
                  })
                }
              >
                {t("Delete {n}", { n: selected.size })}
              </Button>
            )}
            <Menu position="bottom-end" withArrow>
              <Menu.Target>
                <Tooltip label={t("Export this page")} withArrow>
                  <ActionIcon variant="default" size="lg" disabled={alerts.length === 0}>
                    <IconDownload size={18} />
                  </ActionIcon>
                </Tooltip>
              </Menu.Target>
              <Menu.Dropdown>
                <Menu.Item onClick={() => exportAlerts(alerts, "csv")}>CSV</Menu.Item>
                <Menu.Item onClick={() => exportAlerts(alerts, "json")}>JSON</Menu.Item>
              </Menu.Dropdown>
            </Menu>
            <ColumnPicker columns={COLUMNS} visible={visible} onToggle={toggleColumn} />
          </>
        }
      />
      <Group mb="md" align="flex-start" wrap="wrap">
        <SearchBar page="alerts" value={query} onSearch={search} fields={ALERT_FIELDS} error={queryError(list.error)} />
        <TimeRange value={range} onChange={(r) => (setRange(r), setPageStr("1"))} />
        <Select
          w={160}
          data={[
            { value: "created_at", label: t("Newest first") },
            { value: "events_count", label: t("Most events") },
            { value: "scenario", label: t("By scenario") },
          ]}
          value={order}
          onChange={(v) => setOrder(v ?? "created_at")}
          allowDeselect={false}
        />
        <Switch label={t("Include simulated")} checked={simulated} onChange={(e) => setSimulated(e.currentTarget.checked)} mt={8} />
        <Tooltip label={showFacets ? t("Hide quick filters") : t("Show quick filters")} withArrow>
          <ActionIcon variant="default" size="lg" visibleFrom="lg" onClick={() => setPref("facets", { ...prefs.facets, alerts: !showFacets })}>
            {showFacets ? <IconLayoutSidebarRightCollapse size={18} /> : <IconAdjustmentsHorizontal size={18} />}
          </ActionIcon>
        </Tooltip>
        <Button variant="default" hiddenFrom="lg" leftSection={<IconAdjustmentsHorizontal size={16} />} onClick={() => setFacetsMobile(true)}>
          {t("Quick filters")}
        </Button>
      </Group>
      <Grid>
        <Grid.Col span={{ base: 12, lg: showFacets ? 9 : 12 }}>
          {list.isError && !queryError(list.error) && <ErrorAlert error={list.error} onRetry={() => list.refetch()} />}
          {list.isPending && <LoadingBlock h={300} />}
          {list.data && alerts.length === 0 && <EmptyState title={t("No alerts")} description={t("Nothing matches this search in the selected period.")} />}
          {alerts.length > 0 && (
            <Paper withBorder radius="md">
              <Table.ScrollContainer minWidth={900}>
                <Table highlightOnHover fz="sm" verticalSpacing={6} style={{ whiteSpace: "nowrap" }}>
                  <Table.Thead>
                    <Table.Tr>
                      {access.canOperate && (
                        <Table.Th w={32}>
                          <Checkbox
                            size="xs"
                            checked={alerts.every((a) => selected.has(key(a)))}
                            indeterminate={selected.size > 0 && !alerts.every((a) => selected.has(key(a)))}
                            onChange={(e) => setSelected(e.currentTarget.checked ? new Set(alerts.map(key)) : new Set())}
                            aria-label={t("Select all")}
                          />
                        </Table.Th>
                      )}
                      {cols.map((c) => (
                        <Table.Th key={c.key}>{t(c.label)}</Table.Th>
                      ))}
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody style={{ opacity: list.isPlaceholderData ? 0.6 : 1 }}>
                    {alerts.map((a) => (
                      <Table.Tr key={key(a)} className="clickable-row" onClick={() => setOpen(a)}>
                        {access.canOperate && (
                          <Table.Td onClick={(e) => e.stopPropagation()}>
                            <Checkbox
                              size="xs"
                              checked={selected.has(key(a))}
                              onChange={(e) => {
                                const next = new Set(selected);
                                if (e.currentTarget.checked) next.add(key(a));
                                else next.delete(key(a));
                                setSelected(next);
                              }}
                              aria-label={t("Select")}
                            />
                          </Table.Td>
                        )}
                        {cols.map((c) => (
                          <Table.Td key={c.key} title={c.key === "time" ? formatDateTime(tsDate(a.createdAt)) : undefined}>
                            {cell(a, c.key, filter)}
                          </Table.Td>
                        ))}
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
              {total > PAGE && (
                <Group justify="center" p="sm">
                  <Pagination total={Math.ceil(total / PAGE)} value={page} onChange={(p) => setPageStr(String(p))} size="sm" />
                </Group>
              )}
            </Paper>
          )}
        </Grid.Col>
        {showFacets && (
          <Grid.Col span={3} visibleFrom="lg">
            {facets}
          </Grid.Col>
        )}
      </Grid>
      <Drawer opened={facetsMobile} onClose={() => setFacetsMobile(false)} title={t("Quick filters")} position="right">
        {facets}
      </Drawer>
      <Drawer opened={open !== null} onClose={() => setOpen(null)} position="right" size="xl" title={open ? t("Alert #{id}", { id: open.id.toString() }) : ""}>
        {open && <AlertDetail instance={open.instance} id={open.id} onDeleted={() => setOpen(null)} />}
      </Drawer>
    </>
  );
}
