import { useMemo, useState } from "react";
import {
  ActionIcon,
  Badge,
  Button,
  Chip,
  Group,
  Menu,
  Modal,
  Pagination,
  Paper,
  SegmentedControl,
  Stack,
  Switch,
  Table,
  Text,
  Tooltip,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { IconBan, IconBroadcast, IconDots, IconEraser, IconSearch, IconTrash } from "@tabler/icons-react";
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../api/client";
import { queryError } from "../api/errors";
import { queryClient } from "../api/queryClient";
import { useAccess } from "../api/hooks";
import type { Decision } from "../gen/openpicket/api/v1/crowdsec_pb";
import { EmptyState, ErrorAlert, LoadingBlock, PageHeader, TimeLeft } from "../components/common";
import { SearchBar } from "../components/SearchBar";
import { Country } from "../components/geo";
import {
  AddDecisionModal,
  CleanupIpModal,
  ColumnPicker,
  DirectionBadge,
  Scenario,
  reportInstanceErrors,
  useColumns,
  type Column,
} from "../components/crowdsec";
import { Propagation } from "../components/Propagation";
import { DECISION_FIELDS } from "../lib/searchFields";
import { addTerm, formatNumber, toNumber } from "../lib/format";
import { useUrlState } from "../lib/urlState";
import { useInstance } from "../lib/scope";
import { t } from "../lib/i18n";

const PAGE = 50;

const COLUMNS: Column[] = [
  { key: "value", label: "Value", default: true },
  { key: "type", label: "Action", default: true },
  { key: "scenario", label: "Scenario", default: true },
  { key: "origin", label: "Origin", default: true },
  { key: "country", label: "Country", default: true },
  { key: "as", label: "AS", default: true },
  { key: "expires", label: "Expires", default: true },
  { key: "edge", label: "Edge", default: true },
  { key: "alert", label: "Alert", default: false },
  { key: "id", label: "ID", default: false },
  { key: "instance", label: "Instance", default: false },
];

/** Value counts of a field on the current page, for quick filter chips. */
function counts(ds: Decision[], f: (d: Decision) => string): [string, number][] {
  const m = new Map<string, number>();
  for (const d of ds) {
    const v = f(d);
    if (v) m.set(v, (m.get(v) ?? 0) + 1);
  }
  return [...m].sort((a, b) => b[1] - a[1]).slice(0, 6);
}

export default function DecisionsPage() {
  const access = useAccess();
  const instance = useInstance();
  const [query, setQuery] = useUrlState("q");
  const [status, setStatus] = useUrlState("status", "active");
  const [dupes, setDupes] = useUrlState("dupes", "hide");
  const [pageStr, setPageStr] = useUrlState("page", "1");
  const [adding, setAdding] = useState(false);
  const [cleanup, setCleanup] = useState<string | undefined>(undefined);
  const [propagation, setPropagation] = useState<string | null>(null);
  const page = Math.max(1, Number(pageStr) || 1);
  const [visible, toggleColumn] = useColumns("decisions", COLUMNS);
  const cols = COLUMNS.filter((c) => visible.has(c.key));
  const search = (q: string) => {
    setQuery(q);
    setPageStr("1");
  };
  const list = useQuery({
    queryKey: ["decisions", query, status, dupes, instance, page],
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
    queryFn: () =>
      api.decisions.searchDecisions({
        query,
        includeExpired: status === "all",
        hideDuplicates: dupes === "hide",
        instance,
        limit: PAGE,
        offset: (page - 1) * PAGE,
      }),
  });
  const del = useMutation({
    mutationFn: (d: Decision) => api.decisions.deleteDecisions({ instance: d.instance, ids: [d.id] }),
    meta: { errorTitle: t("Could not delete the decision") },
    onSuccess: (res, d) => {
      reportInstanceErrors(res.errors, t("Decision on {value} deleted", { value: d.value }));
      void queryClient.invalidateQueries({ queryKey: ["decisions"] });
    },
  });
  const ds = list.data?.decisions ?? [];
  const total = toNumber(list.data?.total);
  const chips = useMemo(
    () => [
      ...counts(ds, (d) => d.origin).map(([v, n]) => ({ field: "origin", v, n })),
      ...counts(ds, (d) => d.scenario).map(([v, n]) => ({ field: "scenario", v, n })),
    ],
    [ds],
  );
  const cell = (d: Decision, key: string) => {
    switch (key) {
      case "value":
        return (
          <Group gap={4} wrap="nowrap">
            <Text size="sm" ff="monospace">
              {d.scope !== "Ip" ? `${d.scope}:` : ""}
              {d.value}
            </Text>
          </Group>
        );
      case "type":
        return (
          <Badge color={d.active ? (d.type === "ban" ? "red" : "orange") : "gray"} variant="light" size="sm">
            {d.type}
          </Badge>
        );
      case "scenario":
        return <Scenario name={d.scenario} />;
      case "origin":
        return d.origin;
      case "country":
        return <Country cc={d.country} />;
      case "as":
        return (
          <Text size="sm" truncate maw={180}>
            {d.asName || "-"}
          </Text>
        );
      case "expires":
        return <TimeLeft ts={d.until} />;
      case "edge":
        return d.edgeDirection ? (
          <DirectionBadge direction={d.edgeDirection} />
        ) : (
          <Tooltip label={t("Not applied by the nodes (not an IP/range ban, or excluded by the edge rules)")} withArrow>
            <Text size="sm" c="dimmed">
              -
            </Text>
          </Tooltip>
        );
      case "alert":
        return (
          <Link to={`/alerts/${encodeURIComponent(d.instance)}/${d.alertId}`} onClick={(e) => e.stopPropagation()}>
            #{d.alertId.toString()}
          </Link>
        );
      case "id":
        return d.id.toString();
      case "instance":
        return d.instance;
    }
    return null;
  };
  return (
    <>
      <PageHeader
        title={t("Decisions")}
        description={list.data ? t("{n} decisions", { n: formatNumber(total) }) : undefined}
        right={
          <>
            {access.canOperate && (
              <>
                <Button variant="default" leftSection={<IconEraser size={16} />} onClick={() => setCleanup("")}>
                  {t("Clean up IP")}
                </Button>
                <Button color="red" leftSection={<IconBan size={16} />} onClick={() => setAdding(true)}>
                  {t("Add decision")}
                </Button>
              </>
            )}
            <ColumnPicker columns={COLUMNS} visible={visible} onToggle={toggleColumn} />
          </>
        }
      />
      <Group mb="xs" align="flex-start" wrap="wrap">
        <SearchBar page="decisions" value={query} onSearch={search} fields={DECISION_FIELDS} error={queryError(list.error)} />
        <SegmentedControl
          value={status}
          onChange={(v) => (setStatus(v), setPageStr("1"))}
          data={[
            { value: "active", label: t("Active") },
            { value: "all", label: t("Include expired") },
          ]}
        />
        <Switch label={t("Hide duplicates")} checked={dupes === "hide"} onChange={(e) => setDupes(e.currentTarget.checked ? "hide" : "show")} mt={8} />
      </Group>
      {chips.length > 0 && (
        <Group gap={6} mb="md">
          {chips.map((c) => (
            <Chip key={`${c.field}:${c.v}`} size="xs" variant="outline" checked={false} onClick={() => search(addTerm(query, c.field, c.v))}>
              {c.field}: {c.v} ({c.n})
            </Chip>
          ))}
        </Group>
      )}
      {list.isError && !queryError(list.error) && <ErrorAlert error={list.error} onRetry={() => list.refetch()} />}
      {list.isPending && <LoadingBlock h={300} />}
      {list.data && ds.length === 0 && (
        <EmptyState title={status === "active" ? t("No active decisions") : t("No decisions")} description={t("Nothing matches this search.")} />
      )}
      {ds.length > 0 && (
        <Paper withBorder radius="md">
          <Table.ScrollContainer minWidth={900}>
            <Table highlightOnHover fz="sm" verticalSpacing={6} style={{ whiteSpace: "nowrap" }}>
              <Table.Thead>
                <Table.Tr>
                  {cols.map((c) => (
                    <Table.Th key={c.key}>{t(c.label)}</Table.Th>
                  ))}
                  <Table.Th w={40} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody style={{ opacity: list.isPlaceholderData ? 0.6 : 1 }}>
                {ds.map((d) => (
                  <Table.Tr key={`${d.instance}/${d.id}`}>
                    {cols.map((c) => (
                      <Table.Td key={c.key}>{cell(d, c.key)}</Table.Td>
                    ))}
                    <Table.Td>
                      <Menu position="bottom-end" withArrow>
                        <Menu.Target>
                          <ActionIcon variant="subtle" color="gray" aria-label={t("Actions")}>
                            <IconDots size={16} />
                          </ActionIcon>
                        </Menu.Target>
                        <Menu.Dropdown>
                          {d.scope === "Ip" && (
                            <Menu.Item leftSection={<IconSearch size={14} />} component={Link} to={`/ip/${encodeURIComponent(d.value)}`}>
                              {t("IP details")}
                            </Menu.Item>
                          )}
                          <Menu.Item leftSection={<IconBroadcast size={14} />} onClick={() => setPropagation(d.value)}>
                            {t("Propagation to nodes")}
                          </Menu.Item>
                          {access.canOperate && d.active && (
                            <Menu.Item
                              color="red"
                              leftSection={<IconTrash size={14} />}
                              onClick={() =>
                                modals.openConfirmModal({
                                  title: t("Delete the decision on {value}?", { value: d.value }),
                                  children: <Text size="sm">{t("Nodes unblock the address within seconds.")}</Text>,
                                  labels: { confirm: t("Delete"), cancel: t("Cancel") },
                                  confirmProps: { color: "red" },
                                  onConfirm: () => del.mutate(d),
                                })
                              }
                            >
                              {t("Delete")}
                            </Menu.Item>
                          )}
                          {access.canOperate && d.scope === "Ip" && (
                            <Menu.Item color="red" leftSection={<IconEraser size={14} />} onClick={() => setCleanup(d.value)}>
                              {t("Clean up IP")}
                            </Menu.Item>
                          )}
                        </Menu.Dropdown>
                      </Menu>
                    </Table.Td>
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
      <AddDecisionModal opened={adding} onClose={() => setAdding(false)} />
      <CleanupIpModal opened={cleanup !== undefined} onClose={() => setCleanup(undefined)} ip={cleanup} />
      <Modal opened={propagation !== null} onClose={() => setPropagation(null)} title={t("Propagation of {value}", { value: propagation ?? "" })} size="lg">
        <Stack>{propagation && <Propagation value={propagation} />}</Stack>
      </Modal>
    </>
  );
}
