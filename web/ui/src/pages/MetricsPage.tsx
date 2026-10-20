import { useMemo, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Group,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
  UnstyledButton,
} from "@mantine/core";
import { IconAlertTriangle, IconArrowDown, IconArrowUp, IconRefresh, IconSearch } from "@tabler/icons-react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { Code, isCode } from "../api/errors";
import { EmptyState, ErrorAlert, LoadingBlock, PageHeader, StatusDot, TimeAgo } from "../components/common";
import type { MetricsTable } from "../gen/openpicket/api/v1/metrics_pb";
import { t, useLanguage } from "../lib/i18n";

const NUMERIC = /^-?\d+(\.\d+)?$/;

function isNumericColumn(table: MetricsTable, col: number): boolean {
  return table.rows.length > 0 && table.rows.every((r) => r.cells[col] === undefined || NUMERIC.test(r.cells[col]) || r.cells[col] === "");
}

function MetricsTableView(props: { table: MetricsTable }) {
  const tb = props.table;
  const [sort, setSort] = useState<{ col: number; desc: boolean } | null>(null);
  const [filter, setFilter] = useState("");
  const numeric = useMemo(() => tb.columns.map((_, i) => isNumericColumn(tb, i)), [tb]);
  const rows = useMemo(() => {
    let out = tb.rows.map((r) => r.cells);
    if (filter) {
      const f = filter.toLowerCase();
      out = out.filter((cells) => cells.some((c) => c.toLowerCase().includes(f)));
    }
    if (sort) {
      const { col, desc } = sort;
      out = [...out].sort((a, b) => {
        const x = a[col] ?? "";
        const y = b[col] ?? "";
        const c = numeric[col] ? Number(x) - Number(y) : x.localeCompare(y);
        return desc ? -c : c;
      });
    }
    return out;
  }, [tb, filter, sort, numeric]);
  return (
    <Paper withBorder p="sm" radius="md">
      <Group justify="space-between" mb="xs" wrap="nowrap">
        <Title order={5}>{t(tb.title)}</Title>
        {tb.rows.length > 10 && (
          <TextInput
            size="xs"
            w={180}
            leftSection={<IconSearch size={12} />}
            placeholder={t("Filter")}
            value={filter}
            onChange={(e) => setFilter(e.currentTarget.value)}
          />
        )}
      </Group>
      <Table.ScrollContainer minWidth={400}>
        <Table striped highlightOnHover fz="sm" verticalSpacing={4}>
          <Table.Thead>
            <Table.Tr>
              {tb.columns.map((c, i) => (
                <Table.Th key={c} ta={numeric[i] ? "right" : undefined}>
                  <UnstyledButton
                    onClick={() => setSort((s) => (s?.col === i ? { col: i, desc: !s.desc } : { col: i, desc: numeric[i] }))}
                  >
                    <Group gap={2} wrap="nowrap" justify={numeric[i] ? "flex-end" : undefined}>
                      <Text size="sm" fw={600}>
                        {t(c)}
                      </Text>
                      {sort?.col === i && (sort.desc ? <IconArrowDown size={12} /> : <IconArrowUp size={12} />)}
                    </Group>
                  </UnstyledButton>
                </Table.Th>
              ))}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((cells, ri) => (
              <Table.Tr key={ri}>
                {cells.map((c, ci) => (
                  <Table.Td key={ci} ta={numeric[ci] ? "right" : undefined} ff={numeric[ci] ? "monospace" : undefined} style={{ wordBreak: "break-all" }}>
                    {c}
                  </Table.Td>
                ))}
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Paper>
  );
}

export default function MetricsPage() {
  useLanguage();
  const [endpoint, setEndpoint] = useState("");
  const q = useQuery({
    queryKey: ["crowdsecMetrics", endpoint],
    queryFn: () => api.metrics.getCrowdSecMetrics({ endpoint }),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
  });
  // The endpoint list comes from the combined view.
  const all = useQuery({
    queryKey: ["crowdsecMetrics", ""],
    queryFn: () => api.metrics.getCrowdSecMetrics({ endpoint: "" }),
    enabled: endpoint !== "",
    staleTime: 60_000,
  });
  const endpoints = (endpoint === "" ? q.data : all.data)?.endpoints ?? q.data?.endpoints ?? [];

  if (isCode(q.error, Code.FailedPrecondition)) {
    return (
      <>
        <PageHeader title={t("CrowdSec metrics")} />
        <EmptyState
          title={t("No CrowdSec metrics endpoint is configured")}
          description={t(
            "Set OPENPICKET_CROWDSEC_METRICS_URLS (e.g. http://crowdsec-lapi:6060/metrics) or OPENPICKET_CROWDSEC_METRICS_DISCOVERY_HOST (a headless service of the agents) on openpicket-manager.",
          )}
        />
      </>
    );
  }

  const data = q.data;
  return (
    <>
      <PageHeader
        title={t("CrowdSec metrics")}
        description={t("Runtime metrics of the CrowdSec agents and LAPIs, as cscli metrics shows them.")}
        right={
          <Group gap="xs">
            <Select
              w={240}
              data={[{ value: "", label: t("Combined") }, ...endpoints.map((e) => ({ value: e.name, label: e.name }))]}
              value={endpoint}
              onChange={(v) => setEndpoint(v ?? "")}
              allowDeselect={false}
            />
            <Tooltip label={t("Refresh")} withArrow>
              <ActionIcon variant="default" size="lg" onClick={() => q.refetch()} loading={q.isFetching}>
                <IconRefresh size={18} />
              </ActionIcon>
            </Tooltip>
          </Group>
        }
      />
      {q.isPending && <LoadingBlock />}
      {q.isError && <ErrorAlert error={q.error} onRetry={() => q.refetch()} />}
      {data && (
        <Stack>
          <Paper withBorder p="sm" radius="md">
            <Group justify="space-between" mb="xs">
              <Title order={5}>{t("Endpoints")}</Title>
              <Text size="xs" c="dimmed">
                {t("Scraped")} <TimeAgo ts={data.scrapedAt} size="xs" />
              </Text>
            </Group>
            <Stack gap={4}>
              {data.endpoints.map((e) => (
                <Group key={e.name} gap="sm" wrap="nowrap">
                  <Tooltip label={e.error || e.url} withArrow>
                    <div>
                      <StatusDot color={e.ok ? "green" : "red"} label={e.name} />
                    </div>
                  </Tooltip>
                  {e.version && (
                    <Badge size="xs" variant="light">
                      {e.version}
                    </Badge>
                  )}
                  {!e.ok && (
                    <Text size="xs" c="red" truncate>
                      {e.error}
                    </Text>
                  )}
                </Group>
              ))}
            </Stack>
          </Paper>
          {data.partial && (
            <Alert color="orange" icon={<IconAlertTriangle size={16} />}>
              {t("Some endpoints could not be scraped: the totals below are partial.")}
            </Alert>
          )}
          {data.tables.length === 0 && <EmptyState title={t("No metrics yet")} description={t("The endpoints answered without CrowdSec metrics.")} />}
          <SimpleGrid cols={{ base: 1, xl: 2 }}>
            {data.tables.map((tb) => (
              <MetricsTableView key={tb.name} table={tb} />
            ))}
          </SimpleGrid>
        </Stack>
      )}
    </>
  );
}
