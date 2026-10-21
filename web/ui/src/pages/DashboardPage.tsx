import { useState } from "react";
import {
  Button,
  Drawer,
  Grid,
  Group,
  Paper,
  Progress,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  Title,
  UnstyledButton,
} from "@mantine/core";
import { BarChart } from "@mantine/charts";
import { IconAdjustmentsHorizontal, IconArrowRight } from "@tabler/icons-react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";
import { api } from "../api/client";
import { queryError } from "../api/errors";
import type { FacetValue } from "../gen/openpicket/api/v1/crowdsec_pb";
import { ErrorAlert, LoadingBlock, PageHeader } from "../components/common";
import { SearchBar } from "../components/SearchBar";
import { TimeRange, rangeBounds, rangeTimestamps } from "../components/TimeRange";
import { WorldMap } from "../components/WorldMap";
import { Facets } from "../components/Facets";
import { Country } from "../components/geo";
import { Scenario } from "../components/crowdsec";
import { ALERT_FIELDS } from "../lib/searchFields";
import { addTerm, compactNumber, formatDate, formatNumber, formatTime, toNumber, tsDate } from "../lib/format";
import { useUrlState } from "../lib/urlState";
import { useInstance } from "../lib/scope";
import { t } from "../lib/i18n";

function Stat(props: { label: string; value: bigint | number; sub?: string; color?: string; to?: string }) {
  const body = (
    <Paper withBorder p="md" radius="md" h="100%">
      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
        {props.label}
      </Text>
      <Text fz={28} fw={700} c={props.color}>
        {formatNumber(props.value)}
      </Text>
      {props.sub && (
        <Text size="xs" c="dimmed">
          {props.sub}
        </Text>
      )}
    </Paper>
  );
  return props.to ? (
    <UnstyledButton component={Link} to={props.to} style={{ display: "block" }}>
      {body}
    </UnstyledButton>
  ) : (
    body
  );
}

function TopList(props: { title: string; values: FacetValue[]; field: string; render?: (v: string) => React.ReactNode; onPick: (field: string, v: string) => void }) {
  const max = Math.max(1, ...props.values.map((v) => toNumber(v.count)));
  return (
    <Paper withBorder p="md" radius="md" h="100%">
      <Text fw={600} mb="xs">
        {props.title}
      </Text>
      {props.values.length === 0 && (
        <Text size="sm" c="dimmed">
          {t("No data")}
        </Text>
      )}
      <Stack gap={6}>
        {props.values.map((v) => (
          <UnstyledButton key={v.value} onClick={() => props.onPick(props.field, v.value)}>
            <Group justify="space-between" wrap="nowrap" gap="xs">
              <Text size="sm" truncate style={{ minWidth: 0 }}>
                {props.render ? props.render(v.value) : v.value}
              </Text>
              <Text size="sm" fw={600}>
                {compactNumber(v.count)}
              </Text>
            </Group>
            <Progress value={(toNumber(v.count) / max) * 100} size={4} mt={2} />
          </UnstyledButton>
        ))}
      </Stack>
    </Paper>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const instance = useInstance();
  const [query, setQuery] = useUrlState("q");
  const [range, setRange] = useUrlState("range", "24h");
  const [simulated, setSimulated] = useState(false);
  const [facets, setFacets] = useState(false);
  const summary = useQuery({
    queryKey: ["summary", query, range, instance, simulated],
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
    queryFn: () => api.dashboard.getSummary({ query, ...rangeTimestamps(range), instance, includeSimulated: simulated }),
  });
  const s = summary.data;
  const pick = (field: string, v: string) => setQuery(addTerm(query, field, v));
  const b = rangeBounds(range);
  const daily = b.to.getTime() - b.from.getTime() > 3 * 86400e3;
  // Every bucket of the range, empty ones included (the server returns
  // only buckets with alerts; buckets are UTC hours or days).
  const step = daily ? 86400e3 : 3600e3;
  const byStart = new Map((s?.series ?? []).map((p) => [tsDate(p.start)?.getTime() ?? 0, p]));
  const series: { t: string; alerts: number; decisions: number }[] = [];
  for (let ts = Math.floor(b.from.getTime() / step) * step; ts <= b.to.getTime(); ts += step) {
    const p = byStart.get(ts);
    const d = new Date(ts);
    series.push({ t: daily ? formatDate(d) : formatTime(d, false), alerts: toNumber(p?.alerts), decisions: toNumber(p?.decisions) });
  }
  const counts = Object.fromEntries((s?.map ?? []).map((m) => [m.country, toNumber(m.count)]));
  const alertsLink = `/alerts?${new URLSearchParams({ ...(query ? { q: query } : {}), range }).toString()}`;
  return (
    <>
      <PageHeader
        title={t("Dashboard")}
        right={
          <Button component={Link} to={alertsLink} variant="light" rightSection={<IconArrowRight size={16} />}>
            {t("Open in alerts")}
          </Button>
        }
      />
      <Group mb="md" align="flex-start" wrap="wrap">
        <SearchBar page="alerts" value={query} onSearch={setQuery} fields={ALERT_FIELDS} error={queryError(summary.error)} />
        <TimeRange value={range} onChange={setRange} />
        <Button variant="default" leftSection={<IconAdjustmentsHorizontal size={16} />} onClick={() => setFacets(true)}>
          {t("Quick filters")}
        </Button>
        <Switch label={t("Include simulated")} checked={simulated} onChange={(e) => setSimulated(e.currentTarget.checked)} mt={8} />
      </Group>
      {summary.isError && !queryError(summary.error) && <ErrorAlert error={summary.error} onRetry={() => summary.refetch()} />}
      {summary.isPending && <LoadingBlock h={300} />}
      {s && (
        <Stack>
          <SimpleGrid cols={{ base: 2, sm: 3, lg: 5 }}>
            <Stat label={t("Alerts")} value={s.alerts} to={alertsLink} />
            <Stat label={t("Active decisions")} value={s.activeDecisions} to="/decisions" color="red" />
            <Stat label={t("Compromised hosts")} value={s.compromisedHosts} color={s.compromisedHosts > 0n ? "red" : undefined}
              to={`/alerts?q=${encodeURIComponent("scope=openpicket_host")}&range=${range}`} />
            <Stat label={t("Nodes online")} value={s.nodesOnline} sub={t("of {n}", { n: formatNumber(s.nodesTotal) })} to="/nodes"
              color={s.nodesOnline < s.nodesTotal ? "orange" : "teal"} />
            {s.simulatedAlerts > 0n ? (
              <Stat label={t("Simulated alerts")} value={s.simulatedAlerts} sub={t("no decision applied")} />
            ) : (
              <Stat label={t("Countries")} value={(s.map ?? []).length} />
            )}
          </SimpleGrid>
          <Paper withBorder p="md" radius="md">
            <Title order={5} mb="sm">
              {t("Activity")}
            </Title>
            {(s.series ?? []).length === 0 ? (
              <Text c="dimmed" size="sm">
                {t("No alerts in this period.")}
              </Text>
            ) : (
              <BarChart
                h={220}
                data={series}
                dataKey="t"
                series={[
                  { name: "alerts", label: t("Alerts"), color: "blue.6" },
                  { name: "decisions", label: t("With decision"), color: "red.6" },
                ]}
                withLegend
                tickLine="none"
                gridAxis="y"
                barProps={{ radius: 2 }}
              />
            )}
          </Paper>
          <Grid>
            <Grid.Col span={{ base: 12, lg: 8 }}>
              <Paper withBorder p="md" radius="md" h="100%">
                <Title order={5} mb="sm">
                  {t("Attack sources")}
                </Title>
                <WorldMap counts={counts} onSelect={(cc) => pick("country", cc)} />
              </Paper>
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }}>
              <TopList title={t("Top countries")} field="country" values={s.topCountries} render={(v) => <Country cc={v} name />} onPick={pick} />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }}>
              <TopList title={t("Top scenarios")} field="scenario" values={s.topScenarios} render={(v) => <Scenario name={v} />} onPick={pick} />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }}>
              <TopList title={t("Top AS")} field="as" values={s.topAs} onPick={pick} />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }}>
              <TopList title={t("Top sources")} field="value" values={s.topSources} onPick={(_, v) => navigate(`/ip/${encodeURIComponent(v)}`)} />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }}>
              <TopList title={t("Top nodes")} field="node" values={s.topNodes} onPick={pick} />
            </Grid.Col>
          </Grid>
        </Stack>
      )}
      <Drawer opened={facets} onClose={() => setFacets(false)} title={t("Quick filters")} position="right" size="md">
        <Facets
          scope={{ query, range, instance, includeSimulated: simulated }}
          onAdd={(f, v, neg) => setQuery(addTerm(query, f, v, "=", neg))}
        />
      </Drawer>
    </>
  );
}
