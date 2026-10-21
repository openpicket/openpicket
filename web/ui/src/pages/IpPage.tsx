import { useState } from "react";
import {
  Badge,
  Button,
  Grid,
  Group,
  Paper,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { IconBan, IconEraser, IconFileText, IconSearch } from "@tabler/icons-react";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router";
import { api } from "../api/client";
import { useAccess } from "../api/hooks";
import { CopyText, EmptyState, ErrorAlert, KeyValue, LoadingBlock, PageHeader, TimeAgo, TimeLeft } from "../components/common";
import { Country } from "../components/geo";
import { AddDecisionModal, CleanupIpModal, DirectionBadge, Scenario } from "../components/crowdsec";
import { Propagation } from "../components/Propagation";
import { IocState, ProposeModal } from "./ApprovalsPage";
import { formatDateTime, formatNumber, toNumber, tsDate } from "../lib/format";
import { useInstance } from "../lib/scope";
import { t } from "../lib/i18n";

const IP_RE = /^[0-9a-fA-F:.]+$/;

function Lookup() {
  const navigate = useNavigate();
  const [v, setV] = useState("");
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (v.trim()) navigate(`/ip/${encodeURIComponent(v.trim())}`);
      }}
    >
      <Group align="flex-end">
        <TextInput
          label={t("IP address")}
          placeholder="198.51.100.4"
          value={v}
          onChange={(e) => setV(e.currentTarget.value)}
          className="mono-input"
          w={320}
          leftSection={<IconSearch size={16} />}
          data-autofocus
        />
        <Button type="submit" disabled={!IP_RE.test(v.trim())}>
          {t("Look up")}
        </Button>
      </Group>
    </form>
  );
}

/** Everything known about one address: geo, alerts, decisions, edge, logs. */
export default function IpPage() {
  const { ip = "" } = useParams();
  const access = useAccess();
  const instance = useInstance();
  const [ban, setBan] = useState(false);
  const [cleanup, setCleanup] = useState(false);
  const [proposing, setProposing] = useState(false);
  const intel = useQuery({ queryKey: ["intelStatus"], queryFn: () => api.intel.getIntelStatus({}), staleTime: 60_000 });
  const iocs = useQuery({
    queryKey: ["iocs", "ip", ip],
    enabled: IP_RE.test(ip) && intel.data?.configured === true,
    queryFn: async () => (await api.intel.listIOCs({ value: ip, limit: 20 })).iocs.filter((i) => i.value.split("|")[0] === ip),
  });
  const valid = IP_RE.test(ip);
  const quoted = `"${ip}"`;
  const geo = useQuery({
    queryKey: ["ip", "geo", ip],
    enabled: valid,
    queryFn: async () => (await api.geo.lookup({ ips: [ip] })).results[0],
  });
  const alerts = useQuery({
    queryKey: ["ip", "alerts", ip, instance],
    enabled: valid,
    queryFn: () =>
      api.alerts.searchAlerts({
        query: `value=${quoted} OR target=${quoted} OR meta.local_ip=${quoted}`,
        from: timestampFromDate(new Date(Date.now() - 365 * 86400e3)),
        instance,
        includeSimulated: true,
        limit: 100,
      }),
  });
  const decisions = useQuery({
    queryKey: ["ip", "decisions", ip, instance],
    enabled: valid,
    queryFn: () => api.decisions.searchDecisions({ query: `value=${quoted}`, includeExpired: true, instance, limit: 100 }),
  });
  if (!ip) {
    return (
      <>
        <PageHeader title={t("IP lookup")} description={t("Alerts, decisions, edge state, GeoIP and logs of an address.")} />
        <Lookup />
      </>
    );
  }
  if (!valid) return <ErrorAlert error={new Error(t("{ip} is not an IP address", { ip }))} />;
  const as = alerts.data?.alerts ?? [];
  const asSource = as.filter((a) => a.source?.value === ip);
  const asTarget = as.filter((a) => a.source?.value !== ip);
  const ds = decisions.data?.decisions ?? [];
  const active = ds.filter((d) => d.active);
  const scenarios = [...new Set(asSource.map((a) => a.scenario))];
  const nodes = [...new Set(as.map((a) => a.nodeId).filter(Boolean))];
  const first = asSource.length ? tsDate(asSource[asSource.length - 1].createdAt) : undefined;
  // GeoIP of the manager, else what CrowdSec recorded on the alerts.
  const src = asSource.find((a) => a.source?.country)?.source;
  const g = geo.data?.country
    ? geo.data
    : src
      ? { country: src.country, asn: Number(src.asNumber) || 0, asOrg: src.asName }
      : geo.data;
  return (
    <>
      <PageHeader
        title={<CopyText value={ip} display={<Text span fz={26} fw={700} ff="monospace">{ip}</Text>} />}
        description={
          <Group gap="xs" component="span">
            {active.length > 0 ? (
              <Badge color="red">{t("blocked")}</Badge>
            ) : (
              <Badge color="gray" variant="light">
                {t("not blocked")}
              </Badge>
            )}
            {g?.country && <Country cc={g.country} name />}
            {g?.asOrg && <Text span size="sm">{`AS${g.asn} ${g.asOrg}`}</Text>}
          </Group>
        }
        right={
          <>
            {access.features?.logs && (
              <Button variant="default" leftSection={<IconFileText size={16} />} component={Link} to={`/logs?ip=${encodeURIComponent(ip)}&range=7d`}>
                {t("Logs")}
              </Button>
            )}
            {access.canOperate && (
              <>
                <Button variant="default" leftSection={<IconEraser size={16} />} onClick={() => setCleanup(true)} disabled={ds.length === 0}>
                  {t("Clean up")}
                </Button>
                <Button color="red" leftSection={<IconBan size={16} />} onClick={() => setBan(true)}>
                  {t("Ban")}
                </Button>
              </>
            )}
          </>
        }
      />
      <Stack>
        <SimpleGrid cols={{ base: 2, md: 4 }}>
          <Paper withBorder p="md" radius="md">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
              {t("Alerts as source")}
            </Text>
            <Text fz={24} fw={700}>
              {formatNumber(asSource.length)}
              {toNumber(alerts.data?.total) > 100 ? "+" : ""}
            </Text>
          </Paper>
          <Paper withBorder p="md" radius="md">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
              {t("Alerts as target")}
            </Text>
            <Text fz={24} fw={700}>
              {formatNumber(asTarget.length)}
            </Text>
          </Paper>
          <Paper withBorder p="md" radius="md">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
              {t("Active decisions")}
            </Text>
            <Text fz={24} fw={700} c={active.length ? "red" : undefined}>
              {active.length}
            </Text>
          </Paper>
          <Paper withBorder p="md" radius="md">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
              {t("First seen")}
            </Text>
            <Text fz="lg" fw={600} mt={6}>
              {first ? formatDateTime(first) : "-"}
            </Text>
          </Paper>
        </SimpleGrid>
        <Grid>
          <Grid.Col span={{ base: 12, md: 5 }}>
            <Paper withBorder p="md" radius="md" h="100%">
              <Title order={5} mb="sm">
                {t("Summary")}
              </Title>
              <KeyValue
                rows={[
                  [t("Country"), <Country key="c" cc={g?.country} name />],
                  [t("AS"), g?.asn ? `AS${g.asn} ${g.asOrg}` : "-"],
                  [t("Scenarios"), scenarios.length ? <Stack gap={2}>{scenarios.map((s) => <Scenario key={s} name={s} />)}</Stack> : "-"],
                  [t("Seen by nodes"), nodes.length ? nodes.join(", ") : "-"],
                ]}
              />
            </Paper>
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 7 }}>
            <Paper withBorder p="md" radius="md" h="100%">
              <Title order={5} mb="sm">
                {t("Edge enforcement")}
              </Title>
              <Propagation value={ip} />
            </Paper>
          </Grid.Col>
        </Grid>
        {intel.data?.configured && (
          <Paper withBorder p="md" radius="md">
            <Group justify="space-between" mb="sm">
              <Title order={5}>MISP</Title>
              {access.canOperate && (iocs.data ?? []).every((i) => i.state === "revoked") && (
                <Button size="xs" variant="light" onClick={() => setProposing(true)}>
                  {t("Propose to MISP")}
                </Button>
              )}
            </Group>
            {(iocs.data ?? []).length === 0 ? (
              <Text size="sm" c="dimmed">
                {t("Not in MISP.")}
              </Text>
            ) : (
              <Stack gap={4}>
                {(iocs.data ?? []).map((i) => (
                  <Group key={i.uuid} gap="sm">
                    <IocState state={i.state} />
                    <Text size="sm">{i.type}</Text>
                    <Text size="sm" c="dimmed">
                      {i.eventInfo}
                    </Text>
                    {i.expiresAt && <TimeLeft ts={i.expiresAt} />}
                    <Link to={`/approvals?state=${i.state}`}>{t("Approvals")}</Link>
                  </Group>
                ))}
              </Stack>
            )}
          </Paper>
        )}
        <Paper withBorder p="md" radius="md">
          <Title order={5} mb="sm">
            {t("Decisions")}
          </Title>
          {decisions.isPending ? (
            <LoadingBlock />
          ) : ds.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("No decision")}
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={640}>
              <Table fz="sm">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t("Action")}</Table.Th>
                    <Table.Th>{t("Scenario")}</Table.Th>
                    <Table.Th>{t("Origin")}</Table.Th>
                    <Table.Th>{t("Expires")}</Table.Th>
                    <Table.Th>{t("Edge")}</Table.Th>
                    <Table.Th>{t("Instance")}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {ds.map((d) => (
                    <Table.Tr key={`${d.instance}/${d.id}`}>
                      <Table.Td>
                        <Badge color={d.active ? "red" : "gray"} variant="light" size="sm">
                          {d.type}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Scenario name={d.scenario} />
                      </Table.Td>
                      <Table.Td>{d.origin}</Table.Td>
                      <Table.Td>
                        <TimeLeft ts={d.until} />
                      </Table.Td>
                      <Table.Td>{d.edgeDirection ? <DirectionBadge direction={d.edgeDirection} /> : "-"}</Table.Td>
                      <Table.Td>{d.instance}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </Paper>
        <Paper withBorder p="md" radius="md">
          <Title order={5} mb="sm">
            {t("Alerts")}
          </Title>
          {alerts.isError && <ErrorAlert error={alerts.error} />}
          {alerts.isPending ? (
            <LoadingBlock />
          ) : as.length === 0 ? (
            <EmptyState title={t("No alerts in the last year")} />
          ) : (
            <Table.ScrollContainer minWidth={720}>
              <Table fz="sm" highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t("Time")}</Table.Th>
                    <Table.Th>{t("Role")}</Table.Th>
                    <Table.Th>{t("Scenario")}</Table.Th>
                    <Table.Th>{t("Node")}</Table.Th>
                    <Table.Th>{t("Direction")}</Table.Th>
                    <Table.Th>{t("Events")}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {as.map((a) => (
                    <Table.Tr key={`${a.instance}/${a.id}`}>
                      <Table.Td>
                        <Link to={`/alerts/${encodeURIComponent(a.instance)}/${a.id}`}>
                          <TimeAgo ts={a.createdAt} />
                        </Link>
                      </Table.Td>
                      <Table.Td>
                        <Badge size="sm" variant="light" color={a.source?.value === ip ? "red" : "blue"}>
                          {a.source?.value === ip ? t("source") : t("target")}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Scenario name={a.scenario} />
                      </Table.Td>
                      <Table.Td>{a.nodeId || "-"}</Table.Td>
                      <Table.Td>
                        <DirectionBadge direction={a.direction} />
                      </Table.Td>
                      <Table.Td>{a.eventsCount}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </Paper>
        <Group>
          <Lookup />
        </Group>
      </Stack>
      <AddDecisionModal opened={ban} onClose={() => setBan(false)} initialValue={ip} />
      <CleanupIpModal opened={cleanup} onClose={() => setCleanup(false)} ip={ip} />
      <ProposeModal opened={proposing} onClose={() => setProposing(false)} value={ip} />
    </>
  );
}
