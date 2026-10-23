import { useState, type ReactNode } from "react";
import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  List,
  Modal,
  Paper,
  Progress,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconArrowLeft, IconEdit, IconExternalLink, IconEye, IconTrash } from "@tabler/icons-react";
import { useMutation } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router";
import { api } from "../api/client";
import { useAccess, useNode } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import { CopyText, ErrorAlert, KeyValue, LoadingBlock, PageHeader, TimeAgo } from "../components/common";
import { LabelBadges, LabelsEditor, ListValue, SyncBadge, labelsToRows, refusalReason, rowsToLabels, type LabelRow } from "../components/nodes";
import { BundlePreview } from "../components/policyEditor";
import type { Node, SyncState } from "../gen/openpicket/api/v1/nodes_pb";
import { formatBytes, formatDateTime, formatNumber, toNumber } from "../lib/format";
import { t } from "../lib/i18n";

function invalidate(id: string) {
  void queryClient.invalidateQueries({ queryKey: ["node", id] });
  void queryClient.invalidateQueries({ queryKey: ["nodes"] });
}

function EditModal(props: { node: Node; opened: boolean; onClose: () => void }) {
  const [description, setDescription] = useState(props.node.description);
  const [labels, setLabels] = useState<LabelRow[]>(labelsToRows(props.node.labels));
  const save = useMutation({
    mutationFn: () => api.nodes.updateNode({ id: props.node.id, description, setLabels: true, labels: rowsToLabels(labels) }),
    meta: { errorTitle: t("Could not update the node") },
    onSuccess: () => {
      invalidate(props.node.id);
      notifications.show({ color: "teal", message: t("Node updated") });
      props.onClose();
    },
  });
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={t("Edit {id}", { id: props.node.id })} size="lg">
      <Stack>
        <TextInput label={t("Description")} value={description} onChange={(e) => setDescription(e.currentTarget.value)} />
        <LabelsEditor value={labels} onChange={setLabels} />
        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {t("Cancel")}
          </Button>
          <Button loading={save.isPending} onClick={() => save.mutate()}>
            {t("Save")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function Section(props: { title: string; children: ReactNode; right?: ReactNode }) {
  return (
    <Paper withBorder p="md" radius="md">
      <Group justify="space-between" mb="sm">
        <Title order={5}>{props.title}</Title>
        {props.right}
      </Group>
      {props.children}
    </Paper>
  );
}

function Overview(props: { node: Node }) {
  const n = props.node;
  const dp = n.dataPlane;
  return (
    <SimpleGrid cols={{ base: 1, lg: 2 }}>
      <Section title={t("Identity")}>
        <KeyValue
          rows={[
            [t("Node id"), <CopyText value={n.id} />],
            [t("Description"), n.description || "-"],
            [t("Labels"), <LabelBadges labels={n.labels} />],
            [t("Fingerprint"), <CopyText value={n.fingerprint} size="xs" />],
            [t("Public key"), <CopyText value={n.publicKey} size="xs" />],
            [t("Registered"), <TimeAgo ts={n.createdAt} />],
            [t("Suricata last seen"), <TimeAgo ts={n.suricataLastSeenAt} />],
          ]}
        />
      </Section>
      <Section title={t("Data plane")}>
        <KeyValue
          rows={[
            [t("Connected"), dp?.connected ? <Badge color="teal">{t("online")}</Badge> : <Badge color="red">{t("offline")}</Badge>],
            [t("Connected since"), dp?.connected ? <TimeAgo ts={dp.connectedAt} /> : "-"],
            [t("Last seen"), <TimeAgo ts={dp?.lastSeenAt} />],
            [t("Replica"), dp?.replica || "-"],
            [t("Remote address"), dp?.remoteAddr ? <CopyText value={dp.remoteAddr} /> : "-"],
            [t("Boot id"), dp?.bootId ? <CopyText value={dp.bootId} size="xs" /> : "-"],
            [t("Agent version"), dp?.agentVersion || "-"],
            [t("Capabilities"), <ListValue values={dp?.capabilities} />],
            [t("WAN interfaces"), <ListValue values={dp?.wanInterfaces} />],
          ]}
        />
      </Section>
      {(dp?.warnings.length ?? 0) > 0 && (
        <Section title={t("Warnings")}>
          <List size="sm" spacing={4}>
            {dp!.warnings.map((w, i) => (
              <List.Item key={i}>
                <Code>{w.code}</Code> {w.message}
              </List.Item>
            ))}
          </List>
        </Section>
      )}
    </SimpleGrid>
  );
}

function CountersTable(props: { counters: { [key: string]: bigint } | undefined; keyLabel: string }) {
  const rows = Object.entries(props.counters ?? {}).sort(([a], [b]) => a.localeCompare(b));
  if (rows.length === 0) return <Text size="sm" c="dimmed">{t("No counters yet")}</Text>;
  return (
    <Table withRowBorders={false} verticalSpacing={2} fz="sm">
      <Table.Thead>
        <Table.Tr>
          <Table.Th>{props.keyLabel}</Table.Th>
          <Table.Th ta="right">{t("Packets")}</Table.Th>
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {rows.map(([k, v]) => (
          <Table.Tr key={k}>
            <Table.Td ff="monospace">{k}</Table.Td>
            <Table.Td ta="right">{formatNumber(v)}</Table.Td>
          </Table.Tr>
        ))}
      </Table.Tbody>
    </Table>
  );
}

function StatusPanel(props: { node: Node }) {
  const st = props.node.dataPlane?.status;
  if (!st) {
    return (
      <Alert color="gray">{props.node.dataPlane?.connected ? t("The node has not sent a status report yet.") : t("The node is offline: no status.")}</Alert>
    );
  }
  const logs = st.logs;
  const used = toNumber(logs?.queueBytes);
  const cap = toNumber(logs?.queueCapacityBytes);
  const enf = st.enforcer;
  return (
    <Stack>
      <Text size="xs" c="dimmed">
        {t("Reported {time}", { time: formatDateTime(new Date(toNumber(st.timeUnixMs))) })}
      </Text>
      <SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Section title={t("Log shipping")}>
          <Stack gap="xs">
            <Group justify="space-between">
              <Text size="sm">{t("Queue")}</Text>
              <Text size="sm">
                {formatBytes(used)} / {formatBytes(cap)}
              </Text>
            </Group>
            <Progress value={cap > 0 ? (used / cap) * 100 : 0} color={cap > 0 && used / cap > 0.8 ? "red" : "blue"} />
            <KeyValue
              rows={[
                [t("Sent records"), formatNumber(logs?.sentRecords)],
                [t("Dropped records"), <Text size="sm" c={toNumber(logs?.droppedRecords) > 0 ? "red" : undefined}>{formatNumber(logs?.droppedRecords)}</Text>],
                [t("In-flight batches"), formatNumber(logs?.inflightBatches)],
                [t("In-flight bytes"), formatBytes(logs?.inflightBytes)],
              ]}
            />
          </Stack>
        </Section>
        <Section title={t("Ban enforcer")} right={<Badge color={enf?.enabled ? "teal" : "gray"}>{enf?.enabled ? t("enabled") : t("disabled")}</Badge>}>
          <Table withRowBorders={false} verticalSpacing={2} fz="sm">
            <Table.Tbody>
              {(
                [
                  [t("Decisions version"), formatNumber(enf?.decisionsVersion)],
                  [t("Inbound bans (IPv4)"), formatNumber(enf?.banInV4)],
                  [t("Inbound bans (IPv6)"), formatNumber(enf?.banInV6)],
                  [t("Two-way bans (IPv4)"), formatNumber(enf?.banBothV4)],
                  [t("Two-way bans (IPv6)"), formatNumber(enf?.banBothV6)],
                  [t("Decisions not applied"), formatNumber(enf?.rejected)],
                ] as [string, string][]
              ).map(([k, v]) => (
                <Table.Tr key={k}>
                  <Table.Td c="dimmed">{k}</Table.Td>
                  <Table.Td ta="right">{v}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
          {enf && enf.refused.length > 0 && (
            <Stack gap={4} mt="sm">
              <Text size="sm" fw={500}>
                {t("Not applied on this node")}
              </Text>
              <Table.ScrollContainer minWidth={360} mah={240}>
                <Table fz="xs" verticalSpacing={2}>
                  <Table.Tbody>
                    {enf.refused.map((r) => (
                      <Table.Tr key={r.value}>
                        <Table.Td ff="monospace">
                          {r.value.includes("/") ? r.value : <Link to={`/ip/${encodeURIComponent(r.value)}`}>{r.value}</Link>}
                        </Table.Td>
                        <Table.Td c="dimmed">{refusalReason(r.reason)}</Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
              {toNumber(enf.rejected) > enf.refused.length && (
                <Text size="xs" c="dimmed">
                  {t("{n} of {total} shown (local reasons first)", { n: enf.refused.length, total: formatNumber(enf.rejected) })}
                </Text>
              )}
            </Stack>
          )}
          {enf?.lastError && (
            <Alert color="red" mt="xs" title={t("Last error")}>
              {enf.lastError}
            </Alert>
          )}
        </Section>
        <Section
          title={t("Port policies")}
          right={<Badge color={st.policy?.enabled ? "teal" : "gray"}>{st.policy?.enabled ? t("enabled") : t("disabled")}</Badge>}
        >
          <Text size="sm" mb="xs">
            {t("Applied version")}: {formatNumber(st.policy?.version)}
          </Text>
          <CountersTable counters={st.policy?.packets} keyLabel={t("Rule")} />
          {st.policy?.lastError && (
            <Alert color="red" mt="xs" title={t("Last error")}>
              {st.policy.lastError}
            </Alert>
          )}
        </Section>
        <Section title={t("NFLOG")} right={<Badge color={st.nflog?.enabled ? "teal" : "gray"}>{st.nflog?.enabled ? t("enabled") : t("disabled")}</Badge>}>
          <CountersTable counters={st.nflog?.records} keyLabel={t("Prefix")} />
          {st.nflog?.ruleError && (
            <Alert color="orange" mt="xs" title={t("WAN-REJECT rule")}>
              {st.nflog.ruleError}
            </Alert>
          )}
          {st.nflog?.lastError && (
            <Alert color="red" mt="xs" title={t("Last error")}>
              {st.nflog.lastError}
            </Alert>
          )}
        </Section>
        <Section
          title={t("NAT lookup")}
          right={<Badge color={st.nat?.enabled ? (st.nat.ready ? "teal" : "orange") : "gray"}>{st.nat?.enabled ? (st.nat.ready ? t("enabled") : t("starting")) : t("disabled")}</Badge>}
        >
          <Text size="xs" c="dimmed" mb="xs">
            {t("Names the inside host of alerts seen on the other side of the node's NAT (conntrack).")}
          </Text>
          <KeyValue
            rows={[
              [t("Translated connections"), formatNumber(st.nat?.flows)],
              [t("Alerts with a translation"), formatNumber(st.nat?.hits)],
              [t("Alerts without one"), formatNumber(st.nat?.misses)],
              [t("Connections not kept (table full)"), <Text size="sm" c={toNumber(st.nat?.dropped) > 0 ? "red" : undefined}>{formatNumber(st.nat?.dropped)}</Text>],
              [t("Full listings"), formatNumber(st.nat?.resyncs)],
            ]}
          />
          {st.nat?.lastError && (
            <Alert color="red" mt="xs" title={t("Last error")}>
              {st.nat.lastError}
            </Alert>
          )}
        </Section>
        <Section title={t("Local networks")}>
          <KeyValue
            rows={[
              [t("HOME_NET"), <ListValue values={st.localNets?.homeNet} />],
              [t("Interface addresses"), <ListValue values={st.localNets?.interfaceAddrs} />],
              [t("Extra"), <ListValue values={st.localNets?.extra} />],
            ]}
          />
        </Section>
      </SimpleGrid>
    </Stack>
  );
}

function SyncRows(props: { state?: SyncState; size?: boolean }) {
  const s = props.state;
  return (
    <KeyValue
      rows={[
        [t("State"), <SyncBadge state={s} />],
        [t("Node version"), formatNumber(s?.version)],
        [t("Cluster version"), formatNumber(s?.current)],
        [t("Acknowledged"), <TimeAgo ts={s?.ackedAt} />],
        ...(props.size ? ([[t("Blocked values"), formatNumber(s?.setSize)]] as [string, ReactNode][]) : []),
        ...(s?.error ? ([[t("Error"), <Text size="sm" c="red">{s.error}</Text>]] as [string, ReactNode][]) : []),
        ...(s && s.skipped.some((id) => !s.stale.includes(id))
          ? ([[t("Skipped policies"), <ListValue values={s.skipped.filter((id) => !s.stale.includes(id))} />]] as [string, ReactNode][])
          : []),
        ...(s?.stale.length ? ([[t("Last good version deployed"), <ListValue values={s.stale} />]] as [string, ReactNode][]) : []),
      ]}
    />
  );
}

function SyncPanel(props: { node: Node }) {
  const preview = useMutation({
    mutationFn: () => api.policies.previewBundle({ nodeId: props.node.id }),
    meta: { errorTitle: t("Could not compile the bundle") },
  });
  return (
    <Stack>
      <SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Section title={t("Decisions")}>
          <SyncRows state={props.node.decisions} size />
        </Section>
        <Section
          title={t("Port policies")}
          right={
            <Button size="xs" variant="light" leftSection={<IconEye size={14} />} loading={preview.isPending} onClick={() => preview.mutate()}>
              {t("Preview policy bundle")}
            </Button>
          }
        >
          <SyncRows state={props.node.policy} />
        </Section>
      </SimpleGrid>
      {preview.data && (
        <Section title={t("Policy bundle preview")}>
          <BundlePreview preview={preview.data} />
        </Section>
      )}
    </Stack>
  );
}

export default function NodePage() {
  const { id = "" } = useParams();
  const node = useNode(id);
  const access = useAccess();
  const navigate = useNavigate();
  const [editing, setEditing] = useState(false);
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api.nodes.updateNode({ id, enabled, setLabels: false, labels: {} }),
    meta: { errorTitle: t("Could not update the node") },
    onSuccess: (_r, enabled) => {
      invalidate(id);
      notifications.show({ color: "teal", message: enabled ? t("Node enabled") : t("Node disabled") });
    },
  });
  const remove = useMutation({
    mutationFn: () => api.nodes.deleteNode({ id }),
    meta: { errorTitle: t("Could not delete the node") },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["nodes"] });
      notifications.show({ color: "teal", message: t("Node {id} deleted", { id }) });
      navigate("/nodes");
    },
  });
  if (node.isPending) return <LoadingBlock h={300} />;
  if (node.isError) return <ErrorAlert error={node.error} onRetry={() => node.refetch()} />;
  const n = node.data;
  const confirmDelete = () =>
    modals.openConfirmModal({
      title: t("Delete node {id}?", { id }),
      children: (
        <Text size="sm">
          {t("The node is removed from the registry and disconnected from both channels. Its agent can no longer connect until it is registered again.")}
        </Text>
      ),
      labels: { confirm: t("Delete"), cancel: t("Cancel") },
      confirmProps: { color: "red" },
      onConfirm: () => remove.mutate(),
    });
  return (
    <>
      <Button component={Link} to="/nodes" variant="subtle" size="xs" leftSection={<IconArrowLeft size={14} />} mb="xs">
        {t("Nodes")}
      </Button>
      <PageHeader
        title={
          <Group gap="sm">
            {n.id}
            {n.dataPlane?.connected ? <Badge color="teal">{t("online")}</Badge> : <Badge color="red">{t("offline")}</Badge>}
            {!n.enabled && <Badge color="gray">{t("disabled")}</Badge>}
          </Group>
        }
        description={n.description || undefined}
        right={
          access.canOperate && (
            <>
              <Switch
                label={t("Enabled")}
                checked={n.enabled}
                disabled={toggle.isPending}
                onChange={(e) => toggle.mutate(e.currentTarget.checked)}
              />
              <Button variant="default" leftSection={<IconEdit size={16} />} onClick={() => setEditing(true)}>
                {t("Edit")}
              </Button>
              <Button color="red" variant="light" leftSection={<IconTrash size={16} />} onClick={confirmDelete} loading={remove.isPending}>
                {t("Delete")}
              </Button>
            </>
          )
        }
      />
      <Tabs defaultValue="overview" keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="overview">{t("Overview")}</Tabs.Tab>
          <Tabs.Tab value="status">{t("Status")}</Tabs.Tab>
          <Tabs.Tab value="sync">{t("Sync")}</Tabs.Tab>
          {access.features?.suricata && <Tabs.Tab value="suricata">{t("Suricata")}</Tabs.Tab>}
        </Tabs.List>
        <Tabs.Panel value="overview">
          <Overview node={n} />
        </Tabs.Panel>
        <Tabs.Panel value="status">
          <StatusPanel node={n} />
        </Tabs.Panel>
        <Tabs.Panel value="sync">
          <SyncPanel node={n} />
        </Tabs.Panel>
        {access.features?.suricata && (
          <Tabs.Panel value="suricata">
            <Section title={t("Suricata")}>
              <Stack align="flex-start">
                <Text size="sm" c="dimmed">
                  {t("Suricata instances, rules and deployment of this node are managed in openpicket-suricontroller.")}
                </Text>
                <Button
                  component="a"
                  href={`/suricata/#/nodes/${encodeURIComponent(n.id)}`}
                  target="_blank"
                  rel="noopener"
                  rightSection={<IconExternalLink size={14} />}
                >
                  {t("Open in Suricata management")}
                </Button>
              </Stack>
            </Section>
          </Tabs.Panel>
        )}
      </Tabs>
      {editing && <EditModal node={n} opened={editing} onClose={() => setEditing(false)} />}
    </>
  );
}
