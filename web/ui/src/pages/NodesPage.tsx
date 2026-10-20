import { useState } from "react";
import { Badge, Button, Code, Group, Modal, Stack, Table, Text, Textarea, TextInput, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconPlugConnected, IconPlus } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { api } from "../api/client";
import { useAccess, useNodes } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import { CopyIcon, EmptyState, ErrorAlert, LoadingBlock, PageHeader, StatusDot, TimeAgo } from "../components/common";
import { LabelBadges, LabelsEditor, SyncBadge, rowsToLabels, type LabelRow } from "../components/nodes";
import { t } from "../lib/i18n";

function RegisterModal(props: { opened: boolean; onClose: () => void }) {
  const [key, setKey] = useState("");
  const [description, setDescription] = useState("");
  const [labels, setLabels] = useState<LabelRow[]>([]);
  const navigate = useNavigate();
  const register = useMutation({
    mutationFn: () => api.nodes.registerNode({ publicKey: key.trim(), description, labels: rowsToLabels(labels) }),
    meta: { errorTitle: t("Could not register the node") },
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["nodes"] });
      notifications.show({ color: "teal", message: t("Node {id} registered", { id: res.node?.id ?? "" }) });
      setKey("");
      setDescription("");
      setLabels([]);
      props.onClose();
      if (res.node) navigate(`/nodes/${res.node.id}`);
    },
  });
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={t("Register node")} size="lg">
      <Stack>
        <Textarea
          label={t("Public key")}
          description={t("The line printed by `openpicket-agent keygen` (ssh-ed25519 … <node-id>). The comment is the node id.")}
          placeholder="ssh-ed25519 AAAAC3Nza… edge-01"
          value={key}
          onChange={(e) => setKey(e.currentTarget.value)}
          autosize
          minRows={2}
          className="mono-input"
          required
          data-autofocus
        />
        <TextInput label={t("Description")} value={description} onChange={(e) => setDescription(e.currentTarget.value)} />
        <LabelsEditor value={labels} onChange={setLabels} />
        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {t("Cancel")}
          </Button>
          <Button disabled={!key.trim()} loading={register.isPending} onClick={() => register.mutate()}>
            {t("Register")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function ConnectionModal(props: { opened: boolean; onClose: () => void }) {
  const info = useQuery({
    queryKey: ["connectionInfo"],
    queryFn: () => api.nodes.getConnectionInfo({}),
    enabled: props.opened,
    staleTime: 5 * 60_000,
  });
  const origin = window.location.origin.replace(/^http/, "ws");
  const url = `${origin}${info.data?.dataPlanePath ?? "/agent/data/v1/connect"}`;
  const snippet = `openpicket:
  url: ${url}
  host_key: "${info.data?.managerHostKey ?? ""}"
  wan_interfaces: [wan]
  allowlist: [controller]
`;
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={t("Agent connection")} size="xl">
      {info.isPending ? (
        <LoadingBlock />
      ) : info.isError ? (
        <ErrorAlert error={info.error} />
      ) : (
        <Stack>
          <div>
            <Group gap={4}>
              <Text size="sm" fw={500}>
                {t("Manager host key")}
              </Text>
              <CopyIcon value={info.data.managerHostKey} />
            </Group>
            <Code block style={{ wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
              {info.data.managerHostKey}
            </Code>
          </div>
          <div>
            <Group gap={4}>
              <Text size="sm" fw={500}>
                {t("agent.yaml (openpicket section)")}
              </Text>
              <CopyIcon value={snippet} />
            </Group>
            <Code block>{snippet}</Code>
            <Text size="xs" c="dimmed" mt={4}>
              {t("Adjust the URL if agents reach the manager through another address, and list the WAN interfaces of the node.")}
            </Text>
          </div>
        </Stack>
      )}
    </Modal>
  );
}

export default function NodesPage() {
  const nodes = useNodes();
  const access = useAccess();
  const navigate = useNavigate();
  const [registering, setRegistering] = useState(false);
  const [connection, setConnection] = useState(false);
  const list = nodes.data ?? [];
  const online = list.filter((n) => n.dataPlane?.connected).length;
  return (
    <>
      <PageHeader
        title={t("Nodes")}
        description={nodes.data ? t("{online} of {total} nodes online", { online, total: list.length }) : undefined}
        right={
          <>
            <Button variant="default" leftSection={<IconPlugConnected size={16} />} onClick={() => setConnection(true)}>
              {t("Connection info")}
            </Button>
            {access.canOperate && (
              <Button leftSection={<IconPlus size={16} />} onClick={() => setRegistering(true)}>
                {t("Register node")}
              </Button>
            )}
          </>
        }
      />
      {nodes.isPending ? (
        <LoadingBlock />
      ) : nodes.isError ? (
        <ErrorAlert error={nodes.error} onRetry={() => nodes.refetch()} />
      ) : list.length === 0 ? (
        <EmptyState
          title={t("No nodes yet")}
          description={t("Install openpicket-agent on a router, run `openpicket-agent keygen` and register its public key here.")}
          action={
            access.canOperate && (
              <Button leftSection={<IconPlus size={16} />} onClick={() => setRegistering(true)}>
                {t("Register node")}
              </Button>
            )
          }
        />
      ) : (
        <Table.ScrollContainer minWidth={1100}>
          <Table highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("Node")}</Table.Th>
                <Table.Th>{t("Labels")}</Table.Th>
                <Table.Th>{t("Agent")}</Table.Th>
                <Table.Th>{t("Replica")}</Table.Th>
                <Table.Th>{t("Last seen")}</Table.Th>
                <Table.Th>{t("Decisions")}</Table.Th>
                <Table.Th>{t("Policies")}</Table.Th>
                <Table.Th>{t("Warnings")}</Table.Th>
                <Table.Th>{t("Suricata")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {list.map((n) => {
                const dp = n.dataPlane;
                const warnings = dp?.warnings ?? [];
                return (
                  <Table.Tr key={n.id} className="clickable-row" onClick={() => navigate(`/nodes/${encodeURIComponent(n.id)}`)}>
                    <Table.Td>
                      <Group gap="xs" wrap="nowrap">
                        <StatusDot color={!n.enabled ? "gray" : dp?.connected ? "teal" : "red"} label={<Text fw={600} size="sm">{n.id}</Text>} />
                        {!n.enabled && (
                          <Badge size="xs" color="gray">
                            {t("disabled")}
                          </Badge>
                        )}
                      </Group>
                      {n.description && (
                        <Text size="xs" c="dimmed" truncate maw={260}>
                          {n.description}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <LabelBadges labels={n.labels} />
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{dp?.agentVersion || "-"}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{dp?.connected ? dp.replica : "-"}</Text>
                    </Table.Td>
                    <Table.Td>
                      <TimeAgo ts={dp?.lastSeenAt} />
                    </Table.Td>
                    <Table.Td>
                      <SyncBadge state={n.decisions} extra={n.decisions ? t("{n} blocked values", { n: n.decisions.setSize }) : undefined} />
                    </Table.Td>
                    <Table.Td>
                      <SyncBadge
                        state={n.policy}
                        extra={n.policy?.skipped.length ? t("Skipped: {ids}", { ids: n.policy.skipped.join(", ") }) : undefined}
                      />
                      {(n.policy?.skipped.length ?? 0) > 0 && (
                        <Badge size="xs" color="orange" variant="outline" ml={4}>
                          {t("{n} skipped", { n: n.policy!.skipped.length })}
                        </Badge>
                      )}
                    </Table.Td>
                    <Table.Td>
                      {warnings.length > 0 ? (
                        <Tooltip label={warnings.map((w) => w.message).join("\n")} withArrow multiline maw={400}>
                          <Badge color="orange" variant="light" size="sm">
                            {warnings.length}
                          </Badge>
                        </Tooltip>
                      ) : (
                        <Text size="xs" c="dimmed">
                          -
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <TimeAgo ts={n.suricataLastSeenAt} />
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      <RegisterModal opened={registering} onClose={() => setRegistering(false)} />
      <ConnectionModal opened={connection} onClose={() => setConnection(false)} />
    </>
  );
}
