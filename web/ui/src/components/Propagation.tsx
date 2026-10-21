import { Alert, Badge, Group, Stack, Table, Text, Tooltip } from "@mantine/core";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../api/client";
import { ErrorAlert, LoadingBlock, StatusDot, TimeAgo, TimeLeft } from "./common";
import { DirectionBadge } from "./crowdsec";
import { refusalReason } from "./nodes";
import type { NodePropagation } from "../gen/openpicket/api/v1/crowdsec_pb";
import { toNumber } from "../lib/format";
import { t } from "../lib/i18n";

/** Whether the node has the decision in force, and if not, why. */
function NodeState(props: { n: NodePropagation }): ReactNode {
  const n = props.n;
  if (n.error) {
    return (
      <Tooltip label={n.error} withArrow multiline w={320}>
        <span>
          <StatusDot color="red" label={t("error")} />
        </span>
      </Tooltip>
    );
  }
  if (n.refused) {
    return (
      <Stack gap={0}>
        <StatusDot color="gray" label={t("not applied")} />
        <Text size="xs" c="dimmed">
          {refusalReason(n.refused)}
        </Text>
      </Stack>
    );
  }
  if (n.applied && n.maybeRefused) {
    return (
      <Tooltip label={t("The node is over its element limit and does not report every decision it leaves out; this one may be among them.")} withArrow multiline w={320}>
        <span>
          <StatusDot color="yellow" label={t("applied?")} />
        </span>
      </Tooltip>
    );
  }
  if (n.applied) return <StatusDot color="teal" label={t("applied")} />;
  return <StatusDot color={n.connected ? "orange" : "gray"} label={n.connected ? t("pending") : t("offline")} />;
}

/** How the edge decision of a value reached each node. */
export function Propagation(props: { value: string }) {
  const q = useQuery({
    queryKey: ["propagation", props.value],
    queryFn: () => api.decisions.getPropagation({ value: props.value }),
    refetchInterval: 5_000,
  });
  if (q.isPending) return <LoadingBlock />;
  if (q.isError) return <ErrorAlert error={q.error} />;
  const p = q.data;
  const applied = p.nodes.filter((n) => n.applied).length;
  return (
    <Stack>
      {p.atEdge ? (
        <Group gap="sm">
          <Text size="sm">{t("Blocked at the edge")}</Text>
          <DirectionBadge direction={p.direction} />
          {p.edgeValue && p.edgeValue !== props.value && (
            <Text size="sm">
              {t("by the range")}{" "}
              <Link to={`/decisions?q=${encodeURIComponent(`value="${p.edgeValue}"`)}&status=all`}>
                <Text span ff="monospace" size="sm">
                  {p.edgeValue}
                </Text>
              </Link>
            </Text>
          )}
          <Text size="sm" c="dimmed">
            {t("version {v}", { v: toNumber(p.version) })} · <TimeLeft ts={p.until} />
          </Text>
          {p.nodes.length > 0 ? (
            <Badge color={applied === p.nodes.length ? "teal" : "orange"} variant="light">
              {t("{a} of {n} nodes applied", { a: applied, n: p.nodes.length })}
            </Badge>
          ) : (
            <Text size="sm" c="dimmed">
              {t("No node is registered yet.")}
            </Text>
          )}
        </Group>
      ) : (
        <Alert color="gray" variant="light">
          {t("No edge block for this value: no active IP/range ban, or the edge rules exclude it.")}
        </Alert>
      )}
      {p.atEdge && p.nodes.length > 0 && (
        <Table.ScrollContainer minWidth={520}>
          <Table fz="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("Node")}</Table.Th>
                <Table.Th>{t("State")}</Table.Th>
                <Table.Th>{t("Acknowledged version")}</Table.Th>
                <Table.Th>{t("Last ack")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {p.nodes.map((n) => (
                <Table.Tr key={n.nodeId}>
                  <Table.Td>
                    <Link to={`/nodes/${encodeURIComponent(n.nodeId)}`}>{n.nodeId}</Link>
                  </Table.Td>
                  <Table.Td>
                    <NodeState n={n} />
                  </Table.Td>
                  <Table.Td>{toNumber(n.ackedVersion)}</Table.Td>
                  <Table.Td>
                    <TimeAgo ts={n.ackedAt} />
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Stack>
  );
}
