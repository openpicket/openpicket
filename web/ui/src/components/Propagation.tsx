import { Alert, Badge, Group, Stack, Table, Text, Tooltip } from "@mantine/core";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../api/client";
import { ErrorAlert, LoadingBlock, StatusDot, TimeAgo, TimeLeft } from "./common";
import { DirectionBadge } from "./crowdsec";
import { refusalReason } from "./nodes";
import type { EdgeBlock, NodePropagation } from "../gen/openpicket/api/v1/crowdsec_pb";
import { toNumber } from "../lib/format";
import { t } from "../lib/i18n";

/** Whether the node has a decision for the value in force, and if not, why. */
function NodeState(props: { n: NodePropagation; several: boolean }): ReactNode {
  const n = props.n;
  let head: ReactNode;
  let detail: ReactNode = null;
  switch (n.state) {
    case "applied":
      head = <StatusDot color="teal" label={t("applied")} />;
      break;
    case "maybe":
      head = (
        <Tooltip label={t("The node is over its element limit and does not report every decision it leaves out; this one may be among them.")} withArrow multiline w={320}>
          <span>
            <StatusDot color="yellow" label={t("applied?")} />
          </span>
        </Tooltip>
      );
      break;
    case "refused":
      head = <StatusDot color="gray" label={t("not applied")} />;
      break;
    case "pending":
      head = <StatusDot color="orange" label={t("pending")} />;
      break;
    case "error":
      head = <StatusDot color="red" label={t("error")} />;
      detail = (
        <Text size="xs" c="red">
          {n.error}
        </Text>
      );
      break;
    default:
      head = <StatusDot color="gray" label={t("unknown")} />;
      detail = (
        <Text size="xs" c="dimmed">
          {n.connected ? t("No recent status report from the node.") : t("The node is offline.")}
        </Text>
      );
  }
  if (n.applied) {
    detail = (
      <Group gap={6} wrap="nowrap">
        <DirectionBadge direction={n.direction} />
        <TimeLeft ts={n.until} size="xs" />
      </Group>
    );
  }
  return (
    <Stack gap={2}>
      {head}
      {detail}
      {n.refusals.map((r) => (
        <Text key={r.value} size="xs" c="dimmed">
          {props.several ? `${r.value}: ` : ""}
          {refusalReason(r.reason)}
        </Text>
      ))}
    </Stack>
  );
}

/** The edge decisions blocking the value when a range takes part. */
function EdgeBlocks(props: { value: string; edge: EdgeBlock[] }) {
  if (props.edge.length === 1 && props.edge[0].value === props.value) return null;
  return (
    <Stack gap={2}>
      {props.edge.map((b) => (
        <Group key={b.value} gap="xs">
          <Link to={`/decisions?q=${encodeURIComponent(`value="${b.value}"`)}&status=all`}>
            <Text span ff="monospace" size="sm">
              {b.value}
            </Text>
          </Link>
          <DirectionBadge direction={b.direction} />
          <Text size="sm" c="dimmed">
            {t("version {v}", { v: toNumber(b.version) })} · <TimeLeft ts={b.until} />
          </Text>
        </Group>
      ))}
    </Stack>
  );
}

/** How the edge decisions blocking a value reached each node. */
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
        <>
          <Group gap="sm">
            <Text size="sm">{t("Blocked at the edge")}</Text>
            <DirectionBadge direction={p.direction} />
            <Text size="sm" c="dimmed">
              <TimeLeft ts={p.until} />
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
          <EdgeBlocks value={props.value} edge={p.edge} />
        </>
      ) : (
        <Alert color="gray" variant="light">
          {t("No edge block for this value: no active IP/range ban, or the edge rules exclude it.")}
        </Alert>
      )}
      {p.atEdge && p.nodes.length > 0 && (
        <Table.ScrollContainer minWidth={480}>
          <Table fz="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("Node")}</Table.Th>
                <Table.Th>{t("State")}</Table.Th>
                <Table.Th>{t("Status report")}</Table.Th>
                <Table.Th>{t("Acknowledged version")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {p.nodes.map((n) => (
                <Table.Tr key={n.nodeId}>
                  <Table.Td>
                    <Link to={`/nodes/${encodeURIComponent(n.nodeId)}`}>{n.nodeId}</Link>
                  </Table.Td>
                  <Table.Td>
                    <NodeState n={n} several={p.edge.length > 1} />
                  </Table.Td>
                  <Table.Td>
                    <TimeAgo ts={n.statusAt} />
                  </Table.Td>
                  <Table.Td>
                    {toNumber(n.ackedVersion)} · <TimeAgo ts={n.ackedAt} />
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
