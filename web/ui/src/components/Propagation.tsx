import { Alert, Badge, Group, Stack, Table, Text, Tooltip } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../api/client";
import { ErrorAlert, LoadingBlock, StatusDot, TimeAgo, TimeLeft } from "./common";
import { DirectionBadge } from "./crowdsec";
import { toNumber } from "../lib/format";
import { t } from "../lib/i18n";

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
                    {n.error ? (
                      <Tooltip label={n.error} withArrow multiline w={320}>
                        <span>
                          <StatusDot color="red" label={t("error")} />
                        </span>
                      </Tooltip>
                    ) : n.applied ? (
                      <StatusDot color="teal" label={t("applied")} />
                    ) : (
                      <StatusDot color={n.connected ? "orange" : "gray"} label={n.connected ? t("pending") : t("offline")} />
                    )}
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
