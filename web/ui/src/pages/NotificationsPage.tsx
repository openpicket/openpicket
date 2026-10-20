import { useState } from "react";
import {
  ActionIcon,
  Badge,
  Button,
  Group,
  Paper,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  Tooltip,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconArrowRight, IconChecks, IconCircleCheck, IconEdit, IconPlus, IconTrash } from "@tabler/icons-react";
import { useInfiniteQuery, useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { api } from "../api/client";
import { useAccess } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import { EmptyState, ErrorAlert, LoadingBlock, PageHeader, SeverityBadge, TimeAgo } from "../components/common";
import { DestinationModal, RuleModal, destinationTypeLabel, ruleTypeLabel } from "../components/notify";
import type { Destination, Notification, Rule } from "../gen/openpicket/api/v1/notifications_pb";
import { formatNumber } from "../lib/format";
import { t, useLanguage } from "../lib/i18n";
import { useUrlState } from "../lib/urlState";

const PAGE = 50;

const deliveryColor: Record<string, string> = { sent: "teal", pending: "yellow", failed: "red" };

function invalidateInbox() {
  void queryClient.invalidateQueries({ queryKey: ["notifications"] });
}

function NotificationItem(props: { n: Notification; destinations: Map<string, string> }) {
  const n = props.n;
  const navigate = useNavigate();
  const mark = useMutation({
    mutationFn: () => api.notifications.markNotificationsRead({ ids: [n.id] }),
    meta: { errorTitle: t("Could not mark the notification read") },
    onSuccess: invalidateInbox,
  });
  const open = () => {
    if (!n.read) mark.mutate();
    if (n.link.startsWith("/")) navigate(n.link);
    else window.open(n.link, "_blank", "noopener");
  };
  return (
    <Paper
      withBorder
      p="sm"
      radius="md"
      style={n.read ? undefined : { borderLeft: "3px solid var(--mantine-primary-color-filled)", background: "var(--mantine-primary-color-light)" }}
    >
      <Group justify="space-between" align="flex-start" wrap="nowrap" gap="sm">
        <Stack gap={4} style={{ minWidth: 0, flex: 1 }}>
          <Group gap="xs" wrap="wrap">
            <SeverityBadge severity={n.severity} />
            <Text fw={n.read ? 500 : 700} size="sm">
              {n.title}
            </Text>
          </Group>
          <Text size="sm" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
            {n.body}
          </Text>
          <Group gap="xs" wrap="wrap">
            <Text size="xs" c="dimmed">
              <TimeAgo ts={n.time} size="xs" /> · {n.ruleName}
            </Text>
            {n.deliveries.map((d) => (
              <Tooltip
                key={d.destination}
                label={d.error ? `${d.error} (${t("{n} attempts", { n: d.attempts })})` : t("{n} attempts", { n: d.attempts })}
                withArrow
                multiline
                maw={360}
              >
                <Badge size="xs" variant="light" color={deliveryColor[d.status] ?? "gray"}>
                  {props.destinations.get(d.destination) ?? d.destination}: {t(d.status)}
                </Badge>
              </Tooltip>
            ))}
          </Group>
        </Stack>
        <Group gap={4} wrap="nowrap">
          {n.link && (
            <Tooltip label={t("Open")} withArrow>
              <ActionIcon variant="subtle" onClick={open}>
                <IconArrowRight size={16} />
              </ActionIcon>
            </Tooltip>
          )}
          {!n.read && (
            <Tooltip label={t("Mark read")} withArrow>
              <ActionIcon variant="subtle" color="gray" onClick={() => mark.mutate()} loading={mark.isPending}>
                <IconCircleCheck size={16} />
              </ActionIcon>
            </Tooltip>
          )}
        </Group>
      </Group>
    </Paper>
  );
}

function Inbox(props: { destinations: Map<string, string> }) {
  const [unreadOnly, setUnreadOnly] = useState(false);
  const q = useInfiniteQuery({
    queryKey: ["notifications", "inbox", unreadOnly],
    queryFn: ({ pageParam }) => api.notifications.listNotifications({ limit: PAGE, beforeId: pageParam, unreadOnly }),
    initialPageParam: 0n,
    getNextPageParam: (last) =>
      last.notifications.length < PAGE ? undefined : last.notifications[last.notifications.length - 1].id,
    refetchInterval: 30_000,
  });
  const markAll = useMutation({
    mutationFn: () => api.notifications.markNotificationsRead({ all: true }),
    meta: { errorTitle: t("Could not mark the notifications read") },
    onSuccess: () => {
      invalidateInbox();
      notifications.show({ color: "teal", message: t("All notifications marked read") });
    },
  });
  const items = q.data?.pages.flatMap((p) => p.notifications) ?? [];
  const unread = q.data?.pages[0]?.unread ?? 0n;
  return (
    <Stack>
      <Group justify="space-between">
        <Group gap="sm">
          <Text size="sm" c="dimmed">
            {t("{n} unread", { n: formatNumber(unread) })}
          </Text>
          <Switch label={t("Unread only")} checked={unreadOnly} onChange={(e) => setUnreadOnly(e.currentTarget.checked)} />
        </Group>
        <Button variant="light" leftSection={<IconChecks size={16} />} onClick={() => markAll.mutate()} loading={markAll.isPending} disabled={unread === 0n}>
          {t("Mark all read")}
        </Button>
      </Group>
      {q.isPending && <LoadingBlock />}
      {q.isError && <ErrorAlert error={q.error} onRetry={() => q.refetch()} />}
      {!q.isPending && items.length === 0 && (
        <EmptyState title={t("No notifications")} description={t("Notifications appear here when a rule fires. Create rules in the Rules tab.")} />
      )}
      {items.map((n) => (
        <NotificationItem key={String(n.id)} n={n} destinations={props.destinations} />
      ))}
      {q.hasNextPage && (
        <Button variant="default" onClick={() => q.fetchNextPage()} loading={q.isFetchingNextPage}>
          {t("Load more")}
        </Button>
      )}
    </Stack>
  );
}

function RulesTab(props: { destinations: Destination[]; names: Map<string, string> }) {
  const access = useAccess();
  const [edit, setEdit] = useState<{ open: boolean; rule?: Rule }>({ open: false });
  const q = useQuery({ queryKey: ["notifyRules"], queryFn: async () => (await api.notifications.listRules({})).rules });
  const remove = useMutation({
    mutationFn: (id: string) => api.notifications.deleteRule({ id }),
    meta: { errorTitle: t("Could not delete the rule") },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifyRules"] });
      notifications.show({ color: "teal", message: t("Rule deleted") });
    },
  });
  const confirmDelete = (r: Rule) =>
    modals.openConfirmModal({
      title: t("Delete rule"),
      children: <Text size="sm">{t("Delete the rule \"{name}\"? Its past notifications stay in the inbox.", { name: r.name })}</Text>,
      labels: { confirm: t("Delete"), cancel: t("Cancel") },
      confirmProps: { color: "red" },
      onConfirm: () => remove.mutate(r.id),
    });
  const rules = q.data ?? [];
  return (
    <Stack>
      {access.canOperate && (
        <Group justify="flex-end">
          <Button leftSection={<IconPlus size={16} />} onClick={() => setEdit({ open: true })}>
            {t("New rule")}
          </Button>
        </Group>
      )}
      {q.isPending && <LoadingBlock />}
      {q.isError && <ErrorAlert error={q.error} onRetry={() => q.refetch()} />}
      {!q.isPending && rules.length === 0 && <EmptyState title={t("No rules")} description={t("Rules decide which events become notifications.")} />}
      {rules.length > 0 && (
        <Table.ScrollContainer minWidth={760}>
          <Table highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("Name")}</Table.Th>
                <Table.Th>{t("Type")}</Table.Th>
                <Table.Th>{t("Severity")}</Table.Th>
                <Table.Th>{t("Enabled")}</Table.Th>
                <Table.Th>{t("Destinations")}</Table.Th>
                <Table.Th>{t("Last fired")}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rules.map((r) => (
                <Table.Tr key={r.id} className="clickable-row" onClick={() => setEdit({ open: true, rule: r })}>
                  <Table.Td>
                    <Text size="sm" fw={500}>
                      {r.name}
                    </Text>
                    {r.query && (
                      <Text size="xs" c="dimmed" ff="monospace" truncate maw={280}>
                        {r.query}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>{ruleTypeLabel(r.type)}</Table.Td>
                  <Table.Td>
                    <SeverityBadge severity={r.severity} />
                  </Table.Td>
                  <Table.Td>
                    <Badge size="sm" variant="light" color={r.enabled ? "teal" : "gray"}>
                      {r.enabled ? t("on") : t("off")}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      {r.destinations.length === 0 && (
                        <Text size="xs" c="dimmed">
                          {t("inbox only")}
                        </Text>
                      )}
                      {r.destinations.map((d) => (
                        <Badge key={d} size="xs" variant="outline">
                          {props.names.get(d) ?? d}
                        </Badge>
                      ))}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <TimeAgo ts={r.lastFiredAt} />
                  </Table.Td>
                  <Table.Td onClick={(e) => e.stopPropagation()}>
                    {access.canOperate && (
                      <Group gap={4} wrap="nowrap">
                        <ActionIcon variant="subtle" onClick={() => setEdit({ open: true, rule: r })} aria-label={t("Edit")}>
                          <IconEdit size={16} />
                        </ActionIcon>
                        <ActionIcon variant="subtle" color="red" onClick={() => confirmDelete(r)} aria-label={t("Delete")}>
                          <IconTrash size={16} />
                        </ActionIcon>
                      </Group>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      <RuleModal
        opened={edit.open}
        rule={edit.rule}
        onClose={() => setEdit({ open: false })}
        destinations={props.destinations}
        readOnly={!access.canOperate}
      />
    </Stack>
  );
}

function DestinationsTab(props: { query: ReturnType<typeof useDestinations> }) {
  const access = useAccess();
  const [edit, setEdit] = useState<{ open: boolean; destination?: Destination }>({ open: false });
  const q = props.query;
  const remove = useMutation({
    mutationFn: (id: string) => api.notifications.deleteDestination({ id }),
    meta: { errorTitle: t("Could not delete the destination") },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifyDestinations"] });
      notifications.show({ color: "teal", message: t("Destination deleted") });
    },
  });
  const confirmDelete = (d: Destination) =>
    modals.openConfirmModal({
      title: t("Delete destination"),
      children: <Text size="sm">{t("Delete the destination \"{name}\"? Rules using it keep notifying the inbox.", { name: d.name })}</Text>,
      labels: { confirm: t("Delete"), cancel: t("Cancel") },
      confirmProps: { color: "red" },
      onConfirm: () => remove.mutate(d.id),
    });
  const list = q.data ?? [];
  return (
    <Stack>
      {access.canAdmin && (
        <Group justify="flex-end">
          <Button leftSection={<IconPlus size={16} />} onClick={() => setEdit({ open: true })}>
            {t("New destination")}
          </Button>
        </Group>
      )}
      {q.isPending && <LoadingBlock />}
      {q.isError && <ErrorAlert error={q.error} onRetry={() => q.refetch()} />}
      {!q.isPending && list.length === 0 && (
        <EmptyState title={t("No destinations")} description={t("Send notifications to webhooks, Slack, Discord, ntfy, Gotify, email or MQTT.")} />
      )}
      {list.length > 0 && (
        <Table.ScrollContainer minWidth={600}>
          <Table highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("Name")}</Table.Th>
                <Table.Th>{t("Type")}</Table.Th>
                <Table.Th>{t("Severities")}</Table.Th>
                <Table.Th>{t("Enabled")}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {list.map((d) => (
                <Table.Tr key={d.id} className="clickable-row" onClick={() => setEdit({ open: true, destination: d })}>
                  <Table.Td>
                    <Text size="sm" fw={500}>
                      {d.name}
                    </Text>
                    <Text size="xs" c="dimmed" ff="monospace">
                      {d.id}
                    </Text>
                  </Table.Td>
                  <Table.Td>{destinationTypeLabel(d.type)}</Table.Td>
                  <Table.Td>
                    {d.minSeverity.length === 0 ? (
                      <Text size="xs" c="dimmed">
                        {t("all")}
                      </Text>
                    ) : (
                      <Group gap={4}>
                        {d.minSeverity.map((s) => (
                          <SeverityBadge key={s} severity={s} />
                        ))}
                      </Group>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Badge size="sm" variant="light" color={d.enabled ? "teal" : "gray"}>
                      {d.enabled ? t("on") : t("off")}
                    </Badge>
                  </Table.Td>
                  <Table.Td onClick={(e) => e.stopPropagation()}>
                    {access.canAdmin && (
                      <Group gap={4} wrap="nowrap">
                        <ActionIcon variant="subtle" onClick={() => setEdit({ open: true, destination: d })} aria-label={t("Edit")}>
                          <IconEdit size={16} />
                        </ActionIcon>
                        <ActionIcon variant="subtle" color="red" onClick={() => confirmDelete(d)} aria-label={t("Delete")}>
                          <IconTrash size={16} />
                        </ActionIcon>
                      </Group>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      <DestinationModal opened={edit.open} destination={edit.destination} onClose={() => setEdit({ open: false })} canEdit={access.canAdmin} />
    </Stack>
  );
}

function useDestinations(enabled: boolean) {
  return useQuery({
    queryKey: ["notifyDestinations"],
    queryFn: async () => (await api.notifications.listDestinations({})).destinations,
    enabled,
  });
}

export default function NotificationsPage() {
  useLanguage();
  const access = useAccess();
  const [tab, setTab] = useUrlState("tab", "inbox");
  const dests = useDestinations(access.isOperator);
  const names = new Map((dests.data ?? []).map((d) => [d.id, d.name]));
  return (
    <>
      <PageHeader title={t("Notifications")} description={t("Notification center, rules and destinations.")} />
      <Tabs value={tab} onChange={(v) => setTab(v ?? "inbox")} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="inbox">{t("Inbox")}</Tabs.Tab>
          <Tabs.Tab value="rules">{t("Rules")}</Tabs.Tab>
          {access.isOperator && <Tabs.Tab value="destinations">{t("Destinations")}</Tabs.Tab>}
        </Tabs.List>
        <Tabs.Panel value="inbox">
          <Inbox destinations={names} />
        </Tabs.Panel>
        <Tabs.Panel value="rules">
          <RulesTab destinations={dests.data ?? []} names={names} />
        </Tabs.Panel>
        {access.isOperator && (
          <Tabs.Panel value="destinations">
            <DestinationsTab query={dests} />
          </Tabs.Panel>
        )}
      </Tabs>
    </>
  );
}
