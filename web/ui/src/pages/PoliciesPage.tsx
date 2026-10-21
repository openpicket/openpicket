import { Fragment, useState } from "react";
import { ActionIcon, Badge, Button, Code, Group, Paper, Select, Stack, Table, Tabs, Text, Tooltip } from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconArrowDown, IconArrowUp, IconChevronDown, IconChevronRight, IconEdit, IconEye, IconPlus, IconTrash } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAccess, useNodes } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import { EmptyState, ErrorAlert, LoadingBlock, PageHeader, TimeAgo } from "../components/common";
import {
  AddressListModal,
  BundlePreview,
  DeleteListButton,
  PolicyEditorModal,
  actionColorOf,
  formatPorts,
  scopeSummary,
} from "../components/policyEditor";
import type { AddressList, Policy } from "../gen/openpicket/api/v1/policies_pb";
import { formatDateTime, formatNumber, tsDate } from "../lib/format";
import { t } from "../lib/i18n";

function usePolicies() {
  return useQuery({ queryKey: ["policies"], queryFn: () => api.policies.listPolicies({}) });
}

function invalidatePolicies() {
  void queryClient.invalidateQueries({ queryKey: ["policies"] });
  void queryClient.invalidateQueries({ queryKey: ["policyHistory"] });
  void queryClient.invalidateQueries({ queryKey: ["addressLists"] });
}

function PreviewForNode() {
  const nodes = useNodes(false);
  const [node, setNode] = useState<string | null>(null);
  const preview = useQuery({
    queryKey: ["bundlePreview", node],
    enabled: !!node,
    queryFn: () => api.policies.previewBundle({ nodeId: node! }),
  });
  return (
    <Paper withBorder p="md" radius="md">
      <Group mb="sm" align="flex-end">
        <Select
          label={t("Preview for node")}
          placeholder={t("Select a node")}
          data={(nodes.data ?? []).map((n) => n.id)}
          value={node}
          onChange={setNode}
          searchable
          w={260}
          leftSection={<IconEye size={16} />}
        />
        <Text size="xs" c="dimmed" maw={480}>
          {t("Compiles the bundle this node would receive with its current labels and the uploaded GeoIP data.")}
        </Text>
      </Group>
      {node && (preview.isPending ? <LoadingBlock /> : preview.isError ? <ErrorAlert error={preview.error} /> : <BundlePreview preview={preview.data} />)}
    </Paper>
  );
}

function PoliciesTab() {
  const policies = usePolicies();
  const access = useAccess();
  const [editing, setEditing] = useState<Policy | null>(null);
  const [creating, setCreating] = useState(false);
  const reorder = useMutation({
    mutationFn: (ids: string[]) => api.policies.reorderPolicies({ ids }),
    meta: { errorTitle: t("Could not reorder the policies") },
    onSuccess: () => invalidatePolicies(),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.policies.deletePolicy({ id }),
    meta: { errorTitle: t("Could not delete the policy") },
    onSuccess: (_r, id) => {
      invalidatePolicies();
      notifications.show({ color: "teal", message: t("Policy {id} deleted", { id }) });
    },
  });
  if (policies.isPending) return <LoadingBlock />;
  if (policies.isError) return <ErrorAlert error={policies.error} onRetry={() => policies.refetch()} />;
  const list = policies.data.policies;
  const moveTo = (i: number, d: number) => {
    const ids = list.map((p) => p.id);
    const j = i + d;
    [ids[i], ids[j]] = [ids[j], ids[i]];
    reorder.mutate(ids);
  };
  const confirmDelete = (p: Policy) =>
    modals.openConfirmModal({
      title: t("Delete policy {id}?", { id: p.id }),
      children: <Text size="sm">{t("Nodes remove its rules with the next bundle.")}</Text>,
      labels: { confirm: t("Delete"), cancel: t("Cancel") },
      confirmProps: { color: "red" },
      onConfirm: () => remove.mutate(p.id),
    });
  return (
    <Stack>
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          {t("Generation {v}. Policies are evaluated in order.", { v: formatNumber(policies.data.version) })}
        </Text>
        {access.canOperate && (
          <Button leftSection={<IconPlus size={16} />} onClick={() => setCreating(true)}>
            {t("New policy")}
          </Button>
        )}
      </Group>
      {list.length === 0 ? (
        <EmptyState title={t("No port policies")} />
      ) : (
        <Table.ScrollContainer minWidth={1000}>
          <Table highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th w={40}>#</Table.Th>
                <Table.Th>{t("Policy")}</Table.Th>
                <Table.Th>{t("Mode")}</Table.Th>
                <Table.Th>{t("Ports")}</Table.Th>
                <Table.Th>{t("Rules")}</Table.Th>
                <Table.Th>{t("Default")}</Table.Th>
                <Table.Th>{t("Scope")}</Table.Th>
                <Table.Th>{t("Updated")}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {list.map((p, i) => (
                <Table.Tr key={p.id} style={{ opacity: p.enabled ? 1 : 0.55 }}>
                  <Table.Td>{i + 1}</Table.Td>
                  <Table.Td>
                    <Group gap="xs">
                      <Text fw={600} size="sm" ff="monospace">
                        {p.id}
                      </Text>
                      {!p.enabled && (
                        <Badge size="xs" color="gray">
                          {t("disabled")}
                        </Badge>
                      )}
                      {p.logDrops && (
                        <Badge size="xs" variant="outline">
                          {t("logs drops")}
                        </Badge>
                      )}
                      {p.compileError && (
                        <Tooltip label={p.compileError} multiline w={360} withArrow>
                          <Badge size="xs" color={p.stale ? "orange" : "red"} variant="light">
                            {p.stale ? t("last good version deployed") : t("not deployed")}
                          </Badge>
                        </Tooltip>
                      )}
                    </Group>
                    {p.description && (
                      <Text size="xs" c="dimmed">
                        {p.description}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Badge color={p.mode === "enforce" ? "blue" : "gray"} variant="light">
                      {t(p.mode)}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {formatPorts(p.ports)}/{p.proto}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      {p.rules.map((r, j) => (
                        <Tooltip
                          key={j}
                          withArrow
                          multiline
                          maw={360}
                          label={[
                            r.source?.countries.length ? `${t("Countries")}: ${r.source.countries.join(", ")}` : "",
                            r.source?.asns.length ? `AS: ${r.source.asns.join(", ")}` : "",
                            r.source?.lists.length ? `${t("Lists")}: ${r.source.lists.join(", ")}` : "",
                            r.source?.cidrs.length ? `CIDR: ${r.source.cidrs.join(", ")}` : "",
                          ]
                            .filter(Boolean)
                            .join("\n")}
                        >
                          <Badge size="sm" color={actionColorOf(r.action)} variant="light">
                            {t(r.action)}{" "}
                            {[...(r.source?.countries ?? []), ...(r.source?.lists ?? [])].slice(0, 3).join(",")}
                            {(r.source?.asns.length ?? 0) > 0 ? ` AS${r.source!.asns[0]}` : ""}
                          </Badge>
                        </Tooltip>
                      ))}
                      {p.rules.length === 0 && (
                        <Text size="xs" c="dimmed">
                          -
                        </Text>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Badge color={actionColorOf(p.defaultAction)} variant="outline">
                      {t(p.defaultAction)}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" maw={220}>
                      {scopeSummary(p)}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <TimeAgo ts={p.updatedAt} size="xs" />
                    <Text size="xs" c="dimmed">
                      {p.updatedBy}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {access.canOperate && (
                      <Group gap={2} wrap="nowrap" justify="flex-end">
                        <ActionIcon variant="subtle" disabled={i === 0 || reorder.isPending} onClick={() => moveTo(i, -1)} aria-label={t("Move up")}>
                          <IconArrowUp size={16} />
                        </ActionIcon>
                        <ActionIcon
                          variant="subtle"
                          disabled={i === list.length - 1 || reorder.isPending}
                          onClick={() => moveTo(i, 1)}
                          aria-label={t("Move down")}
                        >
                          <IconArrowDown size={16} />
                        </ActionIcon>
                        <ActionIcon variant="subtle" onClick={() => setEditing(p)} aria-label={t("Edit")}>
                          <IconEdit size={16} />
                        </ActionIcon>
                        <ActionIcon variant="subtle" color="red" onClick={() => confirmDelete(p)} aria-label={t("Delete")}>
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
      <PreviewForNode />
      {creating && <PolicyEditorModal opened onClose={() => setCreating(false)} />}
      {editing && <PolicyEditorModal opened policy={editing} onClose={() => setEditing(null)} />}
    </Stack>
  );
}

function ListsTab() {
  const access = useAccess();
  const lists = useQuery({ queryKey: ["addressLists"], queryFn: async () => (await api.policies.listAddressLists({})).lists });
  const [editing, setEditing] = useState<AddressList | null>(null);
  const [creating, setCreating] = useState(false);
  const remove = useMutation({
    mutationFn: (name: string) => api.policies.deleteAddressList({ name }),
    meta: { errorTitle: t("Could not delete the list") },
    onSuccess: (_r, name) => {
      invalidatePolicies();
      notifications.show({ color: "teal", message: t("List {name} deleted", { name }) });
    },
  });
  if (lists.isPending) return <LoadingBlock />;
  if (lists.isError) return <ErrorAlert error={lists.error} onRetry={() => lists.refetch()} />;
  return (
    <Stack>
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          {t("Named sets of CIDRs and AS numbers that policy rules can reference.")}
        </Text>
        {access.canOperate && (
          <Button leftSection={<IconPlus size={16} />} onClick={() => setCreating(true)}>
            {t("New list")}
          </Button>
        )}
      </Group>
      {lists.data.length === 0 ? (
        <EmptyState title={t("No address lists")} />
      ) : (
        <Table.ScrollContainer minWidth={800}>
          <Table highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("Name")}</Table.Th>
                <Table.Th>{t("Description")}</Table.Th>
                <Table.Th>{t("CIDRs")}</Table.Th>
                <Table.Th>{t("AS numbers")}</Table.Th>
                <Table.Th>{t("Used by")}</Table.Th>
                <Table.Th>{t("Updated")}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {lists.data.map((l) => (
                <Table.Tr key={l.name}>
                  <Table.Td>
                    <Text size="sm" fw={600} ff="monospace">
                      {l.name}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{l.description || "-"}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Tooltip label={l.cidrs.slice(0, 20).join("\n") + (l.cidrs.length > 20 ? "\n…" : "")} disabled={l.cidrs.length === 0} multiline>
                      <Text size="sm">{formatNumber(l.cidrs.length)}</Text>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{l.asns.length ? l.asns.map((a) => `AS${a}`).join(", ") : "-"}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      {l.usedBy.length ? (
                        l.usedBy.map((u) => (
                          <Badge key={u} size="sm" variant="outline" tt="none">
                            {u}
                          </Badge>
                        ))
                      ) : (
                        <Text size="xs" c="dimmed">
                          -
                        </Text>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <TimeAgo ts={l.updatedAt} size="xs" />
                    <Text size="xs" c="dimmed">
                      {l.updatedBy}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {access.canOperate && (
                      <Group gap={2} justify="flex-end" wrap="nowrap">
                        <ActionIcon variant="subtle" onClick={() => setEditing(l)} aria-label={t("Edit")}>
                          <IconEdit size={16} />
                        </ActionIcon>
                        <DeleteListButton
                          list={l}
                          disabled={remove.isPending}
                          onDelete={() =>
                            modals.openConfirmModal({
                              title: t("Delete list {name}?", { name: l.name }),
                              labels: { confirm: t("Delete"), cancel: t("Cancel") },
                              confirmProps: { color: "red" },
                              onConfirm: () => remove.mutate(l.name),
                            })
                          }
                        />
                      </Group>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {creating && <AddressListModal opened onClose={() => setCreating(false)} />}
      {editing && <AddressListModal opened list={editing} onClose={() => setEditing(null)} />}
    </Stack>
  );
}

function prettyJson(s: string): string {
  if (!s) return "";
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

function HistoryTab() {
  const history = useQuery({ queryKey: ["policyHistory"], queryFn: async () => (await api.policies.policyHistory({ limit: 200 })).changes });
  const [open, setOpen] = useState<Set<number>>(new Set());
  if (history.isPending) return <LoadingBlock />;
  if (history.isError) return <ErrorAlert error={history.error} onRetry={() => history.refetch()} />;
  if (history.data.length === 0) return <EmptyState title={t("No changes yet")} />;
  const toggle = (i: number) => {
    const next = new Set(open);
    if (next.has(i)) next.delete(i);
    else next.add(i);
    setOpen(next);
  };
  const actionColor: Record<string, string> = { put: "blue", delete: "red", reorder: "grape" };
  return (
    <Table.ScrollContainer minWidth={700}>
      <Table verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr>
            <Table.Th w={30} />
            <Table.Th>{t("Time")}</Table.Th>
            <Table.Th>{t("Policy or list")}</Table.Th>
            <Table.Th>{t("Action")}</Table.Th>
            <Table.Th>{t("Version")}</Table.Th>
            <Table.Th>{t("By")}</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {history.data.map((c, i) => (
            <Fragment key={i}>
              <Table.Tr className={c.specJson ? "clickable-row" : undefined} onClick={() => c.specJson && toggle(i)}>
                <Table.Td>{c.specJson && (open.has(i) ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />)}</Table.Td>
                <Table.Td>
                  <Text size="sm">{formatDateTime(tsDate(c.changedAt))}</Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm" ff="monospace">
                    {c.policyId === "*" ? t("(all policies)") : c.policyId}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Badge size="sm" color={actionColor[c.action] ?? "gray"} variant="light">
                    {t(c.action)}
                  </Badge>
                </Table.Td>
                <Table.Td>{formatNumber(c.version)}</Table.Td>
                <Table.Td>
                  <Text size="sm">{c.changedBy}</Text>
                </Table.Td>
              </Table.Tr>
              {open.has(i) && (
                <Table.Tr>
                  <Table.Td colSpan={6}>
                    <Code block>{prettyJson(c.specJson)}</Code>
                  </Table.Td>
                </Table.Tr>
              )}
            </Fragment>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

export default function PoliciesPage() {
  return (
    <>
      <PageHeader
        title={t("Port policies")}
        description={t(
          "Policies allow or block sources by country, AS, list or CIDR on public ports, matched before DNAT (so 443 is the public port even when it is forwarded to 8443). CrowdSec bans are applied first: a banned source is dropped even if a policy accepts it.",
        )}
      />
      <Tabs defaultValue="policies" keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="policies">{t("Policies")}</Tabs.Tab>
          <Tabs.Tab value="lists">{t("Address lists")}</Tabs.Tab>
          <Tabs.Tab value="history">{t("History")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="policies">
          <PoliciesTab />
        </Tabs.Panel>
        <Tabs.Panel value="lists">
          <ListsTab />
        </Tabs.Panel>
        <Tabs.Panel value="history">
          <HistoryTab />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
