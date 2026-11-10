import { useState } from "react";
import { ActionIcon, Alert, Badge, Button, Checkbox, Group, Modal, Paper, Select, Stack, Table, Text, TextInput, Tooltip } from "@mantine/core";
import { DateTimePicker } from "@mantine/dates";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconEdit, IconPlus, IconTrash } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { api } from "../api/client";
import { POLL_MS, useAccess } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import { EmptyState, ErrorAlert, LoadingBlock, PageHeader, TimeAgo, TimeLeft } from "../components/common";
import type { AllowlistEntry, AllowlistLAPIStatus } from "../gen/openpicket/api/v1/allowlist_pb";
import { formatDateTime, formatNumber, toNumber, tsDate } from "../lib/format";
import { t } from "../lib/i18n";

const DAY = 24 * 60 * 60 * 1000;
const EXPIRY_PRESETS: { value: string; label: string; days?: number }[] = [
  { value: "1d", label: "1 day", days: 1 },
  { value: "7d", label: "7 days", days: 7 },
  { value: "30d", label: "30 days", days: 30 },
  { value: "90d", label: "90 days", days: 90 },
  { value: "never", label: "Never" },
  { value: "custom", label: "Custom date" },
];

/** Whether the network is wider than the server accepts without confirmation (/8, /32 for IPv6). */
function isWide(network: string): boolean {
  const [addr, bits] = network.trim().split("/");
  if (bits === undefined || !/^\d+$/.test(bits)) return false;
  return Number(bits) < (addr.includes(":") ? 32 : 8);
}

function invalidate() {
  void queryClient.invalidateQueries({ queryKey: ["allowlist"] });
  void queryClient.invalidateQueries({ queryKey: ["propagation"] });
}

function EntryModal(props: { onClose: () => void; entry?: AllowlistEntry }) {
  const e = props.entry;
  const creating = !e;
  const [network, setNetwork] = useState(e?.network ?? "");
  const [description, setDescription] = useState(e?.description ?? "");
  const [expiry, setExpiry] = useState(e ? (e.expiresAt ? "custom" : "never") : "30d");
  const [date, setDate] = useState<Date | null>(tsDate(e?.expiresAt) ?? null);
  const [wide, setWide] = useState(false);
  const needsWide = isWide(network);
  const expiresAt = (): Date | undefined => {
    const p = EXPIRY_PRESETS.find((x) => x.value === expiry);
    if (p?.days) return new Date(Date.now() + p.days * DAY);
    if (expiry === "custom") return date ?? undefined;
    return undefined;
  };
  const save = useMutation({
    mutationFn: () => {
      const exp = expiresAt();
      return api.allowlist.putAllowlistEntry({
        entry: { network: network.trim(), description, expiresAt: exp ? timestampFromDate(exp) : undefined },
        wide,
      });
    },
    meta: { errorTitle: t("Could not save the entry") },
    onSuccess: (r) => {
      invalidate();
      notifications.show({ color: "teal", message: t("{network} allowlisted", { network: r.network }) });
      props.onClose();
    },
  });
  const badDate = expiry === "custom" && (!date || date.getTime() <= Date.now());
  return (
    <Modal opened onClose={props.onClose} title={creating ? t("New allowlist entry") : t("Edit {id}", { id: e.network })}>
      <Stack>
        <TextInput
          label={t("Network")}
          description={t("An address or a CIDR range")}
          placeholder="192.0.2.0/24"
          value={network}
          onChange={(ev) => setNetwork(ev.currentTarget.value)}
          disabled={!creating}
          required
          className="mono-input"
        />
        <TextInput label={t("Description")} value={description} onChange={(ev) => setDescription(ev.currentTarget.value)} maxLength={512} />
        <Select
          label={t("Expires")}
          data={EXPIRY_PRESETS.map((p) => ({ value: p.value, label: t(p.label) }))}
          value={expiry}
          onChange={(v) => setExpiry(v ?? "30d")}
          allowDeselect={false}
        />
        {expiry === "custom" && (
          <DateTimePicker
            label={t("Expiry")}
            value={date}
            onChange={(v) => setDate(v ? new Date(v) : null)}
            minDate={new Date()}
            withSeconds={false}
            error={badDate && date ? t("The expiry is in the past") : undefined}
          />
        )}
        {needsWide && (
          <Alert color="orange" variant="light">
            <Checkbox
              checked={wide}
              onChange={(ev) => setWide(ev.currentTarget.checked)}
              label={t("This network is wider than /8 (/32 for IPv6): decisions on a large part of the Internet will not be enforced.")}
            />
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {t("Cancel")}
          </Button>
          <Button disabled={!network.trim() || badDate || (needsWide && !wide)} loading={save.isPending} onClick={() => save.mutate()}>
            {t("Save")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function Expiry(props: { entry: AllowlistEntry }) {
  const e = props.entry;
  if (!e.expiresAt) return <Text size="sm">{t("Never")}</Text>;
  if (!e.active)
    return (
      <Group gap={6}>
        <Badge color="gray" variant="light">
          {t("expired")}
        </Badge>
        <Text size="xs" c="dimmed">
          {formatDateTime(tsDate(e.expiresAt))}
        </Text>
      </Group>
    );
  return (
    <Stack gap={0}>
      <TimeLeft ts={e.expiresAt} size="sm" />
      <Text size="xs" c="dimmed">
        {formatDateTime(tsDate(e.expiresAt))}
      </Text>
    </Stack>
  );
}

/** How the openpicket allowlist of each LAPI follows the entries. */
function LAPISync(props: { lapis: AllowlistLAPIStatus[] }) {
  if (props.lapis.length === 0) return null;
  return (
    <Paper withBorder p="sm" mb="md">
      <Stack gap="xs">
        <Text size="sm" c="dimmed">
          {t(
            "Each LAPI below keeps an \"openpicket\" allowlist equal to these entries: it drops alerts from these networks and deletes their decisions, for every bouncer. Removing an entry does not bring deleted decisions back.",
          )}
        </Text>
        {props.lapis.map((l) => (
          <Group key={l.instance} gap="sm">
            <Text size="sm" fw={600} ff="monospace">
              {l.instance}
            </Text>
            {!l.enabled ? (
              <Tooltip label={t("No allowlist sync URL for this LAPI: only the edge honours the allowlist.")} withArrow multiline w={300}>
                <Badge color="gray" variant="light">
                  {t("not synced")}
                </Badge>
              </Tooltip>
            ) : l.error ? (
              <>
                <Badge color="red" variant="light">
                  {t("sync failed")}
                </Badge>
                <TimeAgo ts={l.attemptAt} size="xs" />
                <Text size="xs" c="red">
                  {l.error}
                </Text>
              </>
            ) : l.syncedAt ? (
              <>
                <Badge color="teal" variant="light">
                  {t("in sync")}
                </Badge>
                <Text size="xs" c="dimmed">
                  {t("{n} items", { n: l.items })} · <TimeAgo ts={l.syncedAt} size="xs" />
                </Text>
              </>
            ) : (
              <Badge color="gray" variant="light">
                {t("pending")}
              </Badge>
            )}
          </Group>
        ))}
      </Stack>
    </Paper>
  );
}

export default function AllowlistPage() {
  const access = useAccess();
  const q = useQuery({ queryKey: ["allowlist"], queryFn: () => api.allowlist.listAllowlist({}), refetchInterval: POLL_MS });
  const [editing, setEditing] = useState<AllowlistEntry | null>(null);
  const [creating, setCreating] = useState(false);
  const remove = useMutation({
    mutationFn: (network: string) => api.allowlist.deleteAllowlistEntry({ network }),
    meta: { errorTitle: t("Could not delete the entry") },
    onSuccess: (_r, network) => {
      invalidate();
      notifications.show({ color: "teal", message: t("{network} removed from the allowlist", { network }) });
    },
  });
  return (
    <>
      <PageHeader
        title={t("Allowlist")}
        description={t(
          "Networks CrowdSec decisions never block at the edge, whatever made them (scenarios, cscli, MISP, manual). A decision overlapping an entry is left out whole, and new manual and MISP decisions on these networks are refused. Port policies still apply; each node's local allowlist is configured on the node.",
        )}
        right={
          access.canAdmin && (
            <Button leftSection={<IconPlus size={16} />} onClick={() => setCreating(true)}>
              {t("New entry")}
            </Button>
          )
        }
      />
      {q.data && <LAPISync lapis={q.data.lapis} />}
      {q.isPending ? (
        <LoadingBlock />
      ) : q.isError ? (
        <ErrorAlert error={q.error} onRetry={() => q.refetch()} />
      ) : q.data.entries.length === 0 ? (
        <EmptyState title={t("The allowlist is empty")} description={t("Add the management networks and the addresses of partners you never want blocked.")} />
      ) : (
        <Table.ScrollContainer minWidth={800}>
          <Table highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("Network")}</Table.Th>
                <Table.Th>{t("Description")}</Table.Th>
                <Table.Th>{t("Expires")}</Table.Th>
                <Table.Th>{t("Decisions kept off the edge")}</Table.Th>
                <Table.Th>{t("Updated")}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {q.data.entries.map((e) => (
                <Table.Tr key={e.network} opacity={e.active ? 1 : 0.6}>
                  <Table.Td>
                    <Text size="sm" fw={600} ff="monospace">
                      {e.network}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{e.description || "-"}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Expiry entry={e} />
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c={toNumber(e.excluded) > 0 ? undefined : "dimmed"}>
                      {formatNumber(e.excluded)}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <TimeAgo ts={e.updatedAt} size="xs" />
                    <Text size="xs" c="dimmed">
                      {e.updatedBy}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {access.canAdmin && (
                      <Group gap={2} justify="flex-end" wrap="nowrap">
                        <ActionIcon variant="subtle" onClick={() => setEditing(e)} aria-label={t("Edit")}>
                          <IconEdit size={16} />
                        </ActionIcon>
                        <ActionIcon
                          variant="subtle"
                          color="red"
                          disabled={remove.isPending}
                          aria-label={t("Delete")}
                          onClick={() =>
                            modals.openConfirmModal({
                              title: t("Remove {network} from the allowlist?", { network: e.network }),
                              children: (
                                <Text size="sm">{t("Active decisions on this network will be enforced at the edge again.")}</Text>
                              ),
                              labels: { confirm: t("Delete"), cancel: t("Cancel") },
                              confirmProps: { color: "red" },
                              onConfirm: () => remove.mutate(e.network),
                            })
                          }
                        >
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
      {creating && <EntryModal onClose={() => setCreating(false)} />}
      {editing && <EntryModal entry={editing} onClose={() => setEditing(null)} />}
    </>
  );
}
