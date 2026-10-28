import { useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  Paper,
  SegmentedControl,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconInfoCircle, IconPencil, IconPlus, IconTrash } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAccess } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import type { SyslogDevice, SyslogSender } from "../gen/openpicket/api/v1/syslog_pb";
import { EmptyState, ErrorAlert, LoadingBlock, PageHeader, StatusDot, TimeAgo } from "../components/common";
import { LabelBadges, LabelsEditor, labelsToRows, rowsToLabels, type LabelRow } from "../components/nodes";
import { formatNumber, toNumber } from "../lib/format";
import { t } from "../lib/i18n";
import { useUrlState } from "../lib/urlState";

/** The device id the gateways give an unregistered sender (accept mode). */
function tempID(addr: string): string {
  return addr.includes(":") ? "ip6-" + addr.replaceAll(":", "-") : addr;
}

type DeviceDraft = { create: boolean; id: string; description: string; sources: string; enabled: boolean; labels: LabelRow[]; programs: LabelRow[] };

function draftOf(d?: SyslogDevice, sender?: string): DeviceDraft {
  if (d) {
    return {
      create: false,
      id: d.id,
      description: d.description,
      sources: d.sources.join("\n"),
      enabled: d.enabled,
      labels: labelsToRows(d.labels),
      programs: labelsToRows(d.programs),
    };
  }
  return { create: true, id: sender ? tempID(sender) : "", description: "", sources: sender ?? "", enabled: true, labels: [], programs: [] };
}

function DeviceModal(props: { draft: DeviceDraft | null; onClose: () => void }) {
  const [d, setD] = useState<DeviceDraft | null>(props.draft);
  const [prev, setPrev] = useState(props.draft);
  if (prev !== props.draft) {
    setPrev(props.draft);
    setD(props.draft);
  }
  const save = useMutation({
    mutationFn: (v: DeviceDraft) =>
      api.syslog.putSyslogDevice({
        create: v.create,
        device: {
          id: v.id.trim(),
          description: v.description.trim(),
          sources: v.sources
            .split(/[\s,]+/)
            .map((s) => s.trim())
            .filter(Boolean),
          enabled: v.enabled,
          labels: rowsToLabels(v.labels),
          programs: rowsToLabels(v.programs),
        },
      }),
    meta: { errorTitle: t("Could not save the device") },
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["syslog"] });
      notifications.show({ color: "teal", message: t("Device {id} saved", { id: res.device?.id ?? "" }) });
      props.onClose();
    },
  });
  if (!d) return null;
  const set = (patch: Partial<DeviceDraft>) => setD({ ...d, ...patch });
  return (
    <Modal opened={props.draft !== null} onClose={props.onClose} title={d.create ? t("Add syslog device") : t("Edit {id}", { id: d.id })} size="lg">
      <Stack>
        <TextInput
          label={t("Device id")}
          description={t("Shown as the node of its logs and alerts; it cannot be a node's id.")}
          value={d.id}
          onChange={(e) => set({ id: e.currentTarget.value })}
          disabled={!d.create}
          placeholder="core-switch-01"
          required
          data-autofocus
        />
        <TextInput label={t("Description")} value={d.description} onChange={(e) => set({ description: e.currentTarget.value })} />
        <Textarea
          label={t("Source addresses")}
          description={t("Addresses or networks (CIDR) the device sends from, one per line. The most specific match wins.")}
          value={d.sources}
          onChange={(e) => set({ sources: e.currentTarget.value })}
          autosize
          minRows={2}
          className="mono-input"
          placeholder={"192.0.2.10\n192.0.2.64/28"}
          required
        />
        <Switch label={t("Enabled")} description={t("Messages of a disabled device are dropped and counted.")} checked={d.enabled} onChange={(e) => set({ enabled: e.currentTarget.checked })} />
        <LabelsEditor value={d.labels} onChange={(labels) => set({ labels })} />
        <Stack gap={6}>
          <Text size="sm" fw={500}>
            {t("Program names")}
          </Text>
          <Text size="xs" c="dimmed">
            {t("Rename syslog tags to the program the CrowdSec parsers expect. The tag * names lines without a syslog header; other tags keep their name.")}
          </Text>
          {d.programs.map((r, i) => (
            <Group key={i} gap="xs" wrap="nowrap">
              <TextInput
                placeholder="%ASA-4-106023"
                value={r.key}
                onChange={(e) => set({ programs: d.programs.map((p, j) => (j === i ? { ...p, key: e.currentTarget.value } : p)) })}
                style={{ flex: 1 }}
                className="mono-input"
              />
              <Text c="dimmed">→</Text>
              <TextInput
                placeholder="cisco-asa"
                value={r.value}
                onChange={(e) => set({ programs: d.programs.map((p, j) => (j === i ? { ...p, value: e.currentTarget.value } : p)) })}
                style={{ flex: 1 }}
                className="mono-input"
              />
              <ActionIcon variant="subtle" color="red" onClick={() => set({ programs: d.programs.filter((_, j) => j !== i) })} aria-label={t("Remove")}>
                <IconTrash size={16} />
              </ActionIcon>
            </Group>
          ))}
          <Group>
            <Button variant="subtle" size="xs" leftSection={<IconPlus size={14} />} onClick={() => set({ programs: [...d.programs, { key: "", value: "" }] })}>
              {t("Add program name")}
            </Button>
          </Group>
        </Stack>
        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {t("Cancel")}
          </Button>
          <Button disabled={!d.id.trim() || !d.sources.trim()} loading={save.isPending} onClick={() => save.mutate(d)}>
            {t("Save")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function SettingsPanel() {
  const access = useAccess();
  const settings = useQuery({ queryKey: ["syslog", "settings"], queryFn: () => api.syslog.getSyslogSettings({}) });
  const set = useMutation({
    mutationFn: (unregistered: string) => api.syslog.setSyslogSettings({ unregistered }),
    meta: { errorTitle: t("Could not save the setting") },
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["syslog"] }),
  });
  if (settings.isPending) return <LoadingBlock h={80} />;
  if (settings.isError) return <ErrorAlert error={settings.error} onRetry={() => settings.refetch()} />;
  const s = settings.data;
  return (
    <Paper withBorder p="md">
      <Stack gap="sm">
        <Group justify="space-between" align="flex-start">
          <Stack gap={4}>
            <Text fw={600}>{t("Unregistered senders")}</Text>
            <Text size="sm" c="dimmed" maw={640}>
              {s.unregistered === "accept"
                ? t("Their messages are taken in as a temporary device named after the address; register it to name it and give it labels.")
                : t("Their messages are dropped and counted per address (Senders tab).")}
              {s.unregisteredDefault ? " " + t("(installation default)") : ""}
            </Text>
          </Stack>
          <SegmentedControl
            value={s.unregistered}
            onChange={(v) => set.mutate(v)}
            disabled={!access.canAdmin || set.isPending}
            data={[
              { value: "drop", label: t("Drop") },
              { value: "accept", label: t("Accept") },
            ]}
          />
        </Group>
        {s.gateways.length === 0 ? (
          <Alert color="orange" icon={<IconInfoCircle size={16} />}>
            {t("No gateway receives syslog. Enable it in the installation (Helm syslog.enabled).")}
          </Alert>
        ) : (
          <Group gap="xs">
            <Text size="sm" c="dimmed">
              {t("Receiving on")}
            </Text>
            {s.gateways.map((g) => (
              <Tooltip key={g.replica} label={g.replica} withArrow>
                <Group gap={4}>
                  {g.listeners.map((l) => (
                    <Badge key={l} variant="light" tt="none" ff="monospace">
                      {l}
                    </Badge>
                  ))}
                </Group>
              </Tooltip>
            ))}
          </Group>
        )}
      </Stack>
    </Paper>
  );
}

function DevicesTable(props: { onEdit: (d: SyslogDevice) => void }) {
  const access = useAccess();
  const devices = useQuery({ queryKey: ["syslog", "devices"], queryFn: () => api.syslog.listSyslogDevices({}), refetchInterval: 30_000 });
  const remove = useMutation({
    mutationFn: (id: string) => api.syslog.deleteSyslogDevice({ id }),
    meta: { errorTitle: t("Could not delete the device") },
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["syslog"] }),
  });
  if (devices.isPending) return <LoadingBlock />;
  if (devices.isError) return <ErrorAlert error={devices.error} onRetry={() => devices.refetch()} />;
  const list = devices.data.devices;
  if (list.length === 0) {
    return <EmptyState title={t("No syslog devices yet")} description={t("Point the device's syslog at a gateway, then register its address here (or from the Senders tab).")} />;
  }
  const confirmDelete = (d: SyslogDevice) =>
    modals.openConfirmModal({
      title: t("Delete device {id}?", { id: d.id }),
      children: <Text size="sm">{t("Its messages are then handled as an unregistered sender's.")}</Text>,
      labels: { confirm: t("Delete"), cancel: t("Cancel") },
      confirmProps: { color: "red" },
      onConfirm: () => remove.mutate(d.id),
    });
  return (
    <Table.ScrollContainer minWidth={1000}>
      <Table highlightOnHover verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>{t("Device")}</Table.Th>
            <Table.Th>{t("Source addresses")}</Table.Th>
            <Table.Th>{t("Labels")}</Table.Th>
            <Table.Th>{t("Programs")}</Table.Th>
            <Table.Th ta="right">{t("Messages")}</Table.Th>
            <Table.Th>{t("Last seen")}</Table.Th>
            {access.canOperate && <Table.Th />}
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {list.map((d) => (
            <Table.Tr key={d.id}>
              <Table.Td>
                <Group gap="xs" wrap="nowrap">
                  <StatusDot color={!d.enabled ? "gray" : d.lastSeen ? "teal" : "yellow"} label={<Text fw={600} size="sm">{d.id}</Text>} />
                  {!d.enabled && (
                    <Badge size="xs" color="gray">
                      {t("disabled")}
                    </Badge>
                  )}
                </Group>
                {d.description && (
                  <Text size="xs" c="dimmed" truncate maw={260}>
                    {d.description}
                  </Text>
                )}
              </Table.Td>
              <Table.Td>
                <Text size="sm" ff="monospace">
                  {d.sources.join(", ")}
                </Text>
              </Table.Td>
              <Table.Td>
                <LabelBadges labels={d.labels} />
              </Table.Td>
              <Table.Td>
                <Group gap={4}>
                  {d.seenPrograms.map((p) => (
                    <Badge key={p} variant="outline" size="sm" tt="none" ff="monospace">
                      {p}
                    </Badge>
                  ))}
                  {Object.keys(d.programs).length > 0 && (
                    <Tooltip
                      label={Object.entries(d.programs)
                        .map(([k, v]) => `${k} → ${v}`)
                        .join("\n")}
                      withArrow
                      multiline
                    >
                      <Badge variant="light" size="sm" color="gray">
                        {t("{n} renamed", { n: Object.keys(d.programs).length })}
                      </Badge>
                    </Tooltip>
                  )}
                </Group>
              </Table.Td>
              <Table.Td ta="right">{formatNumber(d.messages)}</Table.Td>
              <Table.Td>
                <TimeAgo ts={d.lastSeen} />
              </Table.Td>
              {access.canOperate && (
                <Table.Td>
                  <Group gap={4} justify="flex-end" wrap="nowrap">
                    <ActionIcon variant="subtle" onClick={() => props.onEdit(d)} aria-label={t("Edit")}>
                      <IconPencil size={16} />
                    </ActionIcon>
                    <ActionIcon variant="subtle" color="red" onClick={() => confirmDelete(d)} aria-label={t("Delete")}>
                      <IconTrash size={16} />
                    </ActionIcon>
                  </Group>
                </Table.Td>
              )}
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

function SendersTable(props: { onRegister: (s: SyslogSender) => void }) {
  const access = useAccess();
  const [onlyUnregistered, setOnlyUnregistered] = useState(true);
  const senders = useQuery({
    queryKey: ["syslog", "senders", onlyUnregistered],
    queryFn: () => api.syslog.listSyslogSenders({ unregistered: onlyUnregistered }),
    refetchInterval: 30_000,
  });
  return (
    <Stack>
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          {t("Messages per sender address, counted by the gateways every 30 seconds.")}
        </Text>
        <Switch label={t("Unregistered only")} checked={onlyUnregistered} onChange={(e) => setOnlyUnregistered(e.currentTarget.checked)} />
      </Group>
      {senders.isPending ? (
        <LoadingBlock />
      ) : senders.isError ? (
        <ErrorAlert error={senders.error} onRetry={() => senders.refetch()} />
      ) : senders.data.senders.length === 0 ? (
        <EmptyState title={onlyUnregistered ? t("No unregistered senders") : t("No senders yet")} />
      ) : (
        <Table.ScrollContainer minWidth={1000}>
          <Table highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("Address")}</Table.Th>
                <Table.Th>{t("Device")}</Table.Th>
                <Table.Th ta="right">{t("Received")}</Table.Th>
                <Table.Th ta="right">{t("Dropped")}</Table.Th>
                <Table.Th>{t("Latest message")}</Table.Th>
                <Table.Th>{t("Last seen")}</Table.Th>
                {access.canOperate && <Table.Th />}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {senders.data.senders.map((s) => (
                <Table.Tr key={s.addr}>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {s.addr}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {s.deviceId ? (
                      <Text size="sm">{s.deviceId}</Text>
                    ) : toNumber(s.messages) > 0 ? (
                      <Tooltip label={t("Taken in as {id}", { id: tempID(s.addr) })} withArrow>
                        <Badge color="yellow" variant="light" size="sm">
                          {t("unregistered")}
                        </Badge>
                      </Tooltip>
                    ) : (
                      <Badge color="gray" variant="light" size="sm">
                        {t("unregistered")}
                      </Badge>
                    )}
                  </Table.Td>
                  <Table.Td ta="right">{formatNumber(s.messages)}</Table.Td>
                  <Table.Td ta="right">{toNumber(s.dropped) > 0 ? formatNumber(s.dropped) : "-"}</Table.Td>
                  <Table.Td maw={420}>
                    <Tooltip label={<Code style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{s.sample}</Code>} withArrow multiline maw={600}>
                      <Text size="xs" ff="monospace" truncate>
                        {s.sample}
                      </Text>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td>
                    <TimeAgo ts={s.lastSeen} />
                  </Table.Td>
                  {access.canOperate && (
                    <Table.Td>
                      {!s.deviceId && (
                        <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => props.onRegister(s)}>
                          {t("Register")}
                        </Button>
                      )}
                    </Table.Td>
                  )}
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Stack>
  );
}

export default function SyslogPage() {
  const access = useAccess();
  const [tab, setTab] = useUrlState("tab", "devices");
  const [draft, setDraft] = useState<DeviceDraft | null>(null);
  return (
    <>
      <PageHeader
        title={t("Syslog devices")}
        description={t("Equipment without an agent (switches, firewalls, NAS) sending syslog to the gateways, recognized by its address.")}
        right={
          access.canOperate && (
            <Button leftSection={<IconPlus size={16} />} onClick={() => setDraft(draftOf())}>
              {t("Add device")}
            </Button>
          )
        }
      />
      <Stack>
        <SettingsPanel />
        <Tabs value={tab} onChange={(v) => setTab(v ?? "devices")}>
          <Tabs.List mb="md">
            <Tabs.Tab value="devices">{t("Devices")}</Tabs.Tab>
            <Tabs.Tab value="senders">{t("Senders")}</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="devices">
            <DevicesTable onEdit={(d) => setDraft(draftOf(d))} />
          </Tabs.Panel>
          <Tabs.Panel value="senders">
            <SendersTable onRegister={(s) => setDraft(draftOf(undefined, s.addr))} />
          </Tabs.Panel>
        </Tabs>
      </Stack>
      <DeviceModal draft={draft} onClose={() => setDraft(null)} />
    </>
  );
}
