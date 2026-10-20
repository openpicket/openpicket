import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  MultiSelect,
  Paper,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  TagsInput,
  Text,
  TextInput,
  Title,
  UnstyledButton,
  useMantineColorScheme,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconRefresh, IconSearch } from "@tabler/icons-react";
import { useInfiniteQuery, useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAccess, useUISettings } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import { EmptyState, ErrorAlert, KeyValue, LoadingBlock, PageHeader, StatusDot, TimeAgo } from "../components/common";
import type { UISettings } from "../gen/openpicket/api/v1/system_pb";
import { LogType, type LogCollectionPolicy } from "../gen/suricontroller/agent/v1/agent_pb";
import { formatDateTime, tsDate } from "../lib/format";
import { LANGUAGES, t, useLanguage } from "../lib/i18n";
import { setPref, usePrefs, type Prefs } from "../lib/prefs";
import { useUrlState } from "../lib/urlState";

const stateColor: Record<string, string> = { ok: "green", degraded: "orange", down: "red", disabled: "gray" };

function timeZones(): string[] {
  try {
    return (Intl as unknown as { supportedValuesOf: (k: string) => string[] }).supportedValuesOf("timeZone");
  } catch {
    return ["UTC"];
  }
}

function StatusTab() {
  const access = useAccess();
  const q = useQuery({ queryKey: ["systemStatus"], queryFn: () => api.system.getStatus({}), refetchInterval: 15_000 });
  const resync = useMutation({
    mutationFn: () => api.system.resyncAlerts({}),
    meta: { errorTitle: t("Could not start the resync") },
    onSuccess: () => notifications.show({ color: "teal", message: t("A full alert resync was requested.") }),
  });
  const confirmResync = () =>
    modals.openConfirmModal({
      title: t("Resync alerts"),
      children: <Text size="sm">{t("Re-read every alert of the retention window from the LAPIs. This can take a while on large installations.")}</Text>,
      labels: { confirm: t("Resync"), cancel: t("Cancel") },
      onConfirm: () => resync.mutate(),
    });
  if (q.isPending) return <LoadingBlock />;
  if (q.isError) return <ErrorAlert error={q.error} onRetry={() => q.refetch()} />;
  const s = q.data;
  return (
    <Stack>
      <Paper withBorder p="md" radius="md">
        <Group justify="space-between" align="flex-start">
          <KeyValue
            rows={[
              [t("Version"), <Code key="v">{s.version}</Code>],
              [t("This replica"), s.replica],
              [
                t("Replicas"),
                <Group key="r" gap={4}>
                  {s.replicas.map((r) => (
                    <Badge key={r} variant="light" color={r === s.replica ? "blue" : "gray"}>
                      {r}
                    </Badge>
                  ))}
                </Group>,
              ],
            ]}
          />
          {access.canOperate && (
            <Button variant="light" leftSection={<IconRefresh size={16} />} onClick={confirmResync} loading={resync.isPending}>
              {t("Resync alerts")}
            </Button>
          )}
        </Group>
      </Paper>
      <Table.ScrollContainer minWidth={600}>
        <Table verticalSpacing="xs" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("Component")}</Table.Th>
              <Table.Th>{t("State")}</Table.Th>
              <Table.Th>{t("Detail")}</Table.Th>
              <Table.Th>{t("Checked")}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {s.components.map((c) => (
              <Table.Tr key={c.name}>
                <Table.Td>
                  <Text size="sm" ff="monospace">
                    {c.name}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <StatusDot color={stateColor[c.state] ?? "gray"} label={t(c.state)} />
                </Table.Td>
                <Table.Td>
                  <Text size="sm" style={{ wordBreak: "break-word" }}>
                    {c.detail}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <TimeAgo ts={c.checkedAt} />
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Stack>
  );
}

const AUDIT_PAGE = 100;

function AuditDetail(props: { detail: string }) {
  const [open, setOpen] = useState(false);
  if (!props.detail) return null;
  return (
    <UnstyledButton onClick={() => setOpen((o) => !o)} style={{ textAlign: "left" }}>
      <Text size="xs" ff="monospace" lineClamp={open ? undefined : 1} style={{ wordBreak: "break-all", maxWidth: 520 }}>
        {props.detail}
      </Text>
    </UnstyledButton>
  );
}

function AuditTab() {
  const [principal, setPrincipal] = useState("");
  const [action, setAction] = useState("");
  const [target, setTarget] = useState("");
  const [filters, setFilters] = useState({ principal: "", actionPrefix: "", target: "" });
  const q = useInfiniteQuery({
    queryKey: ["audit", filters],
    queryFn: ({ pageParam }) => api.system.listAudit({ limit: AUDIT_PAGE, beforeId: pageParam, ...filters }),
    initialPageParam: 0n,
    getNextPageParam: (last) => (last.entries.length < AUDIT_PAGE ? undefined : last.entries[last.entries.length - 1].id),
  });
  const apply = () => setFilters({ principal: principal.trim(), actionPrefix: action.trim(), target: target.trim() });
  const entries = q.data?.pages.flatMap((p) => p.entries) ?? [];
  return (
    <Stack>
      <Group align="flex-end" gap="xs" wrap="wrap">
        <TextInput label={t("Principal")} placeholder="static:admin" value={principal} onChange={(e) => setPrincipal(e.currentTarget.value)} onKeyDown={(e) => e.key === "Enter" && apply()} />
        <TextInput label={t("Action prefix")} placeholder="DecisionService." value={action} onChange={(e) => setAction(e.currentTarget.value)} onKeyDown={(e) => e.key === "Enter" && apply()} />
        <TextInput label={t("Target")} value={target} onChange={(e) => setTarget(e.currentTarget.value)} onKeyDown={(e) => e.key === "Enter" && apply()} />
        <Button leftSection={<IconSearch size={16} />} onClick={apply}>
          {t("Filter")}
        </Button>
      </Group>
      {q.isPending && <LoadingBlock />}
      {q.isError && <ErrorAlert error={q.error} onRetry={() => q.refetch()} />}
      {!q.isPending && entries.length === 0 && <EmptyState title={t("No audit entries")} />}
      {entries.length > 0 && (
        <Table.ScrollContainer minWidth={900}>
          <Table verticalSpacing={4} fz="sm" striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("Time")}</Table.Th>
                <Table.Th>{t("Source")}</Table.Th>
                <Table.Th>{t("Principal")}</Table.Th>
                <Table.Th>{t("Action")}</Table.Th>
                <Table.Th>{t("Target")}</Table.Th>
                <Table.Th>{t("Detail")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {entries.map((e) => (
                <Table.Tr key={String(e.id)}>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDateTime(tsDate(e.time))}</Table.Td>
                  <Table.Td>
                    <Badge size="xs" variant="light" color={e.source === "suricontroller" ? "grape" : "blue"}>
                      {e.source}
                    </Badge>
                  </Table.Td>
                  <Table.Td>{e.principal}</Table.Td>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {e.action}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" ff="monospace" style={{ wordBreak: "break-all" }}>
                      {e.target}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <AuditDetail detail={e.detail} />
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {q.hasNextPage && (
        <Button variant="default" onClick={() => q.fetchNextPage()} loading={q.isFetchingNextPage}>
          {t("Load more")}
        </Button>
      )}
    </Stack>
  );
}

type UIForm = Omit<UISettings, "$typeName" | "$unknown">;

function UISettingsForm() {
  const ui = useUISettings();
  const access = useAccess();
  const [f, setF] = useState<UIForm | null>(null);
  useEffect(() => {
    if (ui.data && !f) {
      const { $typeName: _t, $unknown: _u, ...rest } = ui.data;
      void _t;
      void _u;
      setF(rest);
    }
  }, [ui.data, f]);
  const zones = useMemo(timeZones, []);
  const save = useMutation({
    mutationFn: () => api.system.setUISettings({ settings: f! }),
    meta: { errorTitle: t("Could not save the settings") },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["uiSettings"] });
      notifications.show({ color: "teal", message: t("Settings saved") });
    },
  });
  if (ui.isError) return <ErrorAlert error={ui.error} />;
  if (!f) return <LoadingBlock />;
  const set = <K extends keyof UIForm>(k: K, v: UIForm[K]) => setF((old) => ({ ...old!, [k]: v }));
  const ro = !access.canAdmin;
  return (
    <Paper withBorder p="md" radius="md">
      <Title order={4} mb="sm">
        {t("UI defaults")}
      </Title>
      <Stack gap="sm">
        <TagsInput
          label={t("Manual decision scenarios")}
          description={t("Offered in the Add decision form. openpicket/manual-both blocks both ways at the edge.")}
          value={f.manualScenarios}
          onChange={(v) => set("manualScenarios", v)}
          disabled={ro}
        />
        <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }}>
          <Select label={t("Default time zone")} data={zones} value={f.timeZone || null} onChange={(v) => set("timeZone", v ?? "")} searchable clearable placeholder={t("Browser")} disabled={ro} />
          <Select
            label={t("Clock")}
            data={[
              { value: "24h", label: t("24-hour") },
              { value: "12h", label: t("12-hour") },
            ]}
            value={f.clock || null}
            onChange={(v) => set("clock", v ?? "")}
            clearable
            disabled={ro}
          />
          <Select
            label={t("Date format")}
            data={[
              { value: "iso", label: "2026-10-20" },
              { value: "us", label: "10/20/2026" },
              { value: "eu", label: "20.10.2026" },
            ]}
            value={f.dateFormat || null}
            onChange={(v) => set("dateFormat", v ?? "")}
            clearable
            disabled={ro}
          />
          <Select label={t("Default language")} data={LANGUAGES} value={f.language || null} onChange={(v) => set("language", v ?? "")} clearable placeholder={t("Browser")} disabled={ro} />
        </SimpleGrid>
        {!ro && (
          <Group justify="flex-end">
            <Button onClick={() => save.mutate()} loading={save.isPending}>
              {t("Save")}
            </Button>
          </Group>
        )}
      </Stack>
    </Paper>
  );
}

const LOG_TYPES = [
  { value: String(LogType.EVE), label: "eve.json" },
  { value: String(LogType.SURICATA), label: "suricata.log" },
  { value: String(LogType.FAST), label: "fast.log" },
  { value: String(LogType.STATS), label: "stats.log" },
  { value: String(LogType.AGENT), label: "agent" },
];

function LogPolicyForm() {
  const access = useAccess();
  const q = useQuery({ queryKey: ["logPolicy"], queryFn: () => api.system.getLogPolicy({}) });
  const [p, setP] = useState<LogCollectionPolicy | null>(null);
  useEffect(() => {
    if (q.data?.policy) setP(q.data.policy);
  }, [q.data]);
  const done = (msg: string) => {
    void queryClient.invalidateQueries({ queryKey: ["logPolicy"] });
    notifications.show({ color: "teal", message: msg });
  };
  const save = useMutation({
    mutationFn: () => api.system.setLogPolicy({ policy: p! }),
    meta: { errorTitle: t("Could not save the log policy") },
    onSuccess: () => done(t("Log collection policy saved; agents receive it now.")),
  });
  const reset = useMutation({
    mutationFn: () => api.system.setLogPolicy({ reset: true }),
    meta: { errorTitle: t("Could not reset the log policy") },
    onSuccess: () => done(t("Log collection policy reset to the default.")),
  });
  if (q.isError) return <ErrorAlert error={q.error} />;
  if (!p) return <LoadingBlock />;
  const ro = !access.canAdmin;
  return (
    <Paper withBorder p="md" radius="md">
      <Group justify="space-between" mb="sm">
        <Title order={4}>{t("Log collection")}</Title>
        {q.data?.isDefault && (
          <Badge variant="light" color="gray">
            {t("default")}
          </Badge>
        )}
      </Group>
      <Stack gap="sm">
        <Text size="sm" c="dimmed">
          {t("What agents ship to Loki and CrowdSec. Suricata alerts reach CrowdSec through eve.json.")}
        </Text>
        <Switch label={t("Collect logs")} checked={p.enabled} onChange={(e) => setP({ ...p, enabled: e.currentTarget.checked })} disabled={ro} />
        <MultiSelect
          label={t("Log types")}
          data={LOG_TYPES}
          value={p.types.map(String)}
          onChange={(v) => setP({ ...p, types: v.map(Number) as LogType[] })}
          disabled={ro || !p.enabled}
        />
        <Switch
          label={t("All eve event types")}
          checked={p.eveAllTypes}
          onChange={(e) => setP({ ...p, eveAllTypes: e.currentTarget.checked })}
          disabled={ro || !p.enabled}
        />
        {!p.eveAllTypes && (
          <TagsInput
            label={t("Eve event types")}
            description={t("alert, anomaly, flow, dns, tls, http, ...")}
            value={p.eveTypes}
            onChange={(v) => setP({ ...p, eveTypes: v })}
            disabled={ro || !p.enabled}
          />
        )}
        {!ro && (
          <Group justify="flex-end">
            <Button variant="default" onClick={() => reset.mutate()} loading={reset.isPending} disabled={q.data?.isDefault}>
              {t("Reset to default")}
            </Button>
            <Button onClick={() => save.mutate()} loading={save.isPending}>
              {t("Save")}
            </Button>
          </Group>
        )}
      </Stack>
    </Paper>
  );
}

function PreferencesTab() {
  const prefs = usePrefs();
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const zones = useMemo(timeZones, []);
  const def = { value: "", label: t("(server default)") };
  return (
    <Paper withBorder p="md" radius="md" maw={640}>
      <Stack gap="sm">
        <Text size="sm" c="dimmed">
          {t("These preferences are stored in this browser only.")}
        </Text>
        <Select label={t("Language")} data={[def, ...LANGUAGES]} value={prefs.language} onChange={(v) => setPref("language", v ?? "")} allowDeselect={false} />
        <Select label={t("Time zone")} data={[def, ...zones.map((z) => ({ value: z, label: z }))]} value={prefs.timeZone} onChange={(v) => setPref("timeZone", v ?? "")} searchable allowDeselect={false} />
        <Select
          label={t("Clock")}
          data={[def, { value: "24h", label: t("24-hour") }, { value: "12h", label: t("12-hour") }]}
          value={prefs.clock}
          onChange={(v) => setPref("clock", (v ?? "") as Prefs["clock"])}
          allowDeselect={false}
        />
        <Select
          label={t("Date format")}
          data={[def, { value: "iso", label: "2026-10-20" }, { value: "us", label: "10/20/2026" }, { value: "eu", label: "20.10.2026" }]}
          value={prefs.dateFormat}
          onChange={(v) => setPref("dateFormat", (v ?? "") as Prefs["dateFormat"])}
          allowDeselect={false}
        />
        <Stack gap={4}>
          <Text size="sm" fw={500}>
            {t("Theme")}
          </Text>
          <SegmentedControl
            value={colorScheme}
            onChange={(v) => setColorScheme(v as "auto" | "light" | "dark")}
            data={[
              { value: "auto", label: t("auto") },
              { value: "light", label: t("light") },
              { value: "dark", label: t("dark") },
            ]}
          />
        </Stack>
        <Text size="xs" c="dimmed">
          {t("Now")}: {formatDateTime(new Date())}
        </Text>
      </Stack>
    </Paper>
  );
}

export default function SystemPage() {
  useLanguage();
  const access = useAccess();
  const [tab, setTab] = useUrlState("tab", "status");
  return (
    <>
      <PageHeader title={t("System")} description={t("Health, audit log and settings of OpenPicket.")} />
      <Tabs value={tab} onChange={(v) => setTab(v ?? "status")} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="status">{t("Status")}</Tabs.Tab>
          {access.isOperator && <Tabs.Tab value="audit">{t("Audit")}</Tabs.Tab>}
          {access.isAdmin && <Tabs.Tab value="settings">{t("Settings")}</Tabs.Tab>}
          <Tabs.Tab value="preferences">{t("Preferences")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="status">
          <StatusTab />
        </Tabs.Panel>
        {access.isOperator && (
          <Tabs.Panel value="audit">
            <AuditTab />
          </Tabs.Panel>
        )}
        {access.isAdmin && (
          <Tabs.Panel value="settings">
            <Stack>
              {access.readOnly && <Alert color="orange">{t("OpenPicket is in read-only mode: settings cannot be changed.")}</Alert>}
              <UISettingsForm />
              <LogPolicyForm />
            </Stack>
          </Tabs.Panel>
        )}
        <Tabs.Panel value="preferences">
          <PreferencesTab />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
