import { useMemo, useState } from "react";
import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  Pagination,
  Paper,
  ScrollArea,
  SegmentedControl,
  Select,
  Stack,
  Table,
  Tabs,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconAlertTriangle, IconDownload, IconRefresh, IconSearch, IconTrash } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAccess } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import { EmptyState, ErrorAlert, LoadingBlock, PageHeader, StatusDot, TimeAgo } from "../components/common";
import type { HubIndexEntry, HubItem } from "../gen/openpicket/api/v1/hub_pb";
import { toNumber } from "../lib/format";
import { t } from "../lib/i18n";
import { useUrlState } from "../lib/urlState";

const TYPES: { value: string; label: string }[] = [
  { value: "scenarios", label: "Scenarios" },
  { value: "parsers", label: "Parsers" },
  { value: "collections", label: "Collections" },
  { value: "postoverflows", label: "Postoverflows" },
  { value: "contexts", label: "Contexts" },
  { value: "appsec-configs", label: "AppSec configs" },
  { value: "appsec-rules", label: "AppSec rules" },
];

const SOURCE_COLOR: Record<string, string> = {
  builtin: "blue",
  hub: "grape",
  custom: "orange",
};
const SOURCE_LABEL: Record<string, string> = {
  builtin: "built-in",
  hub: "hub",
  custom: "custom",
};

function invalidate() {
  void queryClient.invalidateQueries({ queryKey: ["hubItems"] });
  void queryClient.invalidateQueries({ queryKey: ["hubRollout"] });
  void queryClient.invalidateQueries({ queryKey: ["hubIndex"] });
}

/** Whether the enabled parsers feed a scenario. */
function CompatBadge(props: { compat: string; missing: string[] }) {
  if (props.compat === "missing") {
    return (
      <Tooltip
        label={t("No enabled parser sets the log types it reads: {types}", {
          types: props.missing.join(", "),
        })}
        withArrow
        multiline
        w={320}
      >
        <Badge size="xs" color="orange" variant="light">
          {t("no matching logs")}
        </Badge>
      </Tooltip>
    );
  }
  if (props.compat === "unknown") {
    return (
      <Badge size="xs" color="gray" variant="light">
        {t("log type unknown")}
      </Badge>
    );
  }
  return null;
}

/** What the log processors run. */
function Rollout() {
  const q = useQuery({
    queryKey: ["hubRollout"],
    queryFn: () => api.hub.getHubRollout({}),
    refetchInterval: 5_000,
  });
  if (q.isPending) return <LoadingBlock />;
  if (q.isError) return <ErrorAlert error={q.error} />;
  const r = q.data;
  const rev = toNumber(r.revision);
  const refused = toNumber(r.failedRevision) === rev && rev > 0;
  return (
    <Paper withBorder p="md" radius="md">
      <Group justify="space-between" mb="sm">
        <Title order={5}>{t("Log processors")}</Title>
        <Text size="sm" c="dimmed">
          {t("Content revision {r}", { r: rev })}
          {toNumber(r.goodRevision) !== rev && ` · ${t("last accepted {r}", { r: toNumber(r.goodRevision) })}`}
        </Text>
      </Group>
      {refused && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />} mb="sm" title={t("CrowdSec refused revision {r}", { r: rev })}>
          <Text size="sm" mb={4}>
            {t("The log processors keep running revision {g}. Fix or disable the item named below.", { g: toNumber(r.goodRevision) })}
          </Text>
          <Code block style={{ whiteSpace: "pre-wrap" }}>
            {r.failedError}
          </Code>
        </Alert>
      )}
      {r.logProcessors.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("No log processor found yet.")}
        </Text>
      ) : (
        <Table.ScrollContainer minWidth={520}>
          <Table fz="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("Endpoint")}</Table.Th>
                <Table.Th>{t("State")}</Table.Th>
                <Table.Th>{t("Revision")}</Table.Th>
                <Table.Th>{t("Checked")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {r.logProcessors.map((l) => {
                const lrev = toNumber(l.revision);
                return (
                  <Table.Tr key={l.endpoint}>
                    <Table.Td ff="monospace">{l.endpoint}</Table.Td>
                    <Table.Td>
                      {l.error && !l.running ? (
                        <Tooltip label={l.error} withArrow multiline w={360}>
                          <span>
                            <StatusDot color="red" label={t("error")} />
                          </span>
                        </Tooltip>
                      ) : !l.running ? (
                        <StatusDot color="orange" label={t("waiting for content")} />
                      ) : lrev === rev ? (
                        <StatusDot color="teal" label={t("up to date")} />
                      ) : (
                        <StatusDot color="yellow" label={t("behind")} />
                      )}
                    </Table.Td>
                    <Table.Td>{lrev || "-"}</Table.Td>
                    <Table.Td>
                      <TimeAgo ts={l.seenAt} />
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Paper>
  );
}

function StateControl(props: { item: HubItem; disabled: boolean }) {
  const it = props.item;
  const set = useMutation({
    mutationFn: (state: string) => api.hub.setHubItemState({ ref: { type: it.type, name: it.name }, state }),
    meta: { errorTitle: t("Could not change the state") },
    onSuccess: () => {
      invalidate();
      notifications.show({
        color: "teal",
        message: t("{name}: the log processors receive the change now", {
          name: it.name,
        }),
      });
    },
  });
  const sim = it.type === "scenarios" || it.type === "collections";
  const data = [
    { value: "enabled", label: t("on") },
    ...(sim ? [{ value: "simulation", label: t("simulation") }] : []),
    { value: "disabled", label: t("off") },
  ];
  return (
    <SegmentedControl
      size="xs"
      data={data}
      value={it.state}
      onChange={(v) => set.mutate(v)}
      disabled={props.disabled || set.isPending}
      color={it.state === "enabled" ? "teal" : it.state === "simulation" ? "yellow" : "gray"}
    />
  );
}

function ItemModal(props: { item: HubItem | null; onClose: () => void }) {
  const it = props.item;
  const q = useQuery({
    queryKey: ["hubItem", it?.type, it?.name],
    enabled: !!it,
    queryFn: () => api.hub.getHubItem({ ref: { type: it!.type, name: it!.name } }),
  });
  return (
    <Modal opened={!!it} onClose={props.onClose} title={it?.name} size="xl">
      {it && (
        <Stack>
          {it.description && <Text size="sm">{it.description}</Text>}
          <Group gap="xs">
            <Badge variant="light" color={SOURCE_COLOR[it.source]}>
              {t(SOURCE_LABEL[it.source] ?? it.source)}
            </Badge>
            {it.version && <Badge variant="outline">{it.version}</Badge>}
            {it.stage && <Badge variant="outline">{it.stage}</Badge>}
          </Group>
          {it.members.length > 0 && (
            <div>
              <Text size="sm" fw={500} mb={4}>
                {t("Members")}
              </Text>
              <Group gap={4}>
                {it.members.map((m) => (
                  <Badge key={m.type + m.name} variant="light" color="gray">
                    {m.type}: {m.name}
                  </Badge>
                ))}
              </Group>
            </div>
          )}
          {it.data.length > 0 && (
            <Text size="sm">
              {t("Data files")}: <Code>{it.data.join(", ")}</Code>
            </Text>
          )}
          {it.type !== "collections" &&
            (q.isPending ? (
              <LoadingBlock />
            ) : q.isError ? (
              <ErrorAlert error={q.error} />
            ) : (
              <ScrollArea.Autosize mah={480}>
                <Code block>{q.data.content}</Code>
              </ScrollArea.Autosize>
            ))}
        </Stack>
      )}
    </Modal>
  );
}

/** CrowdSec content: items, their state, and what the log processors run. */
export default function HubPage() {
  const access = useAccess();
  const [type, setType] = useUrlState("type", "scenarios");
  const [view, setView] = useUrlState("view", "installed");
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<HubItem | null>(null);
  const q = useQuery({
    queryKey: ["hubItems"],
    queryFn: () => api.hub.listHubItems({}),
  });
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const it of q.data?.items ?? []) c[it.type] = (c[it.type] ?? 0) + 1;
    return c;
  }, [q.data]);
  const s = search.trim().toLowerCase();
  const items = (q.data?.items ?? []).filter(
    (it) => it.type === type && (!s || it.name.toLowerCase().includes(s) || it.description.toLowerCase().includes(s)),
  );
  const staged = type === "parsers" || type === "postoverflows";
  return (
    <>
      <PageHeader
        title={t("CrowdSec content")}
        description={t("Parsers, scenarios and collections the log processors run. Simulation raises alerts without decisions.")}
      />
      <Stack>
        <Rollout />
        <SegmentedControl
          w="fit-content"
          value={view}
          onChange={setView}
          data={[
            { value: "installed", label: t("Installed") },
            { value: "hub", label: t("CrowdSec hub") },
          ]}
        />
        {view === "hub" ? (
          <HubBrowser />
        ) : (
          <Paper withBorder p="md" radius="md">
            <Tabs value={type} onChange={(v) => v && setType(v)} mb="sm">
              <Tabs.List>
                {TYPES.map((ty) => (
                  <Tabs.Tab
                    key={ty.value}
                    value={ty.value}
                    rightSection={
                      counts[ty.value] ? (
                        <Badge size="xs" variant="light">
                          {counts[ty.value]}
                        </Badge>
                      ) : null
                    }
                  >
                    {t(ty.label)}
                  </Tabs.Tab>
                ))}
              </Tabs.List>
            </Tabs>
            <TextInput
              placeholder={t("Search name or description")}
              leftSection={<IconSearch size={16} />}
              value={search}
              onChange={(e) => setSearch(e.currentTarget.value)}
              mb="sm"
              maw={360}
            />
            {q.isPending ? (
              <LoadingBlock />
            ) : q.isError ? (
              <ErrorAlert error={q.error} />
            ) : items.length === 0 ? (
              <EmptyState title={t("Nothing here")} />
            ) : (
              <Table.ScrollContainer minWidth={760}>
                <Table fz="sm" highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{t("Name")}</Table.Th>
                      <Table.Th>{t("Source")}</Table.Th>
                      <Table.Th>{t("Version")}</Table.Th>
                      {staged && <Table.Th>{t("Stage")}</Table.Th>}
                      <Table.Th>{t("Collections")}</Table.Th>
                      <Table.Th>{t("State")}</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {items.map((it) => (
                      <Table.Tr key={it.type + it.name}>
                        <Table.Td style={{ cursor: "pointer" }} onClick={() => setOpen(it)}>
                          <Text size="sm" ff="monospace">
                            {it.name}
                          </Text>
                          {it.description && (
                            <Text size="xs" c="dimmed" lineClamp={1}>
                              {it.description}
                            </Text>
                          )}
                          <CompatBadge compat={it.compat} missing={it.missingLogTypes} />
                        </Table.Td>
                        <Table.Td>
                          <Badge variant="light" color={SOURCE_COLOR[it.source]}>
                            {t(SOURCE_LABEL[it.source] ?? it.source)}
                          </Badge>
                        </Table.Td>
                        <Table.Td>
                          <Group gap={4} wrap="nowrap">
                            {it.version || "-"}
                            {it.latestVersion && access.canAdmin && <UpdateButton item={it} />}
                          </Group>
                        </Table.Td>
                        {staged && <Table.Td>{it.stage}</Table.Td>}
                        <Table.Td>
                          <Group gap={4}>
                            {it.memberOf.map((c) => (
                              <Badge key={c} size="xs" variant="outline">
                                {c}
                              </Badge>
                            ))}
                          </Group>
                        </Table.Td>
                        <Table.Td>
                          <Group gap={4} wrap="nowrap">
                            <StateControl item={it} disabled={!access.canAdmin} />
                            {access.canAdmin && it.source !== "builtin" && <RemoveButton item={it} />}
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            )}
          </Paper>
        )}
      </Stack>
      <ItemModal item={open} onClose={() => setOpen(null)} />
    </>
  );
}

function UpdateButton(props: { item: HubItem }) {
  const it = props.item;
  const update = useMutation({
    mutationFn: () => api.hub.installHubItem({ ref: { type: it.type, name: it.name } }),
    meta: { errorTitle: t("Could not update {name}", { name: it.name }) },
    onSuccess: () => {
      invalidate();
      notifications.show({
        color: "teal",
        message: t("{name} updated to {v}", {
          name: it.name,
          v: it.latestVersion,
        }),
      });
    },
  });
  return (
    <Tooltip label={t("Update to {v}", { v: it.latestVersion })} withArrow>
      <Badge
        size="xs"
        color="grape"
        variant="filled"
        style={{ cursor: "pointer" }}
        onClick={() => !update.isPending && update.mutate()}
        leftSection={<IconDownload size={10} />}
      >
        {it.latestVersion}
      </Badge>
    </Tooltip>
  );
}

function RemoveButton(props: { item: HubItem }) {
  const it = props.item;
  const remove = useMutation({
    mutationFn: () => api.hub.removeHubItem({ ref: { type: it.type, name: it.name } }),
    meta: { errorTitle: t("Could not remove {name}", { name: it.name }) },
    onSuccess: () => {
      invalidate();
      notifications.show({
        color: "teal",
        message: t("{name} removed", { name: it.name }),
      });
    },
  });
  const confirm = () =>
    modals.openConfirmModal({
      title: t("Remove {name}?", { name: it.name }),
      children: (
        <Text size="sm">
          {it.type === "collections"
            ? t("Its members go too, unless installed on their own or in another collection.")
            : it.memberOf.length > 0
              ? t("It stays as a member of {c}.", { c: it.memberOf.join(", ") })
              : t("The log processors stop running it.")}
        </Text>
      ),
      labels: { confirm: t("Remove"), cancel: t("Cancel") },
      confirmProps: { color: "red" },
      onConfirm: () => remove.mutate(),
    });
  return (
    <Tooltip label={t("Remove")} withArrow>
      <ActionIcon variant="subtle" color="red" onClick={confirm} loading={remove.isPending} aria-label={t("Remove")}>
        <IconTrash size={16} />
      </ActionIcon>
    </Tooltip>
  );
}

/** The CrowdSec hub index: search, preview, install. */
function HubBrowser() {
  const access = useAccess();
  const [type, setType] = useState("scenarios");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [preview, setPreview] = useState<HubIndexEntry | null>(null);
  const limit = 50;
  const q = useQuery({
    queryKey: ["hubIndex", type, query, page],
    queryFn: () => api.hub.listHubIndex({ type, query, limit, offset: (page - 1) * limit }),
    placeholderData: (prev) => prev,
  });
  const refresh = useMutation({
    mutationFn: () => api.hub.refreshHubIndex({}),
    meta: { errorTitle: t("Could not download the hub index") },
    onSuccess: (r) => {
      invalidate();
      notifications.show({
        color: "teal",
        message: r.changed ? t("Hub index updated") : t("The hub index is up to date"),
      });
    },
  });
  return (
    <Paper withBorder p="md" radius="md">
      <Group justify="space-between" mb="sm" align="flex-end">
        <Group align="flex-end">
          <Select
            label={t("Type")}
            data={TYPES.map((ty) => ({ value: ty.value, label: t(ty.label) }))}
            value={type}
            onChange={(v) => {
              if (v) setType(v);
              setPage(1);
            }}
            w={180}
            allowDeselect={false}
          />
          <TextInput
            label={t("Search")}
            placeholder={t("Search name or description")}
            leftSection={<IconSearch size={16} />}
            value={query}
            onChange={(e) => {
              setQuery(e.currentTarget.value);
              setPage(1);
            }}
            w={320}
          />
        </Group>
        <Group gap="xs">
          <Text size="xs" c="dimmed">
            {q.data?.fetchedAt ? (
              <>
                {t("Index downloaded")} <TimeAgo ts={q.data.fetchedAt} size="xs" />
              </>
            ) : (
              t("The index was never downloaded")
            )}
          </Text>
          {access.canAdmin && (
            <Button size="xs" variant="default" leftSection={<IconRefresh size={14} />} loading={refresh.isPending} onClick={() => refresh.mutate()}>
              {t("Refresh")}
            </Button>
          )}
        </Group>
      </Group>
      {q.isPending ? (
        <LoadingBlock />
      ) : q.isError ? (
        <ErrorAlert error={q.error} />
      ) : !q.data.fetchedAt ? (
        <EmptyState
          title={t("No hub index yet")}
          description={t("Download it from {url}. Without internet access, set OPENPICKET_HUB_URL to a mirror or upload items.", {
            url: q.data.baseUrl,
          })}
        />
      ) : (
        <>
          <Table.ScrollContainer minWidth={640}>
            <Table fz="sm" highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("Name")}</Table.Th>
                  <Table.Th>{t("Version")}</Table.Th>
                  <Table.Th>{t("Installed")}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {q.data.entries.map((e) => (
                  <Table.Tr key={e.type + e.name} style={{ cursor: "pointer" }} onClick={() => setPreview(e)}>
                    <Table.Td>
                      <Text size="sm" ff="monospace">
                        {e.name}
                      </Text>
                      <Text size="xs" c="dimmed" lineClamp={1}>
                        {e.description}
                      </Text>
                    </Table.Td>
                    <Table.Td>{e.version}</Table.Td>
                    <Table.Td>
                      {e.installedSource ? (
                        <Badge
                          variant="light"
                          color={e.installedVersion !== e.version && e.installedSource === "hub" ? "grape" : SOURCE_COLOR[e.installedSource]}
                        >
                          {e.installedSource === "hub" ? e.installedVersion : t(SOURCE_LABEL[e.installedSource] ?? e.installedSource)}
                        </Badge>
                      ) : (
                        "-"
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
          {q.data.total > limit && (
            <Group justify="center" mt="sm">
              <Pagination total={Math.ceil(q.data.total / limit)} value={page} onChange={setPage} size="sm" />
            </Group>
          )}
        </>
      )}
      <PreviewModal entry={preview} onClose={() => setPreview(null)} />
    </Paper>
  );
}

function PreviewModal(props: { entry: HubIndexEntry | null; onClose: () => void }) {
  const access = useAccess();
  const e = props.entry;
  const q = useQuery({
    queryKey: ["hubPreview", e?.type, e?.name],
    enabled: !!e && access.canAdmin,
    queryFn: () => api.hub.previewHubItem({ ref: { type: e!.type, name: e!.name } }),
    retry: false,
  });
  const install = useMutation({
    mutationFn: () => api.hub.installHubItem({ ref: { type: e!.type, name: e!.name } }),
    meta: {
      errorTitle: t("Could not install {name}", { name: e?.name ?? "" }),
    },
    onSuccess: (r) => {
      invalidate();
      notifications.show({
        color: "teal",
        message: t("Installed {n} items. New scenarios start in simulation: review their alerts, then turn them on.", { n: r.installed.length }),
        autoClose: 8000,
      });
      props.onClose();
    },
  });
  return (
    <Modal opened={!!e} onClose={props.onClose} title={e?.name} size="xl">
      {e && (
        <Stack>
          <Text size="sm">{e.description}</Text>
          {e.references.length > 0 && (
            <Group gap="xs">
              {e.references.map((r) => (
                <Anchor key={r} href={r} target="_blank" rel="noreferrer" size="xs">
                  {r}
                </Anchor>
              ))}
            </Group>
          )}
          {!access.canAdmin ? (
            <Text size="sm" c="dimmed">
              {t("Only administrators can preview and install hub items.")}
            </Text>
          ) : q.isPending ? (
            <LoadingBlock />
          ) : q.isError ? (
            <ErrorAlert error={q.error} />
          ) : (
            <>
              {q.data.compat === "missing" && (
                <Alert color="orange" icon={<IconAlertTriangle size={16} />}>
                  {t("No enabled parser sets the log types its scenarios read ({types}): they stay silent until such logs come in.", {
                    types: q.data.missingLogTypes.join(", "),
                  })}
                </Alert>
              )}
              {q.data.items.length > 1 && (
                <div>
                  <Text size="sm" fw={500} mb={4}>
                    {t("Installs {n} items", { n: q.data.items.length })}
                  </Text>
                  <Group gap={4}>
                    {q.data.items.map((m) => (
                      <Badge key={m.type + m.name} variant="light" color="gray">
                        {m.type}: {m.name}
                      </Badge>
                    ))}
                  </Group>
                </div>
              )}
              {q.data.dataFiles.length > 0 && (
                <Text size="sm">
                  {t("Data files")}: <Code>{q.data.dataFiles.join(", ")}</Code>
                </Text>
              )}
              {q.data.content && (
                <ScrollArea.Autosize mah={400}>
                  <Code block>{q.data.content}</Code>
                </ScrollArea.Autosize>
              )}
              <Group justify="flex-end">
                <Button leftSection={<IconDownload size={16} />} loading={install.isPending} onClick={() => install.mutate()}>
                  {e.installedSource === "hub" ? (e.installedVersion !== e.version ? t("Update") : t("Reinstall")) : t("Install")}
                </Button>
              </Group>
            </>
          )}
        </Stack>
      )}
    </Modal>
  );
}
