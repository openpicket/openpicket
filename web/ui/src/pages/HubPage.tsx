import { useMemo, useState } from "react";
import { Alert, Badge, Code, Group, Modal, Paper, ScrollArea, SegmentedControl, Stack, Table, Tabs, Text, TextInput, Title, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertTriangle, IconSearch } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAccess } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import { EmptyState, ErrorAlert, LoadingBlock, PageHeader, StatusDot, TimeAgo } from "../components/common";
import type { HubItem } from "../gen/openpicket/api/v1/hub_pb";
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

const SOURCE_COLOR: Record<string, string> = { builtin: "blue", hub: "grape", custom: "orange" };
const SOURCE_LABEL: Record<string, string> = { builtin: "built-in", hub: "hub", custom: "custom" };

function invalidate() {
  void queryClient.invalidateQueries({ queryKey: ["hubItems"] });
  void queryClient.invalidateQueries({ queryKey: ["hubRollout"] });
}

/** What the log processors run. */
function Rollout() {
  const q = useQuery({ queryKey: ["hubRollout"], queryFn: () => api.hub.getHubRollout({}), refetchInterval: 5_000 });
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
      notifications.show({ color: "teal", message: t("{name}: the log processors receive the change now", { name: it.name }) });
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
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<HubItem | null>(null);
  const q = useQuery({ queryKey: ["hubItems"], queryFn: () => api.hub.listHubItems({}) });
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const it of q.data?.items ?? []) c[it.type] = (c[it.type] ?? 0) + 1;
    return c;
  }, [q.data]);
  const s = search.trim().toLowerCase();
  const items = (q.data?.items ?? []).filter((it) => it.type === type && (!s || it.name.toLowerCase().includes(s) || it.description.toLowerCase().includes(s)));
  const staged = type === "parsers" || type === "postoverflows";
  return (
    <>
      <PageHeader
        title={t("CrowdSec content")}
        description={t("Parsers, scenarios and collections the log processors run. Simulation raises alerts without decisions.")}
      />
      <Stack>
        <Rollout />
        <Paper withBorder p="md" radius="md">
          <Tabs value={type} onChange={(v) => v && setType(v)} mb="sm">
            <Tabs.List>
              {TYPES.map((ty) => (
                <Tabs.Tab key={ty.value} value={ty.value} rightSection={counts[ty.value] ? <Badge size="xs" variant="light">{counts[ty.value]}</Badge> : null}>
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
                    <Table.Th>{t("Item source")}</Table.Th>
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
                      </Table.Td>
                      <Table.Td>
                        <Badge variant="light" color={SOURCE_COLOR[it.source]}>
                          {t(SOURCE_LABEL[it.source] ?? it.source)}
                        </Badge>
                      </Table.Td>
                      <Table.Td>{it.version || "-"}</Table.Td>
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
                        <StateControl item={it} disabled={!access.canAdmin} />
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </Paper>
      </Stack>
      <ItemModal item={open} onClose={() => setOpen(null)} />
    </>
  );
}
