import { useEffect, useState } from "react";
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Checkbox,
  Group,
  Modal,
  Paper,
  SegmentedControl,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Textarea,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconExternalLink, IconPlus, IconSearch, IconX } from "@tabler/icons-react";
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../api/client";
import { queryClient } from "../api/queryClient";
import { useAccess } from "../api/hooks";
import type { IOC } from "../gen/openpicket/api/v1/intel_pb";
import { EmptyState, ErrorAlert, LoadingBlock, PageHeader, TimeAgo, TimeLeft } from "../components/common";
import { Country } from "../components/geo";
import { Scenario } from "../components/crowdsec";
import { formatNumber, toNumber } from "../lib/format";
import { useUrlState } from "../lib/urlState";
import { t } from "../lib/i18n";

const TTLS = ["7d", "30d", "90d", "180d", "365d"];

const stateColor: Record<string, string> = { proposed: "blue", approved: "red", rejected: "gray", revoked: "gray" };

export function IocState(props: { state: string }) {
  return (
    <Badge color={stateColor[props.state] ?? "gray"} variant="light" size="sm">
      {t(props.state)}
    </Badge>
  );
}

/** Proposes an address to MISP. */
export function ProposeModal(props: { opened: boolean; onClose: () => void; value?: string }) {
  const [value, setValue] = useState(props.value ?? "");
  const [type, setType] = useState("ip-src");
  const [comment, setComment] = useState("");
  useEffect(() => {
    if (props.opened) setValue(props.value ?? "");
  }, [props.opened, props.value]);
  const propose = useMutation({
    mutationFn: () => api.intel.proposeIOC({ value: value.trim(), type, comment }),
    meta: { errorTitle: t("Could not propose to MISP") },
    onSuccess: () => {
      notifications.show({ color: "teal", message: t("{value} proposed to MISP", { value }) });
      void queryClient.invalidateQueries({ queryKey: ["iocs"] });
      props.onClose();
    },
  });
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={t("Propose to MISP")}>
      <Stack>
        <TextInput label={t("IP address or range")} value={value} onChange={(e) => setValue(e.currentTarget.value)} className="mono-input" data-autofocus />
        <Select
          label={t("Attribute type")}
          data={[
            { value: "ip-src", label: t("ip-src: attacker (blocks inbound)") },
            { value: "ip-dst", label: t("ip-dst: C2 or malware host (blocks both ways)") },
          ]}
          value={type}
          onChange={(v) => setType(v ?? "ip-src")}
          allowDeselect={false}
        />
        <Textarea label={t("Comment")} value={comment} onChange={(e) => setComment(e.currentTarget.value)} autosize minRows={2} />
        <Text size="sm" c="dimmed">
          {t("The attribute is added to this month's OpenPicket sightings event with to_ids off. Nothing is blocked until it is approved.")}
        </Text>
        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {t("Cancel")}
          </Button>
          <Button disabled={!value.trim()} loading={propose.isPending} onClick={() => propose.mutate()}>
            {t("Propose")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

export default function ApprovalsPage() {
  const access = useAccess();
  const [state, setState] = useUrlState("state", "proposed");
  const [value, setValue] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [ttl, setTtl] = useState("30d");
  const [proposing, setProposing] = useState(false);
  const status = useQuery({ queryKey: ["intelStatus"], queryFn: () => api.intel.getIntelStatus({}), refetchInterval: 30_000 });
  const list = useQuery({
    queryKey: ["iocs", state, value],
    enabled: status.data?.configured === true,
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
    queryFn: () => api.intel.listIOCs({ state: state === "all" ? "" : state, value, limit: 500 }),
  });
  const change = useMutation({
    mutationFn: (v: { uuids: string[]; state: string }) => api.intel.setIOCState({ uuids: v.uuids, state: v.state, ttl }),
    meta: { errorTitle: t("Could not change the MISP attributes") },
    onSuccess: (_, v) => {
      notifications.show({ color: "teal", message: t("{n} attributes {state}", { n: v.uuids.length, state: t(v.state) }) });
      setSelected(new Set());
      void queryClient.invalidateQueries({ queryKey: ["iocs"] });
      void queryClient.invalidateQueries({ queryKey: ["intelStatus"] });
    },
  });
  if (status.isPending) return <LoadingBlock h={300} />;
  if (status.isError) return <ErrorAlert error={status.error} />;
  const st = status.data;
  if (!st.configured) {
    return (
      <>
        <PageHeader title={t("Approvals")} />
        <EmptyState
          title={t("MISP is not configured")}
          description={t(
            "Set OPENPICKET_MISP_URL and OPENPICKET_MISP_API_KEY (or the chart's misp values). Approved MISP attributes become CrowdSec decisions that the edge enforces.",
          )}
        />
      </>
    );
  }
  const iocs = list.data?.iocs ?? [];
  const act = (s: string, uuids: string[]) => change.mutate({ uuids, state: s });
  const all = iocs.length > 0 && iocs.every((i) => selected.has(i.uuid));
  const actions = (i: IOC) => (
    <Group gap={4} wrap="nowrap">
      {i.state !== "approved" && (
        <Tooltip label={t("Approve for {ttl}", { ttl })} withArrow>
          <Button size="compact-xs" color="red" variant="light" leftSection={<IconCheck size={12} />} onClick={() => act("approved", [i.uuid])}>
            {t("Approve")}
          </Button>
        </Tooltip>
      )}
      {i.state === "proposed" && (
        <Button size="compact-xs" variant="subtle" color="gray" leftSection={<IconX size={12} />} onClick={() => act("rejected", [i.uuid])}>
          {t("Reject")}
        </Button>
      )}
      {i.state === "approved" && (
        <Button size="compact-xs" variant="subtle" color="gray" onClick={() => act("revoked", [i.uuid])}>
          {t("Revoke")}
        </Button>
      )}
    </Group>
  );
  return (
    <>
      <PageHeader
        title={t("Approvals")}
        description={t("MISP attributes managed by OpenPicket. Approved ones are blocked at the edge until revoked or their TTL ends; the approval state lives in MISP.")}
        right={
          <>
            <Button variant="default" component="a" href={st.mispUrl} target="_blank" rightSection={<IconExternalLink size={14} />}>
              MISP
            </Button>
            {access.canOperate && (
              <Button leftSection={<IconPlus size={16} />} onClick={() => setProposing(true)}>
                {t("Propose")}
              </Button>
            )}
          </>
        }
      />
      {st.lastError && (
        <Alert color="orange" mb="md" title={t("MISP sync failed")}>
          {st.lastError} — {t("existing decisions stay until they expire.")}
        </Alert>
      )}
      <Group mb="md" gap="lg">
        <Text size="sm">
          {t("Pending")}: <b>{formatNumber(st.proposed)}</b>
        </Text>
        <Text size="sm">
          {t("Enforced")}: <b>{formatNumber(st.active)}</b>
        </Text>
        <Text size="sm" c="dimmed">
          {t("Last sync")}: <TimeAgo ts={st.lastSyncAt} />
        </Text>
        <Text size="sm" c="dimmed">
          {st.proposeMinAlerts > 0
            ? t("Sources with {n}+ alerts are proposed automatically.", { n: st.proposeMinAlerts })
            : t("Automatic proposals are off.")}
        </Text>
      </Group>
      <Group mb="md" justify="space-between" wrap="wrap">
        <Group>
          <SegmentedControl
            value={state}
            onChange={(v) => (setState(v), setSelected(new Set()))}
            data={["proposed", "approved", "rejected", "revoked", "all"].map((s) => ({ value: s, label: t(s) }))}
          />
          <TextInput leftSection={<IconSearch size={14} />} placeholder={t("Value")} value={value} onChange={(e) => setValue(e.currentTarget.value)} w={200} />
        </Group>
        {access.canOperate && (
          <Group>
            <Select w={110} data={TTLS} value={ttl} onChange={(v) => setTtl(v ?? "30d")} allowDeselect={false} aria-label={t("TTL")} />
            <Button color="red" disabled={selected.size === 0} loading={change.isPending} onClick={() => act("approved", [...selected])}>
              {t("Approve {n}", { n: selected.size })}
            </Button>
            <Button variant="default" disabled={selected.size === 0} onClick={() => act("rejected", [...selected])}>
              {t("Reject {n}", { n: selected.size })}
            </Button>
          </Group>
        )}
      </Group>
      {list.isError && <ErrorAlert error={list.error} />}
      {list.isPending && <LoadingBlock />}
      {list.data && iocs.length === 0 && <EmptyState title={t("Nothing here")} description={t("No MISP attribute in this state.")} />}
      {iocs.length > 0 && (
        <Paper withBorder radius="md">
          <Table.ScrollContainer minWidth={1000}>
            <Table fz="sm" verticalSpacing={6} highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  {access.canOperate && (
                    <Table.Th w={32}>
                      <Checkbox size="xs" checked={all} onChange={(e) => setSelected(e.currentTarget.checked ? new Set(iocs.map((i) => i.uuid)) : new Set())} />
                    </Table.Th>
                  )}
                  <Table.Th>{t("Value")}</Table.Th>
                  <Table.Th>{t("State")}</Table.Th>
                  <Table.Th>{t("Evidence")}</Table.Th>
                  <Table.Th>{t("Comment")}</Table.Th>
                  <Table.Th>{t("Expires")}</Table.Th>
                  <Table.Th>{t("Event")}</Table.Th>
                  {access.canOperate && <Table.Th />}
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody style={{ opacity: list.isPlaceholderData ? 0.6 : 1 }}>
                {iocs.map((i) => (
                  <Table.Tr key={i.uuid}>
                    {access.canOperate && (
                      <Table.Td>
                        <Checkbox
                          size="xs"
                          checked={selected.has(i.uuid)}
                          onChange={(e) => {
                            const next = new Set(selected);
                            if (e.currentTarget.checked) next.add(i.uuid);
                            else next.delete(i.uuid);
                            setSelected(next);
                          }}
                        />
                      </Table.Td>
                    )}
                    <Table.Td>
                      <Stack gap={2}>
                        <Anchor component={Link} to={`/ip/${encodeURIComponent(i.value.split("|")[0])}`} ff="monospace" size="sm">
                          {i.value}
                        </Anchor>
                        <Group gap={4}>
                          <Badge size="xs" variant="outline">
                            {i.type}
                          </Badge>
                          {i.country && <Country cc={i.country} size="xs" />}
                          {i.asName && (
                            <Text size="xs" c="dimmed" truncate maw={140}>
                              {i.asName}
                            </Text>
                          )}
                        </Group>
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      <Stack gap={2}>
                        <IocState state={i.state} />
                        {i.state === "approved" && !i.toIds && (
                          <Text size="xs" c="orange">
                            {t("to_ids off")}
                          </Text>
                        )}
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      {toNumber(i.alerts) === 0 ? (
                        <Text size="xs" c="dimmed">
                          {t("no alerts")}
                        </Text>
                      ) : (
                        <Stack gap={2}>
                          <Text size="xs">
                            {t("{n} alerts", { n: formatNumber(i.alerts) })}, <TimeAgo ts={i.lastAlertAt} size="xs" />
                          </Text>
                          {i.scenarios.slice(0, 2).map((s) => (
                            <Text key={s} size="xs">
                              <Scenario name={s} />
                            </Text>
                          ))}
                          {i.nodes.length > 0 && (
                            <Text size="xs" c="dimmed">
                              {i.nodes.join(", ")}
                            </Text>
                          )}
                        </Stack>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" lineClamp={3} maw={320}>
                        {i.comment || "-"}
                      </Text>
                    </Table.Td>
                    <Table.Td>{i.expiresAt ? <TimeLeft ts={i.expiresAt} /> : i.ttl || "-"}</Table.Td>
                    <Table.Td>
                      <Anchor href={`${st.mispUrl}/events/view/${i.eventId}`} target="_blank" size="xs">
                        {i.eventInfo || `#${i.eventId}`}
                      </Anchor>
                    </Table.Td>
                    {access.canOperate && <Table.Td>{actions(i)}</Table.Td>}
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Paper>
      )}
      <ProposeModal opened={proposing} onClose={() => setProposing(false)} />
    </>
  );
}
