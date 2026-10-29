import { type ReactNode, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Group,
  NumberInput,
  Paper,
  PasswordInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Text,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { Dropzone } from "@mantine/dropzone";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconAlertTriangle, IconCloudDownload, IconDatabase, IconDeviceFloppy, IconSearch, IconTrash, IconUpload, IconX } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, uploadGeoDatabase } from "../api/client";
import { errorMessage } from "../api/errors";
import { useAccess } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import { CopyIcon, EmptyState, ErrorAlert, KeyValue, LoadingBlock, PageHeader, TimeAgo, TimeLeft } from "../components/common";
import { Country } from "../components/geo";
import type { GetGeoUpdateSettingsResponse, GeoUpdateStatus } from "../gen/openpicket/api/v1/policies_pb";
import { formatBytes, formatDateTime, tsDate } from "../lib/format";
import { t } from "../lib/i18n";

function invalidateGeo() {
  void queryClient.invalidateQueries({ queryKey: ["geoDatabases"] });
  void queryClient.invalidateQueries({ queryKey: ["geoUpdate"] });
  // Bundles and previews depend on the geo data.
  void queryClient.invalidateQueries({ queryKey: ["bundlePreview"] });
  void queryClient.invalidateQueries({ queryKey: ["nodes"] });
}

function Upload() {
  const upload = useMutation({
    mutationFn: (file: File) => uploadGeoDatabase(file),
    meta: { silent: true },
    onSuccess: (res) => {
      invalidateGeo();
      notifications.show({ color: "teal", message: t("Uploaded the {kind} database ({type})", { kind: res.kind, type: res.database_type }) });
    },
    onError: (err) => notifications.show({ color: "red", title: t("Upload failed"), message: errorMessage(err), autoClose: 8000 }),
  });
  return (
    <Dropzone
      onDrop={(files) => files[0] && upload.mutate(files[0])}
      onReject={() => notifications.show({ color: "red", message: t("Drop one .mmdb file of at most 256 MB") })}
      maxFiles={1}
      maxSize={256 * 1024 * 1024}
      multiple={false}
      loading={upload.isPending}
      accept={{ "application/octet-stream": [".mmdb"] }}
    >
      <Group justify="center" gap="lg" mih={110} style={{ pointerEvents: "none" }}>
        <Dropzone.Accept>
          <IconUpload size={40} stroke={1.4} />
        </Dropzone.Accept>
        <Dropzone.Reject>
          <IconX size={40} stroke={1.4} />
        </Dropzone.Reject>
        <Dropzone.Idle>
          <IconDatabase size={40} stroke={1.4} />
        </Dropzone.Idle>
        <div>
          <Text size="lg">{t("Drop a MaxMind database here or click to select it")}</Text>
          <Text size="sm" c="dimmed" mt={4}>
            {t("GeoLite2/GeoIP2 Country (or City) and ASN .mmdb files. The kind is read from the file; an upload replaces the database of that kind.")}
          </Text>
        </div>
      </Group>
    </Dropzone>
  );
}

function UpdateStatus(props: { status?: GeoUpdateStatus; enabled: boolean }) {
  const st = props.status;
  return (
    <Stack gap="sm">
      {st?.lastError && (
        <Alert color="red" icon={<IconAlertTriangle size={18} />} title={t("The last check failed")}>
          <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>
            {st.lastError}
          </Text>
        </Alert>
      )}
      <KeyValue
        labelWidth={130}
        rows={[
          [t("Last check"), <TimeAgo ts={st?.lastCheckAt} />],
          [t("Last download"), <TimeAgo ts={st?.lastDownloadAt} />],
          [
            t("Next check"),
            !props.enabled ? (
              <Text span size="sm" c="dimmed">
                {t("disabled")}
              </Text>
            ) : st?.nextCheckAt ? (
              <TimeLeft ts={st.nextCheckAt} />
            ) : (
              <Text span size="sm">
                {t("within a minute")}
              </Text>
            ),
          ],
          ...(st?.editions ?? []).map((e): [string, ReactNode] => [
            e.edition,
            <Tooltip label={`SHA-256 ${e.sha256}`} withArrow openDelay={300}>
              <Text span size="sm" ff="monospace">
                {e.file || e.sha256.slice(0, 12)}
              </Text>
            </Tooltip>,
          ]),
        ]}
      />
    </Stack>
  );
}

function AutoUpdateForm(props: { data: GetGeoUpdateSettingsResponse; canAdmin: boolean }) {
  const cur = props.data.settings;
  const [enabled, setEnabled] = useState(cur?.enabled ?? false);
  const [licenseKey, setLicenseKey] = useState("");
  const [country, setCountry] = useState(cur?.countryEdition ?? "");
  const [asn, setAsn] = useState(cur?.asnEdition ?? "");
  const [hours, setHours] = useState<number>(cur?.intervalHours || 24);
  const keySet = cur?.licenseKeySet ?? false;
  const ro = !props.canAdmin;
  const none = { value: "", label: t("None") };
  const save = useMutation({
    mutationFn: () =>
      api.geo.setUpdateSettings({
        settings: { enabled, countryEdition: country, asnEdition: asn, intervalHours: hours },
        licenseKey,
      }),
    meta: { errorTitle: t("Could not save the settings") },
    onSuccess: () => {
      setLicenseKey("");
      void queryClient.invalidateQueries({ queryKey: ["geoUpdate"] });
      notifications.show({ color: "teal", message: t("Saved the download settings") });
    },
  });
  const run = useMutation({
    mutationFn: () => api.geo.runUpdate({}),
    meta: { errorTitle: t("Download failed") },
    onSuccess: (res) => {
      invalidateGeo();
      if (res.status?.lastError) {
        notifications.show({ color: "red", title: t("Download failed"), message: res.status.lastError, autoClose: 8000 });
      } else {
        notifications.show({ color: "teal", message: t("The databases are up to date") });
      }
    },
  });
  const dirty =
    licenseKey !== "" || enabled !== cur?.enabled || country !== cur?.countryEdition || asn !== cur?.asnEdition || hours !== cur?.intervalHours;
  return (
    <SimpleGrid cols={{ base: 1, md: 2 }} spacing="xl">
      <Stack gap="sm">
        <Switch
          label={t("Download periodically")}
          description={t("Checks MaxMind every interval and stores a new release like an upload, replacing the database of that kind.")}
          checked={enabled}
          onChange={(e) => setEnabled(e.currentTarget.checked)}
          disabled={ro}
        />
        <PasswordInput
          label={t("License key")}
          description={t("A MaxMind license key (GeoLite2 keys are free: maxmind.com, Manage License Keys).")}
          placeholder={keySet ? t("Stored; leave empty to keep it.") : undefined}
          value={licenseKey}
          onChange={(e) => setLicenseKey(e.currentTarget.value)}
          required={enabled && !keySet}
          disabled={ro}
          autoComplete="off"
        />
        <Group grow align="flex-start">
          <Select
            label={t("Country database")}
            data={[none, ...props.data.countryEditions.map((e) => ({ value: e, label: e }))]}
            value={country}
            onChange={(v) => setCountry(v ?? "")}
            allowDeselect={false}
            disabled={ro}
          />
          <Select
            label={t("ASN database")}
            data={[none, ...props.data.asnEditions.map((e) => ({ value: e, label: e }))]}
            value={asn}
            onChange={(v) => setAsn(v ?? "")}
            allowDeselect={false}
            disabled={ro}
          />
        </Group>
        <NumberInput
          label={t("Check every (hours)")}
          description={t("GeoLite2 releases come out twice a week; checks that find no new release download nothing.")}
          min={1}
          max={720}
          value={hours}
          onChange={(v) => setHours(Number(v) || 1)}
          disabled={ro}
          maw={480}
        />
        {props.canAdmin && (
          <Group mt="xs">
            <Button leftSection={<IconDeviceFloppy size={16} />} onClick={() => save.mutate()} loading={save.isPending} disabled={!dirty}>
              {t("Save")}
            </Button>
            <Tooltip label={t("Save a license key first")} disabled={keySet} withArrow>
              <Button
                variant="default"
                leftSection={<IconCloudDownload size={16} />}
                onClick={() => run.mutate()}
                loading={run.isPending}
                disabled={!keySet || dirty}
              >
                {t("Download now")}
              </Button>
            </Tooltip>
          </Group>
        )}
      </Stack>
      <UpdateStatus status={props.data.status} enabled={(cur?.enabled ?? false) && keySet} />
    </SimpleGrid>
  );
}

function AutoUpdate(props: { canAdmin: boolean }) {
  const q = useQuery({ queryKey: ["geoUpdate"], queryFn: () => api.geo.getUpdateSettings({}) });
  const s = q.data?.settings;
  return (
    <Paper withBorder p="md" radius="md">
      <Group justify="space-between" mb="sm">
        <Title order={5}>{t("Automatic download")}</Title>
        {s && (
          <Badge variant="light" color={s.enabled && s.licenseKeySet ? "teal" : "gray"}>
            {s.enabled && s.licenseKeySet ? t("Enabled") : t("Disabled")}
          </Badge>
        )}
      </Group>
      {q.isPending ? (
        <LoadingBlock h={120} />
      ) : q.isError ? (
        <ErrorAlert error={q.error} onRetry={() => q.refetch()} />
      ) : (
        // Remount after a save so the form shows the stored settings.
        <AutoUpdateForm key={`${s?.updatedAt?.seconds}`} data={q.data} canAdmin={props.canAdmin} />
      )}
    </Paper>
  );
}

function Lookup() {
  const [text, setText] = useState("");
  const ips = text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const lookup = useMutation({
    mutationFn: () => api.geo.lookup({ ips: ips.slice(0, 1000) }),
    meta: { errorTitle: t("Lookup failed") },
  });
  return (
    <Paper withBorder p="md" radius="md">
      <Title order={5} mb="sm">
        {t("Lookup")}
      </Title>
      <Stack>
        <Textarea
          placeholder={"198.51.100.4\n2001:db8::1"}
          description={t("One address per line (at most 1000)")}
          value={text}
          onChange={(e) => setText(e.currentTarget.value)}
          autosize
          minRows={3}
          maxRows={10}
          className="mono-input"
        />
        <Group>
          <Button leftSection={<IconSearch size={16} />} disabled={ips.length === 0} loading={lookup.isPending} onClick={() => lookup.mutate()}>
            {t("Look up")}
          </Button>
        </Group>
        {lookup.data && (
          <Table.ScrollContainer minWidth={500}>
            <Table verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("Address")}</Table.Th>
                  <Table.Th>{t("Country")}</Table.Th>
                  <Table.Th>{t("ASN")}</Table.Th>
                  <Table.Th>{t("AS organization")}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {lookup.data.results.map((r, i) => (
                  <Table.Tr key={i}>
                    <Table.Td ff="monospace">{r.ip}</Table.Td>
                    <Table.Td>
                      <Country cc={r.country} name />
                    </Table.Td>
                    <Table.Td>{r.asn ? `AS${r.asn}` : "-"}</Table.Td>
                    <Table.Td>{r.asOrg || "-"}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Stack>
    </Paper>
  );
}

export default function GeoIpPage() {
  const access = useAccess();
  const dbs = useQuery({ queryKey: ["geoDatabases"], queryFn: () => api.geo.listDatabases({}) });
  const remove = useMutation({
    mutationFn: (kind: string) => api.geo.deleteDatabase({ kind }),
    meta: { errorTitle: t("Could not delete the database") },
    onSuccess: (_r, kind) => {
      invalidateGeo();
      notifications.show({ color: "teal", message: t("Deleted the {kind} database", { kind }) });
    },
  });
  const kinds = new Set((dbs.data?.databases ?? []).map((d) => d.kind));
  const missing = ["country", "asn"].filter((k) => !kinds.has(k));
  return (
    <>
      <PageHeader
        title={t("GeoIP")}
        description={t("MaxMind databases uploaded or downloaded here are the only GeoIP source: log enrichment, country and AS port policies, and the UI use them.")}
      />
      <Stack>
        {dbs.isPending ? (
          <LoadingBlock />
        ) : dbs.isError ? (
          <ErrorAlert error={dbs.error} onRetry={() => dbs.refetch()} />
        ) : (
          <>
            {missing.length > 0 && (
              <Alert color="orange" icon={<IconAlertTriangle size={18} />} title={t("Missing databases")}>
                {missing.includes("country") && <Text size="sm">{t("No country database: policy rules by country are skipped and sources have no country.")}</Text>}
                {missing.includes("asn") && <Text size="sm">{t("No ASN database: policy rules by AS number are skipped and sources have no AS.")}</Text>}
              </Alert>
            )}
            {dbs.data.databases.length === 0 ? (
              <EmptyState title={t("No database uploaded")} />
            ) : (
              <Table.ScrollContainer minWidth={800}>
                <Table verticalSpacing="xs">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{t("Kind")}</Table.Th>
                      <Table.Th>{t("Type")}</Table.Th>
                      <Table.Th>{t("Build time")}</Table.Th>
                      <Table.Th>SHA-256</Table.Th>
                      <Table.Th>{t("Size")}</Table.Th>
                      <Table.Th>{t("Uploaded")}</Table.Th>
                      <Table.Th />
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {dbs.data.databases.map((d) => (
                      <Table.Tr key={d.kind}>
                        <Table.Td>
                          <Badge variant="light">{t(d.kind)}</Badge>
                        </Table.Td>
                        <Table.Td>{d.databaseType}</Table.Td>
                        <Table.Td>
                          <Text size="sm">{formatDateTime(tsDate(d.buildTime))}</Text>
                        </Table.Td>
                        <Table.Td>
                          <Group gap={4} wrap="nowrap">
                            <Tooltip label={d.sha256} withArrow>
                              <Text size="sm" ff="monospace">
                                {d.sha256.slice(0, 12)}
                              </Text>
                            </Tooltip>
                            <CopyIcon value={d.sha256} />
                          </Group>
                        </Table.Td>
                        <Table.Td>{formatBytes(d.size)}</Table.Td>
                        <Table.Td>
                          <TimeAgo ts={d.uploadedAt} size="xs" />
                          <Text size="xs" c="dimmed">
                            {d.uploadedBy}
                          </Text>
                        </Table.Td>
                        <Table.Td>
                          {access.canAdmin && (
                            <ActionIcon
                              variant="subtle"
                              color="red"
                              aria-label={t("Delete")}
                              onClick={() =>
                                modals.openConfirmModal({
                                  title: t("Delete the {kind} database?", { kind: d.kind }),
                                  children: <Text size="sm">{t("Policies depending on it are skipped on every node with the next bundle.")}</Text>,
                                  labels: { confirm: t("Delete"), cancel: t("Cancel") },
                                  confirmProps: { color: "red" },
                                  onConfirm: () => remove.mutate(d.kind),
                                })
                              }
                            >
                              <IconTrash size={16} />
                            </ActionIcon>
                          )}
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            )}
          </>
        )}
        <AutoUpdate canAdmin={access.canAdmin} />
        {access.canAdmin && <Upload />}
        <Lookup />
      </Stack>
    </>
  );
}
