import { useState } from "react";
import { ActionIcon, Alert, Badge, Button, Group, Paper, Stack, Table, Text, Textarea, Title, Tooltip } from "@mantine/core";
import { Dropzone } from "@mantine/dropzone";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconAlertTriangle, IconDatabase, IconSearch, IconTrash, IconUpload, IconX } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, uploadGeoDatabase } from "../api/client";
import { errorMessage } from "../api/errors";
import { useAccess } from "../api/hooks";
import { queryClient } from "../api/queryClient";
import { CopyIcon, EmptyState, ErrorAlert, LoadingBlock, PageHeader, TimeAgo } from "../components/common";
import { Country } from "../components/geo";
import { formatBytes, formatDateTime, tsDate } from "../lib/format";
import { t } from "../lib/i18n";

function invalidateGeo() {
  void queryClient.invalidateQueries({ queryKey: ["geoDatabases"] });
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
        description={t("MaxMind databases uploaded here are the only GeoIP source: log enrichment, country and AS port policies, and the UI use them.")}
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
        {access.canAdmin && <Upload />}
        <Lookup />
      </Stack>
    </>
  );
}
