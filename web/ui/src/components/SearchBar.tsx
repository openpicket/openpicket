import { useEffect, useState } from "react";
import {
  ActionIcon,
  Badge,
  Button,
  Checkbox,
  Code,
  Divider,
  Group,
  Menu,
  Modal,
  Popover,
  ScrollArea,
  Stack,
  Table,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { IconBookmark, IconHistory, IconInfoCircle, IconSearch, IconTrash, IconX } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { queryClient } from "../api/queryClient";
import { useAccess } from "../api/hooks";
import { SYNTAX, type FieldDoc } from "../lib/searchFields";
import { t } from "../lib/i18n";

function SyntaxHelp(props: { fields: FieldDoc[]; onPick: (example: string) => void }) {
  return (
    <ScrollArea.Autosize mah={460}>
      <Stack gap="xs" p={4} maw={520}>
        <Text fw={600} size="sm">
          {t("Search syntax")}
        </Text>
        <Table withRowBorders={false} verticalSpacing={2} fz="sm">
          <Table.Tbody>
            {SYNTAX.map(([ex, d]) => (
              <Table.Tr key={ex}>
                <Table.Td w={190}>
                  <Code>{ex}</Code>
                </Table.Td>
                <Table.Td>{t(d)}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        <Divider />
        <Text fw={600} size="sm">
          {t("Fields")}
        </Text>
        <Table withRowBorders={false} verticalSpacing={2} fz="sm">
          <Table.Tbody>
            {props.fields.map((f) => (
              <Table.Tr key={f.name}>
                <Table.Td w={110}>
                  <Code>{f.name}</Code>
                </Table.Td>
                <Table.Td>
                  {t(f.description)}{" "}
                  {f.example && (
                    <Text span size="xs" c="blue" style={{ cursor: "pointer" }} onClick={() => props.onPick(f.example!)}>
                      {f.example}
                    </Text>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Stack>
    </ScrollArea.Autosize>
  );
}

function SaveFilterModal(props: { opened: boolean; onClose: () => void; page: string; query: string }) {
  const [name, setName] = useState("");
  const [shared, setShared] = useState(false);
  const access = useAccess();
  const save = useMutation({
    mutationFn: () => api.system.saveFilter({ filter: { page: props.page, name, query: props.query, shared } }),
    meta: { errorTitle: t("Could not save the filter") },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["savedFilters", props.page] });
      setName("");
      props.onClose();
    },
  });
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={t("Save filter")}>
      <Stack>
        <Code block>{props.query}</Code>
        <TextInput label={t("Name")} value={name} onChange={(e) => setName(e.currentTarget.value)} data-autofocus required />
        {access.isOperator && (
          <Checkbox label={t("Share with every user")} checked={shared} onChange={(e) => setShared(e.currentTarget.checked)} />
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={props.onClose}>
            {t("Cancel")}
          </Button>
          <Button disabled={!name.trim()} loading={save.isPending} onClick={() => save.mutate()}>
            {t("Save")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

/**
 * Query input of the search language with syntax help, saved filters and
 * recent queries. onSearch runs on Enter or when a saved/recent query is
 * picked.
 */
export function SearchBar(props: {
  page: "alerts" | "decisions" | "logs";
  value: string;
  onSearch: (q: string) => void;
  fields: FieldDoc[];
  placeholder?: string;
  error?: string;
}) {
  const [draft, setDraft] = useState(props.value);
  const [help, setHelp] = useState(false);
  const [saving, setSaving] = useState(false);
  useEffect(() => setDraft(props.value), [props.value]);
  const saved = useQuery({
    queryKey: ["savedFilters", props.page],
    queryFn: async () => (await api.system.listSavedFilters({ page: props.page })).filters,
    staleTime: 60_000,
  });
  const recent = useQuery({
    queryKey: ["recentQueries", props.page],
    queryFn: async () => (await api.system.listRecentQueries({ page: props.page })).queries,
    staleTime: 30_000,
  });
  const remember = useMutation({
    mutationFn: (q: string) => api.system.addRecentQuery({ page: props.page, query: q }),
    meta: { silent: true },
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["recentQueries", props.page] }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.system.deleteSavedFilter({ id }),
    meta: { errorTitle: t("Could not delete the filter") },
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["savedFilters", props.page] }),
  });
  const run = (q: string) => {
    setDraft(q);
    props.onSearch(q.trim());
    if (q.trim()) remember.mutate(q.trim());
  };
  return (
    <>
      <Group gap="xs" wrap="nowrap" align="flex-start" style={{ flex: 1, minWidth: 260 }}>
        <TextInput
          style={{ flex: 1 }}
          leftSection={<IconSearch size={16} />}
          placeholder={props.placeholder ?? t("Search… (Enter)")}
          value={draft}
          error={props.error}
          onChange={(e) => setDraft(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") run(draft);
            if (e.key === "Escape") setDraft(props.value);
          }}
          className="mono-input"
          rightSectionWidth={draft ? 62 : 34}
          rightSection={
            <Group gap={2} wrap="nowrap">
              {draft && (
                <ActionIcon variant="subtle" color="gray" size="sm" onClick={() => run("")} aria-label={t("Clear")}>
                  <IconX size={14} />
                </ActionIcon>
              )}
              <Popover opened={help} onChange={setHelp} position="bottom-end" shadow="md" width={540}>
                <Popover.Target>
                  <ActionIcon variant="subtle" color="gray" size="sm" onClick={() => setHelp((h) => !h)} aria-label={t("Search syntax")}>
                    <IconInfoCircle size={16} />
                  </ActionIcon>
                </Popover.Target>
                <Popover.Dropdown>
                  <SyntaxHelp
                    fields={props.fields}
                    onPick={(ex) => {
                      setDraft((d) => (d.trim() ? `${d.trim()} ${ex}` : ex));
                      setHelp(false);
                    }}
                  />
                </Popover.Dropdown>
              </Popover>
            </Group>
          }
        />
        <Menu position="bottom-end" withArrow width={320}>
          <Menu.Target>
            <Tooltip label={t("Saved filters and recent searches")} withArrow>
              <ActionIcon variant="default" size="lg">
                <IconBookmark size={18} />
              </ActionIcon>
            </Tooltip>
          </Menu.Target>
          <Menu.Dropdown>
            <Menu.Label>{t("Saved filters")}</Menu.Label>
            {(saved.data ?? []).length === 0 && <Menu.Item disabled>{t("None yet")}</Menu.Item>}
            {(saved.data ?? []).map((f) => (
              <Menu.Item
                key={f.id}
                onClick={() => run(f.query)}
                rightSection={
                  <Group gap={4} wrap="nowrap">
                    {f.shared && (
                      <Badge size="xs" variant="light">
                        {t("shared")}
                      </Badge>
                    )}
                    <ActionIcon
                      size="xs"
                      variant="subtle"
                      color="red"
                      onClick={(e) => {
                        e.stopPropagation();
                        remove.mutate(f.id);
                      }}
                      aria-label={t("Delete")}
                    >
                      <IconTrash size={12} />
                    </ActionIcon>
                  </Group>
                }
              >
                <Text size="sm" truncate>
                  {f.name}
                </Text>
              </Menu.Item>
            ))}
            <Menu.Item leftSection={<IconBookmark size={14} />} disabled={!props.value} onClick={() => setSaving(true)}>
              {t("Save current search…")}
            </Menu.Item>
            <Menu.Divider />
            <Menu.Label>{t("Recent searches")}</Menu.Label>
            {(recent.data ?? []).length === 0 && <Menu.Item disabled>{t("None yet")}</Menu.Item>}
            {(recent.data ?? []).map((q) => (
              <Menu.Item key={q} leftSection={<IconHistory size={14} />} onClick={() => run(q)}>
                <Text size="sm" ff="monospace" truncate>
                  {q}
                </Text>
              </Menu.Item>
            ))}
          </Menu.Dropdown>
        </Menu>
      </Group>
      <SaveFilterModal opened={saving} onClose={() => setSaving(false)} page={props.page} query={props.value} />
    </>
  );
}
