import { useState } from "react";
import { ActionIcon, Group, Paper, Progress, ScrollArea, Stack, Text, TextInput, Tooltip, UnstyledButton } from "@mantine/core";
import { IconMinus, IconPlus, IconSearch } from "@tabler/icons-react";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { api } from "../api/client";
import { rangeTimestamps, type RangeValue } from "./TimeRange";
import { Country } from "./geo";
import { formatNumber, toNumber } from "../lib/format";
import { t } from "../lib/i18n";

/** Facet field -> search field. */
export const FACET_FIELD: Record<string, string> = {
  scenario: "scenario",
  country: "country",
  as_name: "as",
  node: "node",
  direction: "direction",
  origin: "origin",
  machine: "machine",
  value: "value",
  target: "target",
  instance: "instance",
};

const TITLE: Record<string, string> = {
  scenario: "Scenarios",
  country: "Countries",
  as_name: "AS",
  node: "Nodes",
  direction: "Direction",
  origin: "Origins",
  machine: "Machines",
  value: "Sources",
  target: "Targets",
  instance: "Instances",
};

export interface FacetScope {
  query: string;
  range: RangeValue;
  instance: string;
  includeSimulated: boolean;
}

function FacetCard(props: { field: string; scope: FacetScope; initial?: { value: string; count: bigint }[]; onAdd: (field: string, value: string, negate: boolean) => void }) {
  const [prefix, setPrefix] = useState("");
  const search = useQuery({
    queryKey: ["facet", props.field, props.scope, prefix],
    enabled: prefix !== "",
    placeholderData: keepPreviousData,
    queryFn: async () =>
      (
        await api.alerts.facets({
          query: props.scope.query,
          ...rangeTimestamps(props.scope.range),
          instance: props.scope.instance,
          includeSimulated: props.scope.includeSimulated,
          fields: [props.field],
          valuePrefix: prefix,
          limit: 20,
        })
      ).facets[0]?.values ?? [],
  });
  const values = prefix ? (search.data ?? []) : (props.initial ?? []);
  const max = Math.max(1, ...values.map((v) => toNumber(v.count)));
  const searchField = FACET_FIELD[props.field];
  return (
    <Paper withBorder p="xs" radius="md">
      <Group justify="space-between" mb={4} wrap="nowrap">
        <Text size="sm" fw={600}>
          {t(TITLE[props.field] ?? props.field)}
        </Text>
        <TextInput
          size="xs"
          w={120}
          leftSection={<IconSearch size={12} />}
          placeholder={t("Filter")}
          value={prefix}
          onChange={(e) => setPrefix(e.currentTarget.value)}
        />
      </Group>
      <ScrollArea.Autosize mah={220}>
        <Stack gap={2}>
          {values.length === 0 && (
            <Text size="xs" c="dimmed">
              {t("No values")}
            </Text>
          )}
          {values.map((v) => (
            <Group key={v.value} gap={4} wrap="nowrap" className="facet-row">
              <UnstyledButton style={{ flex: 1, minWidth: 0 }} onClick={() => props.onAdd(searchField, v.value, false)}>
                <Group justify="space-between" gap={4} wrap="nowrap">
                  <Text size="xs" truncate style={{ minWidth: 0 }}>
                    {props.field === "country" ? <Country cc={v.value} size="xs" name /> : v.value || <i>{t("(empty)")}</i>}
                  </Text>
                  <Text size="xs" c="dimmed" style={{ flex: "none" }}>
                    {formatNumber(v.count)}
                  </Text>
                </Group>
                <Progress value={(toNumber(v.count) / max) * 100} size={3} mt={1} />
              </UnstyledButton>
              <Tooltip label={t("Only this")} withArrow openDelay={400}>
                <ActionIcon size="xs" variant="subtle" onClick={() => props.onAdd(searchField, v.value, false)}>
                  <IconPlus size={12} />
                </ActionIcon>
              </Tooltip>
              <Tooltip label={t("Exclude")} withArrow openDelay={400}>
                <ActionIcon size="xs" variant="subtle" color="red" onClick={() => props.onAdd(searchField, v.value, true)}>
                  <IconMinus size={12} />
                </ActionIcon>
              </Tooltip>
            </Group>
          ))}
        </Stack>
      </ScrollArea.Autosize>
    </Paper>
  );
}

/**
 * Quick filters: counts per value of each field for the current search
 * (each facet ignores its own clause, so the other values stay visible).
 */
export function Facets(props: { scope: FacetScope; fields?: string[]; onAdd: (field: string, value: string, negate: boolean) => void }) {
  const fields = props.fields ?? ["scenario", "country", "as_name", "node", "direction", "origin", "target"];
  const q = useQuery({
    queryKey: ["facets", props.scope, fields],
    placeholderData: keepPreviousData,
    queryFn: async () =>
      (
        await api.alerts.facets({
          query: props.scope.query,
          ...rangeTimestamps(props.scope.range),
          instance: props.scope.instance,
          includeSimulated: props.scope.includeSimulated,
          fields,
          limit: 8,
        })
      ).facets,
  });
  const byField = Object.fromEntries((q.data ?? []).map((f) => [f.field, f.values]));
  return (
    <Stack gap="xs">
      {fields.map((f) => (
        <FacetCard key={f} field={f} scope={props.scope} initial={byField[f]} onAdd={props.onAdd} />
      ))}
    </Stack>
  );
}
