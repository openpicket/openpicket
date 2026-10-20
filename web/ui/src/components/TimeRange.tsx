import { useState } from "react";
import { Button, Group, Popover, Select, Stack } from "@mantine/core";
import { DateTimePicker } from "@mantine/dates";
import { timestampFromDate, type Timestamp } from "@bufbuild/protobuf/wkt";
import { formatDateTime } from "../lib/format";
import { t } from "../lib/i18n";

/** A preset ("24h") or a custom range ("<from ms>~<to ms>"). */
export type RangeValue = string;

export const PRESETS: { value: string; label: string; ms: number }[] = [
  { value: "1h", label: "Last hour", ms: 3600e3 },
  { value: "6h", label: "Last 6 hours", ms: 6 * 3600e3 },
  { value: "24h", label: "Last 24 hours", ms: 24 * 3600e3 },
  { value: "7d", label: "Last 7 days", ms: 7 * 86400e3 },
  { value: "30d", label: "Last 30 days", ms: 30 * 86400e3 },
];

export function rangeBounds(v: RangeValue, now = Date.now()): { from: Date; to: Date } {
  if (v.includes("~")) {
    const [a, b] = v.split("~").map(Number);
    return { from: new Date(a), to: new Date(b) };
  }
  const p = PRESETS.find((x) => x.value === v) ?? PRESETS[2];
  return { from: new Date(now - p.ms), to: new Date(now) };
}

export function rangeTimestamps(v: RangeValue): { from: Timestamp; to: Timestamp } {
  const b = rangeBounds(v);
  return { from: timestampFromDate(b.from), to: timestampFromDate(b.to) };
}

/** Preset or custom time range. */
export function TimeRange(props: { value: RangeValue; onChange: (v: RangeValue) => void; w?: number }) {
  const custom = props.value.includes("~");
  const [open, setOpen] = useState(false);
  const b = rangeBounds(props.value);
  const [from, setFrom] = useState<Date | null>(b.from);
  const [to, setTo] = useState<Date | null>(b.to);
  const data = [
    ...PRESETS.map((p) => ({ value: p.value, label: t(p.label) })),
    { value: "custom", label: custom ? `${formatDateTime(b.from)} – ${formatDateTime(b.to)}` : t("Custom range…") },
  ];
  return (
    <Popover opened={open} onChange={setOpen} position="bottom-end" shadow="md">
      <Popover.Target>
        <Select
          w={props.w ?? 200}
          data={data}
          value={custom ? "custom" : props.value}
          allowDeselect={false}
          onChange={(v) => {
            if (v === "custom") setOpen(true);
            else if (v) props.onChange(v);
          }}
          comboboxProps={{ width: 260, position: "bottom-end" }}
        />
      </Popover.Target>
      <Popover.Dropdown>
        <Stack gap="xs" w={260}>
          <DateTimePicker label={t("From")} value={from} onChange={(v) => setFrom(v ? new Date(v) : null)} withSeconds={false} />
          <DateTimePicker label={t("To")} value={to} onChange={(v) => setTo(v ? new Date(v) : null)} withSeconds={false} />
          <Group justify="flex-end">
            <Button variant="default" size="xs" onClick={() => setOpen(false)}>
              {t("Cancel")}
            </Button>
            <Button
              size="xs"
              disabled={!from || !to || from >= to}
              onClick={() => {
                props.onChange(`${from!.getTime()}~${to!.getTime()}`);
                setOpen(false);
              }}
            >
              {t("Apply")}
            </Button>
          </Group>
        </Stack>
      </Popover.Dropdown>
    </Popover>
  );
}
