import { Group, Text, Tooltip, type MantineSize } from "@mantine/core";
import { countryName, flag } from "../lib/countries";

export function Country(props: { cc?: string; size?: MantineSize; name?: boolean }) {
  if (!props.cc) {
    return (
      <Text span size={props.size ?? "sm"} c="dimmed">
        -
      </Text>
    );
  }
  const name = countryName(props.cc);
  return (
    <Tooltip label={name} withArrow openDelay={300} disabled={props.name}>
      <Group gap={4} wrap="nowrap" component="span" style={{ display: "inline-flex" }}>
        <span aria-hidden>{flag(props.cc)}</span>
        <Text span size={props.size ?? "sm"}>
          {props.name ? name : props.cc}
        </Text>
      </Group>
    </Tooltip>
  );
}
