import { Group, Text } from "@mantine/core";
import { IconShieldHalfFilled } from "@tabler/icons-react";

export function Brand(props: { size?: "md" | "lg" | "xl" }) {
  const h = props.size === "xl" ? 40 : 26;
  return (
    <Group gap={8} wrap="nowrap">
      <IconShieldHalfFilled size={h} color="var(--mantine-primary-color-filled)" />
      <Text fw={700} size={props.size ?? "lg"}>
        OpenPicket
      </Text>
    </Group>
  );
}
