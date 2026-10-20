import { Button, Center, Stack, Text, Title } from "@mantine/core";
import { isRouteErrorResponse, Link, useRouteError } from "react-router";
import { t } from "../lib/i18n";

export function RouteError() {
  const err = useRouteError();
  const msg = isRouteErrorResponse(err) ? `${err.status} ${err.statusText}` : err instanceof Error ? err.message : String(err);
  return (
    <Center h="80vh">
      <Stack align="center">
        <Title order={3}>{t("Something went wrong")}</Title>
        <Text c="dimmed" size="sm" maw={600} ta="center">
          {msg}
        </Text>
        <Button component={Link} to="/" variant="light">
          {t("Back to the dashboard")}
        </Button>
      </Stack>
    </Center>
  );
}
