import type { ReactNode } from "react";
import { Button, Center, Stack } from "@mantine/core";
import { Navigate, useLocation } from "react-router";
import { useAuthInfo } from "../api/hooks";
import { ErrorAlert, LoadingBlock } from "./common";
import { t } from "../lib/i18n";

export function RequireAuth({ children }: { children: ReactNode }) {
  const auth = useAuthInfo();
  const location = useLocation();
  if (auth.isPending) return <LoadingBlock h="100vh" />;
  if (auth.isError && !auth.data) {
    return (
      <Center h="100vh" p="md">
        <Stack w={480}>
          <ErrorAlert error={auth.error} title={t("Cannot reach the OpenPicket manager")} />
          <Button variant="light" onClick={() => auth.refetch()}>
            {t("Retry")}
          </Button>
        </Stack>
      </Center>
    );
  }
  if (!auth.data?.principal) {
    const from = location.pathname + location.search;
    return <Navigate to={`/login?next=${encodeURIComponent(from)}`} replace />;
  }
  return <>{children}</>;
}
