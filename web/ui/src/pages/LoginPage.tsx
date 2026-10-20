import { useState } from "react";
import { Alert, Button, Center, Divider, Paper, PasswordInput, Stack, Text, TextInput } from "@mantine/core";
import { IconLock } from "@tabler/icons-react";
import { Navigate, useSearchParams } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAuthInfo } from "../api/hooks";
import { authInfoKey, queryClient } from "../api/queryClient";
import { errorMessage } from "../api/errors";
import { Brand } from "../components/Brand";
import { LoadingBlock } from "../components/common";
import { t, useLanguage } from "../lib/i18n";

/** Only same-origin paths are followed after login. */
function safeNext(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}

export function LoginPage() {
  useLanguage();
  const auth = useAuthInfo();
  const [params] = useSearchParams();
  const next = safeNext(params.get("next"));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const login = useMutation({
    mutationFn: () => api.auth.login({ username, password }),
    meta: { silent: true },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: authInfoKey }).then(() => {
        // Full navigation: /suricata/ paths are served by another app.
        window.location.assign(next);
      });
    },
  });
  if (auth.isPending) return <LoadingBlock h="100vh" />;
  if (auth.data?.principal) {
    if (next.startsWith("/suricata")) {
      window.location.assign(next);
      return <LoadingBlock h="100vh" />;
    }
    return <Navigate to={next} replace />;
  }
  const info = auth.data;
  return (
    <Center mih="100vh" p="md" bg="var(--mantine-color-gray-light)">
      <Paper withBorder shadow="sm" p="xl" radius="md" w={400}>
        <Stack>
          <Center>
            <Brand size="xl" />
          </Center>
          {info?.loginUrl && (
            <Button component="a" href={info.loginUrl} size="md" variant="filled">
              {t("Sign in with single sign-on")}
            </Button>
          )}
          {info?.loginUrl && info.passwordLogin && <Divider label={t("or")} />}
          {info?.passwordLogin ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                login.mutate();
              }}
            >
              <Stack>
                <TextInput label={t("Username")} value={username} onChange={(e) => setUsername(e.currentTarget.value)} autoComplete="username" required data-autofocus />
                <PasswordInput label={t("Password")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoComplete="current-password" required />
                {login.isError && (
                  <Alert color="red" icon={<IconLock size={16} />}>
                    {errorMessage(login.error)}
                  </Alert>
                )}
                <Button type="submit" loading={login.isPending}>
                  {t("Sign in")}
                </Button>
              </Stack>
            </form>
          ) : (
            !info?.loginUrl && (
              <Text size="sm" c="dimmed" ta="center">
                {t("Sign in through the identity proxy in front of OpenPicket, then reload this page.")}
              </Text>
            )
          )}
        </Stack>
      </Paper>
    </Center>
  );
}
