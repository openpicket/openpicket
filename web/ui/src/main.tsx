import { StrictMode, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { createTheme, localStorageColorSchemeManager, MantineProvider } from "@mantine/core";
import { DatesProvider } from "@mantine/dates";
import { Notifications } from "@mantine/notifications";
import { ModalsProvider } from "@mantine/modals";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router";
import "dayjs/locale/ko";
import "@mantine/core/styles.css";
import "@mantine/charts/styles.css";
import "@mantine/dates/styles.css";
import "@mantine/dropzone/styles.css";
import "@mantine/notifications/styles.css";
import "./global.css";
import { queryClient } from "./api/queryClient";
import { useUISettings } from "./api/hooks";
import { router } from "./router";
import { t, useLanguage } from "./lib/i18n";

const colorSchemeManager = localStorageColorSchemeManager({ key: "openpicket-color-scheme" });

const theme = createTheme({
  primaryColor: "blue",
  defaultRadius: "sm",
  fontFamilyMonospace: "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace",
});

function Themed(props: { children: ReactNode }) {
  // Loads the server defaults (language, time zone) for the formatters.
  useUISettings();
  const lang = useLanguage();
  return (
    <MantineProvider theme={theme} defaultColorScheme="auto" colorSchemeManager={colorSchemeManager}>
      <DatesProvider settings={{ locale: lang, firstDayOfWeek: 1 }}>
        <ModalsProvider labels={{ confirm: t("Confirm"), cancel: t("Cancel") }}>
          <Notifications position="top-right" limit={5} />
          {props.children}
        </ModalsProvider>
      </DatesProvider>
    </MantineProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <Themed>
        <RouterProvider router={router} />
      </Themed>
    </QueryClientProvider>
  </StrictMode>,
);
