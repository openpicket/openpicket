import { Suspense } from "react";
import {
  ActionIcon,
  AppShell,
  Badge,
  Burger,
  Group,
  Indicator,
  Menu,
  NavLink,
  ScrollArea,
  Select,
  Text,
  Tooltip,
  UnstyledButton,
  useMantineColorScheme,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconBell,
  IconChartBar,
  IconPuzzle,
  IconChecklist,
  IconChevronDown,
  IconDeviceDesktop,
  IconExternalLink,
  IconFileText,
  IconGauge,
  IconGavel,
  IconLanguage,
  IconLogout,
  IconMapPin,
  IconMoon,
  IconNetwork,
  IconRadar2,
  IconRouter,
  IconSearch,
  IconSettings,
  IconShieldLock,
  IconSun,
  IconUser,
  IconWorld,
  type Icon,
} from "@tabler/icons-react";
import { Link, Outlet, useLocation, useNavigate } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAccess, useAuthInfo, useUnread } from "../api/hooks";
import { authInfoKey, queryClient } from "../api/queryClient";
import { LoadingBlock } from "./common";
import { Brand } from "./Brand";
import { LANGUAGES, t, useLanguage } from "../lib/i18n";
import { setPref } from "../lib/prefs";
import { scope, useInstance } from "../lib/scope";

interface NavItem {
  to: string;
  label: string;
  icon: Icon;
  exact?: boolean;
  feature?: "logs" | "metrics" | "suricata";
  external?: boolean;
}

const NAV: { section: string; items: NavItem[] }[] = [
  { section: "", items: [{ to: "/", label: "Dashboard", icon: IconGauge, exact: true }] },
  {
    section: "Investigate",
    items: [
      { to: "/alerts", label: "Alerts", icon: IconRadar2 },
      { to: "/decisions", label: "Decisions", icon: IconGavel },
      { to: "/approvals", label: "Approvals", icon: IconChecklist },
      { to: "/ip", label: "IP lookup", icon: IconSearch },
      { to: "/logs", label: "Logs", icon: IconFileText, feature: "logs" },
    ],
  },
  {
    section: "Edge",
    items: [
      { to: "/nodes", label: "Nodes", icon: IconRouter },
      { to: "/syslog", label: "Syslog devices", icon: IconNetwork },
      { to: "/policies", label: "Port policies", icon: IconShieldLock },
      { to: "/geoip", label: "GeoIP", icon: IconMapPin },
      { to: "/suricata/", label: "Suricata", icon: IconWorld, feature: "suricata", external: true },
    ],
  },
  {
    section: "Monitor",
    items: [
      { to: "/crowdsec", label: "CrowdSec content", icon: IconPuzzle },
      { to: "/metrics", label: "CrowdSec metrics", icon: IconChartBar, feature: "metrics" },
      { to: "/notifications", label: "Notifications", icon: IconBell },
      { to: "/system", label: "System", icon: IconSettings },
    ],
  },
];

function ColorSchemeToggle() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const next = colorScheme === "auto" ? "light" : colorScheme === "light" ? "dark" : "auto";
  const Icon = colorScheme === "auto" ? IconDeviceDesktop : colorScheme === "light" ? IconSun : IconMoon;
  return (
    <Tooltip label={t("Theme: {theme}", { theme: t(colorScheme) })} withArrow>
      <ActionIcon variant="default" size="lg" onClick={() => setColorScheme(next)} aria-label={t("Toggle color scheme")}>
        <Icon size={18} />
      </ActionIcon>
    </Tooltip>
  );
}

function LanguageMenu() {
  const lang = useLanguage();
  return (
    <Menu position="bottom-end" withArrow>
      <Menu.Target>
        <ActionIcon variant="default" size="lg" aria-label={t("Language")}>
          <IconLanguage size={18} />
        </ActionIcon>
      </Menu.Target>
      <Menu.Dropdown>
        {LANGUAGES.map((l) => (
          <Menu.Item key={l.value} onClick={() => setPref("language", l.value)} fw={l.value === lang ? 700 : undefined}>
            {l.label}
          </Menu.Item>
        ))}
      </Menu.Dropdown>
    </Menu>
  );
}

function NotificationBell() {
  const unread = useUnread();
  const n = Number(unread.data?.unread ?? 0n);
  return (
    <Tooltip label={t("Notifications")} withArrow>
      <Indicator disabled={n === 0} label={n > 99 ? "99+" : n} size={16} offset={4} color="red">
        <ActionIcon component={Link} to="/notifications" variant="default" size="lg" aria-label={t("Notifications")}>
          <IconBell size={18} />
        </ActionIcon>
      </Indicator>
    </Tooltip>
  );
}

function InstanceSelect() {
  const access = useAccess();
  const instance = useInstance();
  const names = access.features?.lapiInstances ?? [];
  if (names.length < 2) return null;
  return (
    <Select
      size="xs"
      w={150}
      aria-label={t("LAPI instance")}
      data={[{ value: "", label: t("All instances") }, ...names.map((n) => ({ value: n, label: n }))]}
      value={instance}
      onChange={(v) => scope.set({ instance: v ?? "" })}
      allowDeselect={false}
      visibleFrom="sm"
    />
  );
}

function UserMenu() {
  const auth = useAuthInfo();
  const navigate = useNavigate();
  const p = auth.data?.principal;
  const logout = useMutation({
    mutationFn: () => api.auth.logout({}),
    meta: { errorTitle: t("Logout failed") },
    onSuccess: (res) => {
      queryClient.clear();
      if (res.redirectUrl) {
        window.location.href = res.redirectUrl;
        return;
      }
      void queryClient.invalidateQueries({ queryKey: authInfoKey });
      navigate("/login", { replace: true });
    },
  });
  return (
    <Menu position="bottom-end" withArrow>
      <Menu.Target>
        <UnstyledButton>
          <Group gap={6} wrap="nowrap">
            <IconUser size={18} />
            <Text size="sm" fw={500} visibleFrom="xs" truncate maw={160}>
              {p?.name || p?.id}
            </Text>
            <IconChevronDown size={14} />
          </Group>
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>{p?.id}</Menu.Label>
        {p?.email && <Menu.Label>{p.email}</Menu.Label>}
        <Menu.Label>
          {t("Role")}: <Badge size="xs">{t(p?.role ?? "")}</Badge>
          {auth.data?.readOnly && (
            <Badge size="xs" color="orange" ml={4}>
              {t("read-only")}
            </Badge>
          )}
        </Menu.Label>
        <Menu.Item component={Link} to="/system?tab=preferences" leftSection={<IconSettings size={16} />}>
          {t("Preferences")}
        </Menu.Item>
        <Menu.Item leftSection={<IconLogout size={16} />} onClick={() => logout.mutate()}>
          {t("Log out")}
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}

function Version() {
  const auth = useAuthInfo();
  return (
    <Text size="xs" c="dimmed" px="sm">
      OpenPicket {auth.data?.version}
    </Text>
  );
}

export function AppLayout() {
  const [opened, { toggle, close }] = useDisclosure();
  const location = useLocation();
  const access = useAccess();
  useLanguage();
  return (
    <AppShell header={{ height: 56 }} navbar={{ width: 220, breakpoint: "sm", collapsed: { mobile: !opened } }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Link to="/" style={{ textDecoration: "none", color: "inherit" }}>
              <Brand />
            </Link>
            {access.readOnly && (
              <Badge color="orange" variant="light" visibleFrom="sm">
                {t("read-only")}
              </Badge>
            )}
          </Group>
          <Group gap="xs" wrap="nowrap">
            <InstanceSelect />
            <NotificationBell />
            <LanguageMenu />
            <ColorSchemeToggle />
            <UserMenu />
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="xs">
        <AppShell.Section grow component={ScrollArea}>
          {NAV.map((group) => {
            const items = group.items.filter((i) => !i.feature || access.features?.[i.feature]);
            if (items.length === 0) return null;
            return (
              <div key={group.section} style={{ marginBottom: 8 }}>
                {group.section && (
                  <Text size="xs" fw={700} c="dimmed" tt="uppercase" px="sm" pt="xs" pb={4}>
                    {t(group.section)}
                  </Text>
                )}
                {items.map((item) => {
                  const active = item.exact
                    ? location.pathname === item.to
                    : location.pathname === item.to || location.pathname.startsWith(item.to + "/");
                  if (item.external) {
                    return (
                      <NavLink
                        key={item.to}
                        href={item.to}
                        target="_blank"
                        label={t(item.label)}
                        leftSection={<item.icon size={18} stroke={1.6} />}
                        rightSection={<IconExternalLink size={14} />}
                        style={{ borderRadius: "var(--mantine-radius-sm)" }}
                      />
                    );
                  }
                  return (
                    <NavLink
                      key={item.to}
                      component={Link}
                      to={item.to}
                      label={t(item.label)}
                      leftSection={<item.icon size={18} stroke={1.6} />}
                      active={active}
                      onClick={close}
                      style={{ borderRadius: "var(--mantine-radius-sm)" }}
                    />
                  );
                })}
              </div>
            );
          })}
        </AppShell.Section>
        <AppShell.Section>
          <Version />
        </AppShell.Section>
      </AppShell.Navbar>
      <AppShell.Main>
        <Suspense fallback={<LoadingBlock h={300} />}>
          <Outlet />
        </Suspense>
      </AppShell.Main>
    </AppShell>
  );
}
