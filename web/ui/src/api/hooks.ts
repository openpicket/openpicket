import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import { authInfoKey } from "./queryClient";
import { serverDefaults } from "../lib/prefs";

export const POLL_MS = 10_000;

export function useAuthInfo() {
  return useQuery({
    queryKey: authInfoKey,
    queryFn: () => api.auth.getAuthInfo({}),
    staleTime: 60_000,
  });
}

/** Role checks of the signed-in user (read-only mode disables changes). */
export function useAccess() {
  const auth = useAuthInfo();
  const role = auth.data?.principal?.role ?? "";
  const readOnly = auth.data?.readOnly ?? false;
  const rank = { viewer: 1, operator: 2, admin: 3 }[role] ?? 0;
  return {
    role,
    readOnly,
    canOperate: rank >= 2 && !readOnly,
    isAdmin: rank >= 3,
    canAdmin: rank >= 3 && !readOnly,
    isOperator: rank >= 2,
    features: auth.data?.features,
  };
}

export function useUISettings() {
  return useQuery({
    queryKey: ["uiSettings"],
    queryFn: async () => {
      const s = (await api.system.getUISettings({})).settings!;
      serverDefaults.set({ language: s.language, timeZone: s.timeZone, clock: s.clock, dateFormat: s.dateFormat });
      return s;
    },
    staleTime: 5 * 60_000,
  });
}

export function useNodes(poll = true) {
  return useQuery({
    queryKey: ["nodes"],
    queryFn: async () => (await api.nodes.listNodes({})).nodes,
    refetchInterval: poll ? POLL_MS : false,
  });
}

export function useNode(id: string) {
  return useQuery({
    queryKey: ["node", id],
    queryFn: async () => (await api.nodes.getNode({ id })).node!,
    refetchInterval: POLL_MS,
  });
}

export function useUnread() {
  return useQuery({
    queryKey: ["notifications", "unread"],
    queryFn: async () => (await api.notifications.listNotifications({ limit: 10 })),
    refetchInterval: 30_000,
  });
}
