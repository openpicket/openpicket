import { persisted, useStore } from "./store";

/** LAPI instance shown on the CrowdSec pages ("" = combined). */
export const scope = persisted<{ instance: string }>("openpicket.scope", { instance: "" });

export function useInstance(): string {
  return useStore(scope).instance;
}
