import { persisted, useStore } from "./store";

/** Display preferences of this browser; empty values use the server defaults. */
export interface Prefs {
  language: string;
  timeZone: string;
  clock: "" | "24h" | "12h";
  dateFormat: "" | "iso" | "us" | "eu";
  /** Visible columns per table. */
  columns: Record<string, string[]>;
  /** Quick filter drawer open per page. */
  facets: Record<string, boolean>;
}

export const prefs = persisted<Prefs>("openpicket.prefs", {
  language: "",
  timeZone: "",
  clock: "",
  dateFormat: "",
  columns: {},
  facets: {},
});

export function usePrefs(): Prefs {
  return useStore(prefs);
}

export function setPref<K extends keyof Prefs>(k: K, v: Prefs[K]): void {
  prefs.set({ ...prefs.get(), [k]: v });
}

/** Server-side defaults (UI settings), applied when a preference is empty. */
export const serverDefaults = persisted("openpicket.serverDefaults", {
  language: "",
  timeZone: "",
  clock: "",
  dateFormat: "",
});
