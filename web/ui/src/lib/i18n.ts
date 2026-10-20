import { useSyncExternalStore } from "react";
import { prefs, serverDefaults } from "./prefs";
import { ko } from "./i18n.ko";

/** Languages with a translation; English strings are the keys. */
export const LANGUAGES: { value: string; label: string }[] = [
  { value: "en", label: "English" },
  { value: "ko", label: "한국어" },
];

const dictionaries: Record<string, Record<string, string>> = { ko };

export function currentLanguage(): string {
  const want = prefs.get().language || serverDefaults.get().language || navigator.language.slice(0, 2);
  return dictionaries[want] || want === "en" ? want : "en";
}

/** Translates s (English) and fills {name} placeholders. */
export function t(s: string, vars?: Record<string, string | number>): string {
  const lang = currentLanguage();
  let out = (lang !== "en" && dictionaries[lang]?.[s]) || s;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) out = out.replaceAll(`{${k}}`, String(v));
  }
  return out;
}

function subscribe(cb: () => void) {
  const a = prefs.subscribe(cb);
  const b = serverDefaults.subscribe(cb);
  return () => {
    a();
    b();
  };
}

/** Re-renders the component when the language changes. */
export function useLanguage(): string {
  return useSyncExternalStore(subscribe, currentLanguage);
}
