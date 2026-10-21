import { useSyncExternalStore } from "react";

/** A tiny observable value persisted in localStorage. */
export function persisted<T>(key: string, initial: T) {
  let value: T = initial;
  try {
    const raw = localStorage.getItem(key);
    if (raw !== null) {
      const stored = JSON.parse(raw);
      // Objects are merged so new defaults appear after an upgrade.
      value = initial && typeof initial === "object" && !Array.isArray(initial) ? ({ ...initial, ...stored } as T) : (stored as T);
    }
  } catch {
    // Unavailable storage or bad JSON: defaults.
  }
  const listeners = new Set<() => void>();
  return {
    get: () => value,
    set(next: T) {
      value = next;
      try {
        localStorage.setItem(key, JSON.stringify(next));
      } catch {
        // Private mode: keep it in memory.
      }
      listeners.forEach((l) => l());
    },
    subscribe(cb: () => void) {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
  };
}

export function useStore<T>(s: { get: () => T; subscribe: (cb: () => void) => () => void }): T {
  return useSyncExternalStore(s.subscribe, s.get);
}
