import { useCallback } from "react";
import { useSearchParams, type SetURLSearchParams } from "react-router";

// setSearchParams builds the next URL from the params of the last render,
// so two updates in one event (a filter and the page reset) would keep only
// the last one. Updates of the same tick are merged and applied once.
let pending: URLSearchParams | null = null;

function update(setParams: SetURLSearchParams, name: string, value: string, def: string) {
  if (!pending) {
    pending = new URLSearchParams(window.location.search);
    queueMicrotask(() => {
      const next = pending!;
      pending = null;
      setParams(next, { replace: true });
    });
  }
  if (value === def || value === "") pending.delete(name);
  else pending.set(name, value);
}

/** A string kept in the URL query (shareable links). */
export function useUrlState(name: string, def = ""): [string, (v: string) => void] {
  const [params, setParams] = useSearchParams();
  const value = params.get(name) ?? def;
  const set = useCallback((v: string) => update(setParams, name, v, def), [name, def, setParams]);
  return [value, set];
}
