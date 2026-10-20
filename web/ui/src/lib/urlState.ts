import { useCallback } from "react";
import { useSearchParams } from "react-router";

/** A string kept in the URL query (shareable links). */
export function useUrlState(name: string, def = ""): [string, (v: string) => void] {
  const [params, setParams] = useSearchParams();
  const value = params.get(name) ?? def;
  const set = useCallback(
    (v: string) =>
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (v === def || v === "") next.delete(name);
          else next.set(name, v);
          return next;
        },
        { replace: true },
      ),
    [name, def, setParams],
  );
  return [value, set];
}
