import { timestampDate, type Timestamp } from "@bufbuild/protobuf/wkt";
import { prefs, serverDefaults } from "./prefs";

export type Num = number | bigint;

export function toNumber(n: Num | undefined | null): number {
  if (n === undefined || n === null) return 0;
  return typeof n === "bigint" ? Number(n) : n;
}

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

export function formatBytes(n: Num | undefined | null, digits = 1): string {
  let v = toNumber(n);
  if (!Number.isFinite(v)) return "-";
  let i = 0;
  while (Math.abs(v) >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  const s = i === 0 ? String(Math.round(v)) : v.toFixed(v >= 100 ? 0 : digits);
  return `${s} ${UNITS[i]}`;
}

export function formatNumber(n: Num | undefined | null): string {
  return toNumber(n).toLocaleString();
}

/** 1234 -> 1.2k */
export function compactNumber(n: Num | undefined | null): string {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(toNumber(n));
}

export function tsDate(ts: Timestamp | undefined | null): Date | undefined {
  if (!ts) return undefined;
  const d = timestampDate(ts);
  return d.getTime() > 0 ? d : undefined;
}

function effective() {
  const p = prefs.get();
  const s = serverDefaults.get();
  return {
    timeZone: p.timeZone || s.timeZone || undefined,
    clock: p.clock || s.clock || "24h",
    dateFormat: p.dateFormat || s.dateFormat || "iso",
  };
}

function parts(d: Date) {
  const e = effective();
  const f = new Intl.DateTimeFormat("en-US", {
    timeZone: e.timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: e.clock === "12h" ? "h12" : "h23",
  });
  const out: Record<string, string> = {};
  for (const p of f.formatToParts(d)) out[p.type] = p.value;
  return { p: out, e };
}

export function formatDate(d: Date | undefined): string {
  if (!d) return "-";
  const { p, e } = parts(d);
  switch (e.dateFormat) {
    case "us":
      return `${p.month}/${p.day}/${p.year}`;
    case "eu":
      return `${p.day}.${p.month}.${p.year}`;
  }
  return `${p.year}-${p.month}-${p.day}`;
}

export function formatTime(d: Date | undefined, seconds = true): string {
  if (!d) return "-";
  const { p, e } = parts(d);
  const t = `${p.hour}:${p.minute}${seconds ? `:${p.second}` : ""}`;
  return e.clock === "12h" ? `${t} ${p.dayPeriod ?? ""}`.trim() : t;
}

export function formatDateTime(d: Date | undefined): string {
  if (!d) return "-";
  return `${formatDate(d)} ${formatTime(d)}`;
}

export function relativeTime(d: Date | undefined, now: number = Date.now()): string {
  if (!d) return "never";
  const diff = Math.round((now - d.getTime()) / 1000);
  const abs = Math.abs(diff);
  let s: string;
  if (abs < 5 || (diff < 0 && abs < 60)) return "just now";
  if (abs < 60) s = `${abs}s`;
  else if (abs < 3600) s = `${Math.floor(abs / 60)}m`;
  else if (abs < 86400) s = `${Math.floor(abs / 3600)}h`;
  else if (abs < 86400 * 30) s = `${Math.floor(abs / 86400)}d`;
  else if (abs < 86400 * 365) s = `${Math.floor(abs / (86400 * 30))}mo`;
  else s = `${Math.floor(abs / (86400 * 365))}y`;
  return diff >= 0 ? `${s} ago` : `in ${s}`;
}

/** Remaining time until d ("3h 12m"), or "expired". */
export function remaining(d: Date | undefined, now: number = Date.now()): string {
  if (!d) return "-";
  const s = Math.round((d.getTime() - now) / 1000);
  if (s <= 0) return "expired";
  return formatDuration(s);
}

export function formatDuration(seconds: Num | undefined | null): string {
  let s = Math.max(0, Math.floor(toNumber(seconds)));
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function pluralize(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Quotes a search value when needed. */
export function quoteValue(v: string): string {
  return /^[A-Za-z0-9_.:/\-]+$/.test(v) ? v : `"${v.replace(/"/g, '\\"')}"`;
}

/** Adds "field:value" (or "-field:value") to a query unless present. */
export function addTerm(query: string, field: string, value: string, op = "=", negate = false): string {
  const term = `${negate ? "-" : ""}${field}${op}${value === "" ? '""' : quoteValue(value)}`;
  const q = query.trim();
  if (q.split(/\s+/).includes(term)) return q;
  return q ? `${q} ${term}` : term;
}
