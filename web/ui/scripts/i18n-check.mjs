// Lists the t("...") strings of src/ missing from a dictionary:
//   node scripts/i18n-check.mjs ko [--json]
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const lang = process.argv[2] ?? "ko";
const json = process.argv.includes("--json");
const files = [];
(function walk(d) {
  for (const f of readdirSync(d)) {
    const p = join(d, f);
    if (statSync(p).isDirectory()) {
      if (f !== "gen") walk(p);
    } else if (/\.tsx?$/.test(f) && !f.startsWith("i18n.")) files.push(p);
  }
})("src");

// t("..."), t('...') and t(`...`) without interpolation; also the label
// strings of tables that are passed to t() later (label: "...").
const re = /\bt\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`[^`$]*`)/g;
const labelRe = /\b(?:label|title|description|section):\s*("(?:[^"\\]|\\.)*")/g;
const keys = new Set();
for (const f of files) {
  const src = readFileSync(f, "utf8");
  for (const m of src.matchAll(re)) keys.add(eval(m[1]));
  for (const m of src.matchAll(labelRe)) keys.add(JSON.parse(m[1]));
}
const dictSrc = readFileSync(`src/lib/i18n.${lang}.ts`, "utf8");
const have = new Set([...dictSrc.matchAll(/^\s*("(?:[^"\\]|\\.)*"|[A-Za-z_][\w]*)\s*:/gm)].map((m) => (m[1].startsWith('"') ? JSON.parse(m[1]) : m[1])));
const missing = [...keys].filter((k) => !have.has(k)).sort();
if (json) console.log(JSON.stringify(missing, null, 1));
else {
  for (const k of missing) console.log(k);
  console.error(`${missing.length} of ${keys.size} strings missing in ${lang}`);
}
