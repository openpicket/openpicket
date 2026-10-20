import countries from "i18n-iso-countries";
import en from "i18n-iso-countries/langs/en.json";
import ko from "i18n-iso-countries/langs/ko.json";
import { currentLanguage } from "./i18n";

countries.registerLocale(en);
countries.registerLocale(ko);

/** Country name in the UI language ("" for unknown codes). */
export function countryName(cc: string | undefined): string {
  if (!cc) return "";
  return countries.getName(cc, currentLanguage(), { select: "official" }) ?? countries.getName(cc, "en") ?? cc;
}

/** Emoji flag of an ISO 3166-1 alpha-2 code. */
export function flag(cc: string | undefined): string {
  if (!cc || cc.length !== 2) return "";
  const base = 0x1f1e6 - 65;
  return String.fromCodePoint(base + cc.toUpperCase().charCodeAt(0), base + cc.toUpperCase().charCodeAt(1));
}

/** ISO numeric code (world-atlas ids) of an alpha-2 code. */
export function numericCode(cc: string): string | undefined {
  return countries.alpha2ToNumeric(cc);
}

export function alpha2FromNumeric(n: string): string | undefined {
  return countries.numericToAlpha2(n);
}

export function allCountries(): { value: string; label: string }[] {
  const names = countries.getNames(currentLanguage(), { select: "official" });
  const fallback = countries.getNames("en", { select: "official" });
  return Object.keys(fallback)
    .map((cc) => ({ value: cc, label: `${flag(cc)} ${names[cc] ?? fallback[cc]} (${cc})` }))
    .sort((a, b) => a.label.localeCompare(b.label));
}
