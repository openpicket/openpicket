import { useMemo, useState } from "react";
import { Box, Group, Text, useComputedColorScheme } from "@mantine/core";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import world from "world-atlas/countries-110m.json";
import { alpha2FromNumeric, countryName, flag } from "../lib/countries";
import { formatNumber } from "../lib/format";

const W = 960;
const H = 470;

const shapes = (() => {
  const topo = world as unknown as Topology<{ countries: GeometryCollection }>;
  const fc = feature(topo, topo.objects.countries) as FeatureCollection<Geometry, { name: string }>;
  const projection = geoNaturalEarth1().fitSize([W, H], fc);
  const path = geoPath(projection);
  return fc.features
    .filter((f) => f.id !== "010") // Antarctica
    .map((f: Feature<Geometry, { name: string }>) => ({
      cc: alpha2FromNumeric(String(f.id ?? "")) ?? "",
      name: f.properties?.name ?? "",
      d: path(f) ?? "",
    }));
})();

/** Choropleth of counts per country (ISO alpha-2). */
export function WorldMap(props: { counts: Record<string, number>; onSelect?: (cc: string) => void; height?: number }) {
  const scheme = useComputedColorScheme("light");
  const [hover, setHover] = useState<{ cc: string; name: string } | null>(null);
  const max = useMemo(() => Math.max(1, ...Object.values(props.counts)), [props.counts]);
  const fill = (cc: string) => {
    const n = props.counts[cc] ?? 0;
    if (n === 0) return scheme === "dark" ? "var(--mantine-color-dark-5)" : "var(--mantine-color-gray-2)";
    // Log scale: a few heavy sources should not wash out the rest.
    const shade = Math.min(9, 3 + Math.round((Math.log1p(n) / Math.log1p(max)) * 6));
    return `var(--mantine-color-red-${shade})`;
  };
  return (
    <Box pos="relative">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ display: "block", maxHeight: props.height ?? 360 }} role="img" aria-label="World map">
        {shapes.map((s, i) => (
          <path
            key={i}
            d={s.d}
            fill={fill(s.cc)}
            stroke={scheme === "dark" ? "var(--mantine-color-dark-7)" : "white"}
            strokeWidth={0.5}
            style={{ cursor: props.onSelect && props.counts[s.cc] ? "pointer" : "default" }}
            onMouseEnter={() => setHover({ cc: s.cc, name: s.name })}
            onMouseLeave={() => setHover(null)}
            onClick={() => s.cc && props.counts[s.cc] && props.onSelect?.(s.cc)}
          />
        ))}
      </svg>
      {hover && (
        <Group gap={6} pos="absolute" top={8} left={8} px={8} py={4} bg="var(--mantine-color-body)" style={{ borderRadius: 4, boxShadow: "var(--mantine-shadow-xs)" }}>
          <Text size="sm">
            {flag(hover.cc)} {countryName(hover.cc) || hover.name}
          </Text>
          <Text size="sm" fw={600}>
            {formatNumber(props.counts[hover.cc] ?? 0)}
          </Text>
        </Group>
      )}
    </Box>
  );
}
