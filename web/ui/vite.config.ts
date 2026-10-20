import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Backend used by `npm run dev` for /api and /suricata.
const backend = process.env.OPENPICKET_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  base: "/",
  plugins: [react()],
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (/[\\/]node_modules[\\/](recharts|d3-[a-z-]+|victory-vendor|@mantine[\\/]charts)[\\/]/.test(id)) return "charts";
          if (/[\\/]node_modules[\\/](world-atlas|topojson-client|i18n-iso-countries)[\\/]/.test(id)) return "geo";
          if (/[\\/]node_modules[\\/]@mantine[\\/]/.test(id)) return "mantine";
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler|react-router)[\\/]/.test(id)) return "react";
          return undefined;
        },
      },
    },
  },
  server: {
    proxy: {
      "/api": { target: backend, changeOrigin: false },
      "/suricata": { target: backend, changeOrigin: false },
    },
  },
});
