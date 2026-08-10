import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// En desarrollo, Vite corre en :5173 y proxya /api al backend dentro de
// la red de Docker Compose. En producción, ese proxy lo hace nginx.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      "/api": {
        target: "http://backend:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
