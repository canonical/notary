import { defineConfig } from "vite";
import { fileURLToPath } from "url";
import fs from "fs";
import path from "path";
import { devtools } from "@tanstack/devtools-vite";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import viteReact from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const version = fs
  .readFileSync(path.join(__dirname, "../version/VERSION"), "utf8")
  .trim();

const config = defineConfig({
  appType: "spa",
  css: {
    preprocessorOptions: {
      scss: {
        silenceDeprecations: ["import"],
        quietDeps: true,
      },
    },
  },
  resolve: { tsconfigPaths: true },
  plugins: [
    devtools(),
    tailwindcss(),
    tanstackRouter({ target: "react", autoCodeSplitting: true }),
    viteReact(),
  ],
  define: {
    "import.meta.env.NOTARY_APP_VERSION": JSON.stringify(version),
  },
  server: {
    proxy: {
      "/api": {
        target: "https://localhost:2111",
        changeOrigin: true,
        secure: false,
      },
      "/login": {
        target: "https://localhost:2111",
        changeOrigin: true,
        secure: false,
        cookieDomainRewrite: "localhost:3000",
        // cookiePathRewrite: "/",
      },
      "/logout": {
        target: "https://localhost:2111",
        changeOrigin: true,
        secure: false,
      },
      "/status": {
        target: "https://localhost:2111",
        changeOrigin: true,
        secure: false,
      },
    },
  },
});

export default config;
