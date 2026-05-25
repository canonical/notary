import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import { devtools } from "@tanstack/devtools-vite";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import viteReact from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const version = fs
	.readFileSync(path.join(__dirname, "../version/VERSION"), "utf8")
	.trim();

const config = defineConfig({
	appType: "spa",
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
	css: {
		preprocessorOptions: {
			scss: {
				silenceDeprecations: ["import"],
				quietDeps: true,
			},
		},
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
				cookieDomainRewrite: "localhost:2112",
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
