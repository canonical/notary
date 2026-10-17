import js from "@eslint/js";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";
import tseslint from "typescript-eslint";

export default defineConfig([
	globalIgnores(["dist/", "src/routeTree.gen.ts"]),
	{
		files: ["**/*.{ts,tsx}"],
		extends: [
			js.configs.recommended,
			tseslint.configs.recommended,
			react.configs.flat.recommended,
			react.configs.flat["jsx-runtime"],
			reactHooks.configs["recommended-latest"],
		],
		languageOptions: {
			globals: { ...globals.browser, ...globals.node },
		},
		settings: {
			react: { version: "detect" },
		},
		rules: {
			"@typescript-eslint/no-unused-vars": [
				"error",
				{ argsIgnorePattern: "^_" },
			],
		},
	},
]);
