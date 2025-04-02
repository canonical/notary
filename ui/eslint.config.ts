import tseslint from "typescript-eslint";
import eslint from "typescript-eslint";
import globals from "globals";
import { FlatCompat } from '@eslint/eslintrc'

const compat = new FlatCompat({
  baseDirectory: import.meta.dirname,
})

export default tseslint.config(
  {
    // Add browser globals
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      globals: {
        ...globals.browser,
      }
    }
  },
  {
    // Add javascript and typescript rules
    files: ["src/**/*.{ts,tsx}"],
    extends: [
      eslint.configs.recommended,
      tseslint.configs.recommendedTypeChecked,
    ],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  // Add Next.js rules and avoid conflicts with prettier
  ...compat.config({
    extends: ['next', 'prettier'],
  }),
)