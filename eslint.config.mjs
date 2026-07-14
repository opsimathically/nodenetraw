import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/build/",
      "**/dist/",
      "**/target/",
      "node_modules/",
      "package-lock.json",
      "**/release/",
      "**/test/types/",
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    files: ["**/src/**/*.ts"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ["**/nodenetraw/src/internal/event-controller.ts"],
    rules: {
      "@typescript-eslint/prefer-promise-reject-errors": "off",
    },
  },
  {
    files: ["**/nodenetraw/src/internal/traceroute.ts"],
    rules: {
      "@typescript-eslint/only-throw-error": "off",
      "@typescript-eslint/prefer-promise-reject-errors": "off",
    },
  },
  {
    files: ["**/*.{js,mjs,cjs}"],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: {
      globals: {
        console: "readonly",
        process: "readonly",
      },
    },
  },
);
