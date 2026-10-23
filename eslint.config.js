import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["python/**/.venv/**", "python/**/node_modules/**", "python/dist/**", "out/**", "**/dist/**", "**/viewer-dist/**", "**/coverage/**", "**/node_modules/**", ".steplight/**"] },
  ...tseslint.configs.recommended,
  {
    rules: {
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
    },
  },
);
