import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from '@typescript-eslint/eslint-plugin'
import tsparser from '@typescript-eslint/parser'

export default [
  {
    ignores: [
      'dist',
      'node_modules',
      'coverage',
      'cypress/screenshots',
      'cypress/videos',
    ]
  },
  // Main source files
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: {
        ...globals.browser,
        NodeListOf: 'readonly',
        RequestInit: 'readonly',
      },
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...tseslint.configs['recommended'].rules,
      ...reactHooks.configs.recommended.rules,
      // Fast refresh warning - not critical for functionality
      'react-refresh/only-export-components': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', {
        argsIgnorePattern: '^_|e|err|error|index|item|key|value|event|data|props|state|config|options|params|req|res|next',
        varsIgnorePattern: '^_|React',
        caughtErrorsIgnorePattern: '.*',
        destructuredArrayIgnorePattern: '^_',
        // Ignore unused parameters in callbacks (common in React)
        args: 'none',
      }],
      // TypeScript already provides excellent type checking - any is OK in specific contexts
      // like error handlers, mocking, and library interop
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-function-type': 'off',
      'no-useless-escape': 'off',
      'no-undef': 'off',
      'react-hooks/rules-of-hooks': 'error',
      // Disable setState-in-effect warning - it's overly restrictive for common patterns
      // like data fetching in useEffect or initialization from localStorage
      'react-hooks/set-state-in-effect': 'off',
      // Exhaustive-deps can cause false positives with stable functions
      'react-hooks/exhaustive-deps': 'off',
    },
  },
  // Test files
  {
    files: ['**/*.test.{ts,tsx}', 'src/test/**/*.{ts,tsx}', 'src/**/__tests__/**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: {
        ...globals.browser,
        ...globals.node,
        React: 'readonly',
        jest: 'readonly',
        describe: 'readonly',
        it: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
        vi: 'readonly',
      },
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...tseslint.configs['recommended'].rules,
      // Disable all warnings in test files - tests have different patterns
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/ban-ts-comment': 'off',
      '@typescript-eslint/no-unused-expressions': 'off',
      '@typescript-eslint/no-unsafe-function-type': 'off',
    },
  },
  // Config files
  {
    files: ['*.config.{ts,js,mjs}', 'vite.config.ts', 'vitest.config.ts', 'cypress.config.ts'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: {
        ...globals.node,
      },
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...tseslint.configs['recommended'].rules,
      '@typescript-eslint/no-unused-vars': ['warn', {
        argsIgnorePattern: '^_|on|config|runnable',
        varsIgnorePattern: '^_',
        caughtErrorsIgnorePattern: '^_|error',
        destructuredArrayIgnorePattern: '^_',
        // Ignore unused parameters in callbacks (common in config files)
        args: 'after-used',
      }],
    },
  },
  // Cypress files
  {
    files: ['cypress/**/*.{ts,js}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: {
        ...globals.browser,
        cy: 'readonly',
        Cypress: 'readonly',
        describe: 'readonly',
        it: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        before: 'readonly',
        after: 'readonly',
        expect: 'readonly',
        assert: 'readonly',
      },
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...tseslint.configs['recommended'].rules,
      '@typescript-eslint/no-unused-vars': ['warn', {
        argsIgnorePattern: '^_|on|config|runnable',
        varsIgnorePattern: '^_',
        caughtErrorsIgnorePattern: '^_|error',
        destructuredArrayIgnorePattern: '^_',
        // Ignore unused parameters in callbacks (common in Cypress)
        args: 'after-used',
      }],
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-namespace': 'off',
      '@typescript-eslint/no-unused-expressions': 'off',
    },
  },
]
