import { builtinModules } from 'node:module'

import eslint from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  {
    ignores: ['dist/**', 'coverage/**', 'node_modules/**'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/consistent-type-exports': 'error',
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports' },
      ],
      '@typescript-eslint/no-confusing-void-expression': 'off',
    },
  },
  {
    files: ['src/core/rules/**/*.ts', 'src/rules/**/*.ts', 'src/reporters/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: [
                'node:*',
                ...builtinModules.filter((module) => !module.startsWith('node:')),
              ],
              message: 'Rules and reporters cannot access Node capabilities.',
            },
            {
              group: ['**/security/**'],
              message:
                'Rules and reporters receive protected values through kernel contracts.',
            },
          ],
        },
      ],
      'no-restricted-globals': [
        'error',
        {
          name: 'fetch',
          message: 'Rules and reporters cannot access the network.',
        },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: 'ImportExpression',
          message: 'Rules and reporters cannot use dynamic imports.',
        },
        {
          selector: "CallExpression[callee.name='require']",
          message: 'Rules and reporters cannot use CommonJS require.',
        },
      ],
    },
  },
  {
    files: ['src/external/domain/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'node:dns',
              message: 'External domain must remain network-free (E1.1).',
            },
            {
              name: 'node:net',
              message: 'External domain must remain network-free (E1.1).',
            },
            {
              name: 'node:http',
              message: 'External domain must remain network-free (E1.1).',
            },
            {
              name: 'node:https',
              message: 'External domain must remain network-free (E1.1).',
            },
            {
              name: 'node:tls',
              message: 'External domain must remain network-free (E1.1).',
            },
          ],
          patterns: [
            {
              group: ['**/external/infra/**'],
              message: 'External domain cannot import External infrastructure.',
            },
          ],
        },
      ],
      'no-restricted-globals': [
        'error',
        {
          name: 'fetch',
          message: 'External domain cannot access the network.',
        },
      ],
    },
  },
  {
    files: ['src/external/policy/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'node:dns',
              message: 'External policy cannot perform DNS (E1.2).',
            },
            {
              name: 'node:http',
              message: 'External policy cannot perform HTTP (E1.2).',
            },
            {
              name: 'node:https',
              message: 'External policy cannot perform HTTPS (E1.2).',
            },
            {
              name: 'node:tls',
              message: 'External policy cannot use TLS I/O (E1.2).',
            },
          ],
          patterns: [
            {
              group: ['**/external/infra/**'],
              message: 'External policy cannot import External infrastructure.',
            },
          ],
        },
      ],
      'no-restricted-globals': [
        'error',
        {
          name: 'fetch',
          message: 'External policy cannot access the network.',
        },
      ],
    },
  },
  {
    files: ['src/external/infra/**/*.ts'],
    rules: {
      'no-restricted-globals': [
        'error',
        {
          name: 'fetch',
          message:
            'External infra must use pinned http(s) connectors, not global fetch.',
        },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector:
            "CallExpression[callee.name='fetch'], CallExpression[callee.property.name='fetch']",
          message: 'External infra must use pinned http(s) connectors, not fetch.',
        },
      ],
    },
  },
  {
    files: ['**/*.js'],
    ...tseslint.configs.disableTypeChecked,
  },
)
