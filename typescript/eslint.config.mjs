import solanaConfig from '@solana/eslint-config-solana';

export default [
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/*.tsbuildinfo',
      '**/__tests__/**',
      'demo/**',
      '**/*.gen.ts',
      // Codama-rendered program client — regenerated, not hand-maintained.
      '**/src/generated/**',
    ],
  },
  ...solanaConfig,
  {
    rules: {
      '@typescript-eslint/no-namespace': ['error', { allowDeclarations: true }],
    },
  },
];
