import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        include: ['packages/*/src/__tests__/*.test.ts'],
        exclude: ['**/integration.test.ts', '**/*-integration.test.ts', '**/*-e2e.test.ts'],
        testTimeout: 15_000,
        globals: true,
        coverage: {
            provider: 'v8',
            reporter: ['text', 'lcov', 'json-summary'],
            reportsDirectory: 'coverage',
            include: ['packages/*/src/**/*.ts'],
            exclude: ['**/__tests__/**', '**/dist/**', '**/*.test.ts'],
        },
    },
});
