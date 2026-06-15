import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        include: [
            'packages/*/src/__tests__/client-charge-integration.test.ts',
            'packages/*/src/__tests__/playground-session-e2e.test.ts',
        ],
        testTimeout: 60_000,
        fileParallelism: false,
        maxWorkers: 1,
        globals: true,
        coverage: {
            provider: 'v8',
            reporter: ['text', 'lcov', 'json-summary'],
            reportsDirectory: 'coverage-surfpool',
            include: ['packages/*/src/client/Charge.ts'],
            exclude: ['**/__tests__/**', '**/dist/**', '**/*.test.ts'],
        },
    },
});
