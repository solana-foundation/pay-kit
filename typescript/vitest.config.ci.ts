/**
 * CI vitest config: runs ALL tests (unit + surfpool integration) with coverage.
 * Used in CI after surfpool-sdk-node has been built and linked.
 */
import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        include: ['packages/*/src/__tests__/*.test.ts'],
        // Exclude surfpool-service-based tests and the playground e2e suites
        // (those need the playground server's dependencies and a sandbox).
        exclude: ['**/integration.test.ts', '**/*-e2e.test.ts'],
        testTimeout: 30_000,
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
