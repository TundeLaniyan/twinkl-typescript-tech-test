import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        globals: true,
        setupFiles: './src/tests/setup.ts', // Setup file to initialize Testcontainers
        environment: 'node',
    },
});
