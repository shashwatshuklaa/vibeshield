import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: [
      'packages/**/*.redis.integration.{test,spec}.ts',
      'apps/**/*.redis.integration.{test,spec}.ts',
      'workers/**/*.redis.integration.{test,spec}.ts',
    ],
    exclude: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/.turbo/**', '**/.next/**'],
    testTimeout: 30_000,
    hookTimeout: 60_000,
    fileParallelism: false,
  },
});
