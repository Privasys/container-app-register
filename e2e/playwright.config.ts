// Copyright (c) Privasys. Licensed under the AGPL-3.0.

import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const E2E_DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.REGISTER_E2E_PORT || 18143);
const BASE_URL = process.env.REGISTER_E2E_URL || `http://127.0.0.1:${PORT}`;

export default defineConfig({
    testDir: E2E_DIR,
    // The screenshot pass has its own config; it writes files and is
    // not a test.
    testMatch: '**/*.spec.ts',
    outputDir: path.join(E2E_DIR, 'test-results'),
    // The suite drives one register. Running specs in parallel against a
    // single-writer store would test the scheduler, not the register.
    fullyParallel: false,
    workers: 1,
    retries: process.env.CI ? 1 : 0,
    timeout: 60_000,
    expect: { timeout: 10_000 },
    reporter: process.env.CI ? [['github'], ['list']] : [['list']],

    use: {
        baseURL: BASE_URL,
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
    },

    // Started for us unless REGISTER_E2E_URL points at one already
    // running, which is how to attach the suite to a deployed register.
    ...(process.env.REGISTER_E2E_URL
        ? {}
        : {
              webServer: {
                  command: 'node serve.mjs',
                  cwd: E2E_DIR,
                  url: `http://127.0.0.1:${PORT}/health`,
                  reuseExistingServer: !process.env.CI,
                  timeout: 120_000,
                  stdout: process.env.CI ? 'pipe' : 'ignore',
                  stderr: 'pipe',
              },
          }),

    projects: [
        // Chromium first: it has Ed25519 in WebCrypto, so the page can
        // complete the whole verification chain there.
        { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
        // Firefox is kept because the signature check is allowed to
        // report itself unavailable rather than passing. A browser
        // without Ed25519 must degrade honestly, not silently.
        { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    ],
});
