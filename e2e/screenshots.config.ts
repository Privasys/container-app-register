// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The screenshot pass. Same register, same API, one browser, in order:
// the first spec puts real work through the workflows so the views have
// something worth photographing, and the rest capture them.

import { defineConfig, devices } from '@playwright/test';
import base from './playwright.config';

export default defineConfig({
    ...base,
    testMatch: '**/screenshots.capture.ts',
    fullyParallel: false,
    workers: 1,
    retries: 0,
    reporter: [['list']],
    projects: [{ name: 'screenshots', use: { ...devices['Desktop Chrome'] } }],
});
