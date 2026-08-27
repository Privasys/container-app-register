// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The operator explorer, driven against a real register.
//
// The explorer is an ordinary client of the register's API, so these
// tests are also the end-to-end check that the API says what the core
// means: the log carries reasons, a record's timeline shows what each
// version changed, and a role without clearance is shown that personal
// data was withheld rather than being shown nothing.

import { expect, test } from '@playwright/test';
import { SEEDED, TOKENS, connect, connectAndWait, openView } from './explorer';

test.describe('connecting', () => {
    test('a registrar connects and lands on the history', async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        await expect(page.locator('nav button.active')).toHaveText('History');
        await expect(page.locator('#log-list .entry').first()).toBeVisible();
        await expect(page.locator('#status-line')).toContainText('transactions');
        // The pack decides what the console can show, so the class list
        // is the register's own answer rather than anything hard-coded.
        await expect(page.locator('#record-class option')).toHaveCount(5);
    });

    test('a token carrying no register role is refused, and says so', async ({ page }) => {
        await connect(page, TOKENS.stranger);
        await expect(page.locator('#status-line.error')).toContainText('no register role', {
            timeout: 15_000,
        });
        await expect(page.locator('#log-list .entry')).toHaveCount(0);
    });

    test('an insurer has no business in the transaction log', async ({ page }) => {
        // A purpose-scoped read credential connects, because it may read
        // vehicles; asking for the log is where it is stopped.
        await connectAndWait(page, TOKENS.insurer);
        await expect(page.locator('#status-line.error')).toContainText('may not read the transaction log');
    });
});

test.describe('history', () => {
    test.beforeEach(async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
    });

    test('every entry carries a summary, an author and a role', async ({ page }) => {
        const entries = page.locator('#log-list .entry');
        // Connecting loads the pack before it loads the log, so wait for
        // the list itself rather than counting whatever has arrived.
        await expect(entries.nth(5)).toBeVisible();
        for (const entry of await entries.all()) {
            await expect(entry.locator('.summary')).not.toBeEmpty();
            await expect(entry.locator('.who')).not.toBeEmpty();
        }
    });

    test('a transaction opens with its reason and the roots either side', async ({ page }) => {
        await page.locator('#log-list .entry').first().click();
        const detail = page.locator('#log-detail');
        await expect(detail.locator('h2')).not.toBeEmpty();
        await expect(detail).toContainText('Root before');
        await expect(detail).toContainText('Root after');
        await expect(detail).toContainText('Write set');

        // The roots are real 32-byte values, not placeholders: this is
        // where a reader sees that the change moved the authenticated
        // state, and from what to what.
        const hashes = await detail.locator('table .hash').allTextContents();
        const roots = hashes.filter((h) => /^[0-9a-f]{64}$/.test(h));
        expect(roots.length).toBeGreaterThanOrEqual(3); // transaction id, before, after
    });

    test('the log filters by class', async ({ page }) => {
        await page.fill('#log-filters input[name="class"]', 'plate');
        await page.click('#log-filters button[type="submit"]');
        await expect(page.locator('#log-list .entry').first()).toBeVisible();
        for (const summary of await page.locator('#log-list .entry .summary').allTextContents()) {
            expect(summary.toLowerCase()).toContain('plate');
        }
    });

    test('a filter that matches nothing says so rather than showing stale rows', async ({ page }) => {
        await page.fill('#log-filters input[name="author"]', 'nobody-at-all');
        await page.click('#log-filters button[type="submit"]');
        await expect(page.locator('#log-list')).toContainText('No transactions match');
    });
});

test.describe('records', () => {
    test.beforeEach(async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        await openView(page, 'records');
    });

    test('the seeded vehicles are listed with their projected columns', async ({ page }) => {
        await expect(page.locator('#record-list .entry')).toHaveCount(2);
        await expect(page.locator('#record-list')).toContainText(SEEDED.vin);
        await expect(page.locator('#record-list')).toContainText(SEEDED.otherVin);
    });

    test('a record opens with its payload and its timeline', async ({ page }) => {
        await page.locator('#record-list .entry', { hasText: SEEDED.vin }).click();
        const detail = page.locator('#record-detail');
        await expect(detail.locator('h2')).toContainText(SEEDED.vin);
        await expect(detail).toContainText('Current version');
        await expect(detail.locator('pre').first()).toContainText('Volkswagen');
        await expect(detail).toContainText('Timeline');
        await expect(detail.locator('.entry')).toHaveCount(1); // one version so far
        await expect(detail.locator('button', { hasText: 'Proof for this version' })).toBeVisible();
    });

    test('the search box filters by natural key', async ({ page }) => {
        await page.fill('#record-filters input[name="q"]', 'VF1');
        await page.click('#record-filters button[type="submit"]');
        await expect(page.locator('#record-list .entry')).toHaveCount(1);
        await expect(page.locator('#record-list')).toContainText(SEEDED.otherVin);
    });

    test('a class with no matching records says so', async ({ page }) => {
        await page.selectOption('#record-class', 'lien');
        await page.click('#record-filters button[type="submit"]');
        await expect(page.locator('#record-list')).toContainText('No records match');
    });
});

test.describe('personal data', () => {
    test('a cleared role sees an owner in full', async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        await openView(page, 'records');
        await page.selectOption('#record-class', 'owner');
        await page.click('#record-filters button[type="submit"]');
        await page.locator('#record-list .entry', { hasText: SEEDED.ownerReference }).click();

        const detail = page.locator('#record-detail');
        await expect(detail.locator('pre').first()).toContainText(SEEDED.ownerName);
        await expect(detail).not.toContainText('Withheld from this role');
    });

    test('an uncleared role is told what was withheld, not shown nothing', async ({ page }) => {
        await connectAndWait(page, TOKENS.auditor);
        await openView(page, 'records');
        await page.selectOption('#record-class', 'owner');
        await page.click('#record-filters button[type="submit"]');
        await page.locator('#record-list .entry', { hasText: SEEDED.ownerReference }).click();

        const detail = page.locator('#record-detail');
        const payload = detail.locator('pre').first();
        await expect(payload).toContainText(SEEDED.ownerReference);
        await expect(payload).not.toContainText(SEEDED.ownerName);
        await expect(detail).toContainText('Withheld from this role');
        await expect(detail).toContainText('name');
    });
});

test.describe('checkpoints', () => {
    test('the verification key and the chain are shown', async ({ page }) => {
        await connectAndWait(page, TOKENS.operator);
        await openView(page, 'checkpoints');
        await expect(page.locator('#checkpoint-key')).toContainText('Verification key');
        await expect(page.locator('#checkpoint-key')).toContainText('ed25519');
        await expect(page.locator('#checkpoint-key')).toContainText('outside the register');

        const entries = page.locator('#checkpoint-list .entry');
        await expect(entries.first()).toBeVisible();
        // Every entry names the state it attests.
        for (const entry of await entries.all()) {
            await expect(entry.locator('.id')).toHaveText(/^v\d+$/);
            await expect(entry.locator('.summary')).toContainText(/[0-9a-f]{64}/);
        }
    });
});

test.describe('retention', () => {
    test('every policy reports its horizon', async ({ page }) => {
        await connectAndWait(page, TOKENS.operator);
        await openView(page, 'retention');
        const rows = page.locator('#retention-list table tr');
        await expect(rows).toHaveCount(4); // a header and three policies
        await expect(page.locator('#retention-list')).toContainText('P01');
        await expect(page.locator('#retention-list')).toContainText('P02');
        await expect(page.locator('#retention-list')).toContainText('P03');
        await expect(page.locator('#retention-list')).toContainText('3650 days');
    });
});

test.describe('health', () => {
    test('the service reports its position', async ({ page }) => {
        await connectAndWait(page, TOKENS.operator);
        await openView(page, 'health');
        const body = page.locator('#health-body');
        await expect(body).toContainText('e2e-register');
        await expect(body).toContainText('car_register 1.0.0');
        await expect(body).toContainText('Root');
        await expect(body).toContainText('Ledger version');
        await expect(body).toContainText('Last checkpoint');
        // Nothing left half-applied: a persistent non-zero here would
        // mean recovery is failing.
        const unapplied = body.locator('tr', { hasText: 'Unapplied transactions' });
        await expect(unapplied).toContainText('0');
    });
});
