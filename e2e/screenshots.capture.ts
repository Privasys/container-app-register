// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// Captures the explorer's views for the documentation and the store
// listing.
//
// Run with `npm run screenshots`. It is deliberately not part of the
// test suite: it asserts almost nothing, and it writes files into the
// repository. What it does do is drive the same register the tests
// drive, through the same API, so the pictures are of the running
// software rather than a mock-up of it.

import { expect, test } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SEEDED, TOKENS, connectAndWait, openView, verifyKey } from './explorer';

const SHOTS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'screenshots');

const shot = async (page: import('@playwright/test').Page, name: string) => {
    await page.waitForTimeout(250); // let the last render settle
    await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: false });
};

// A register with only its seed in it makes for a dull history. This
// puts real work through the workflows first, so the log has a
// proposal, an approval and a correction in it, and a record has two
// versions with something to diff.
test('give the register something to show', async ({ request }) => {
    const as = (token: string) => ({
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
    });
    const digest = (seed: string) => seed.repeat(64).slice(0, 64);

    // A first registration, proposed by a clerk and approved by a registrar.
    const propose = await request.post('/api/v1/workflows/first_registration/propose', {
        headers: as(TOKENS.clerk),
        data: {
            payload: {
                vin: 'VF3CCHMZ3PT000042',
                make: 'Peugeot',
                model: '208',
                year: 2024,
                colour: 'red',
                fuel: 'electric',
                engine_cc: 0,
                first_registration: '2024-06-01',
                plate: 'CC-421-CC',
            },
            evidence: { proof_of_conformity: digest('a') },
            body: 'Dealer submission, chassis inspected at the counter.',
        },
    });
    if (propose.ok()) {
        const { task } = await propose.json();
        await request.post(`/api/v1/tasks/${task.id}/decide`, {
            headers: as(TOKENS.registrar),
            data: { approve: true, reason: 'Certificate of conformity checked against the chassis plate.' },
        });
    }

    // A correction, so a record has a second version and a visible diff.
    const list = await request.get('/api/v1/records?class=vehicle&q=WVW', {
        headers: as(TOKENS.registrar),
    });
    const { records } = await list.json();
    const vehicle = records[0];
    const corrected = await request.post('/api/v1/workflows/correction/propose', {
        headers: as(TOKENS.clerk),
        data: {
            object_id: vehicle.id,
            payload: {
                vin: SEEDED.vin,
                make: 'Volkswagen',
                model: 'Golf',
                year: 2019,
                colour: 'green',
                fuel: 'petrol',
                engine_cc: 1498,
                first_registration: '2019-04-02',
                plate: 'AA-123-AA',
            },
            evidence: { correction_evidence: digest('b') },
            message: `Correct the recorded colour of ${SEEDED.vin}`,
            body: 'Recorded as blue at first registration. The vehicle is green; photographs on file.',
        },
    });
    if (corrected.ok()) {
        const { task } = await corrected.json();
        await request.post(`/api/v1/tasks/${task.id}/decide`, {
            headers: as(TOKENS.registrar),
            data: { approve: true, reason: 'Photographs match the chassis number.' },
        });
    }

    // A lien, so the transfer conditions have something to report on.
    await request.post('/api/v1/workflows/register_lien/propose', {
        headers: as(TOKENS.registrar),
        data: {
            payload: {
                vehicle_id: vehicle.id,
                lender: 'Specimen Finance SA',
                reference: 'LN-2026-0114',
                amount: 8500,
                secured_on: '2026-01-14',
            },
        },
    });
});

test.describe('the explorer', () => {
    // The content column is capped at 1180px, so a wider viewport buys
    // nothing but margin.
    test.use({ viewport: { width: 1280, height: 940 }, deviceScaleFactor: 2 });

    test('the history', async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        await expect(page.locator('#log-list .entry').first()).toBeVisible();
        await shot(page, 'history');
    });

    test('one transaction in full', async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        // Narrow the log first, so the detail panel is in frame rather
        // than somewhere below twenty rows of seed.
        await page.fill('#log-filters input[name="kind"]', 'record.correct');
        await page.click('#log-filters button[type="submit"]');
        await page.locator('#log-list .entry').first().click();
        await expect(page.locator('#log-detail')).toContainText('Root after');
        await shot(page, 'transaction');
    });

    test('a record and its timeline', async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        await openView(page, 'records');
        await page.locator('#record-list .entry', { hasText: SEEDED.vin }).click();
        await expect(page.locator('#record-detail')).toContainText('Timeline');
        await shot(page, 'record');
    });

    test('personal data withheld from a role without clearance', async ({ page }) => {
        await connectAndWait(page, TOKENS.auditor);
        await openView(page, 'records');
        await page.selectOption('#record-class', 'owner');
        await page.click('#record-filters button[type="submit"]');
        await page.locator('#record-list .entry', { hasText: SEEDED.ownerReference }).click();
        await expect(page.locator('#record-detail')).toContainText('Withheld from this role');
        await shot(page, 'redaction');
    });

    test('a proof, verified in the browser', async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        await verifyKey(page, 'vehicle', SEEDED.vin);
        await expect(page.locator('#proof-result .verdict')).toHaveText('Verified in this browser');
        await shot(page, 'proof');
    });

    test('an absence proof', async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        await verifyKey(page, 'vehicle', SEEDED.unregisteredVin);
        await expect(page.locator('#proof-result')).toContainText('absent');
        await shot(page, 'proof-absence');
    });

    test('a bundle that was altered on its way to the page', async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        await page.route('**/api/v1/proofs/**', async (route) => {
            const response = await route.fetch();
            const body = (await response.text()).replace(SEEDED.vin, 'WVWZZZ1JZXW000999');
            route.fulfill({ response, body });
        });
        await verifyKey(page, 'vehicle', SEEDED.vin);
        await expect(page.locator('#proof-result .verdict')).toHaveText('Verification failed');
        await shot(page, 'proof-tampered');
    });

    test('the checkpoint chain', async ({ page }) => {
        await connectAndWait(page, TOKENS.operator);
        await openView(page, 'checkpoints');
        await expect(page.locator('#checkpoint-list .entry').first()).toBeVisible();
        await shot(page, 'checkpoints');
    });

    test('the retention report', async ({ page }) => {
        await connectAndWait(page, TOKENS.operator);
        await openView(page, 'retention');
        await expect(page.locator('#retention-list')).toContainText('P01');
        await shot(page, 'retention');
    });

    test('service health', async ({ page }) => {
        await connectAndWait(page, TOKENS.operator);
        await openView(page, 'health');
        await expect(page.locator('#health-body')).toContainText('Ledger version');
        await shot(page, 'health');
    });
});

test.describe('the explorer in the dark', () => {
    test.use({
        viewport: { width: 1280, height: 940 },
        deviceScaleFactor: 2,
        colorScheme: 'dark',
    });

    test('a proof', async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        await verifyKey(page, 'vehicle', SEEDED.vin);
        await expect(page.locator('#proof-result .verdict')).toHaveText('Verified in this browser');
        await shot(page, 'proof-dark');
    });

    test('history', async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
        await expect(page.locator('#log-list .entry').first()).toBeVisible();
        await page.locator('#log-list .entry', { hasText: 'Correct the recorded colour' }).first().click();
        await shot(page, 'history-dark');
    });
});
