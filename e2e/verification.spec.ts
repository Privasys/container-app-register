// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The explorer's proof view, which is the one part of the register that
// asks not to be believed.
//
// It fetches an evidence bundle and checks it in the page: recompute the
// Merkle root from the proof, verify the register's signature over the
// bundle, and check the anchoring checkpoint. Asserting that a genuine
// bundle passes is only half the test. The half that matters is that a
// bundle altered between the register and the page fails — so most of
// what follows intercepts the response and edits it before the page
// sees it. If any of these ever pass, the page is trusting the server
// and the verification is theatre.

import { expect, test, type Page } from '@playwright/test';
import { SEEDED, TOKENS, checkState, connectAndWait, hasEd25519, verifyKey } from './explorer';

/** Rewrites the evidence the page receives, before it receives it. */
async function tamper(page: Page, edit: (bundle: string) => string): Promise<void> {
    await page.route('**/api/v1/proofs/**', async (route) => {
        const response = await route.fetch();
        route.fulfill({ response, body: edit(await response.text()) });
    });
}

test.describe('a genuine bundle', () => {
    test.beforeEach(async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
    });

    test('a registered key verifies, and the proof check needs no browser feature', async ({ page }) => {
        const signatures = await hasEd25519(page);
        await verifyKey(page, 'vehicle', SEEDED.vin);

        // Recomputing the root is arithmetic over hashes: it must pass
        // in every browser, whatever else is unavailable.
        expect(await checkState(page, 'Merkle proof')).toBe('pass');
        await expect(page.locator('#proof-result .check.fail')).toHaveCount(0);
        await expect(page.locator('#proof-result')).toContainText('shows the entry present');

        // The anchor is exact: the register issues a checkpoint for the
        // state it is about to hand out evidence for.
        expect(await checkState(page, 'Checkpoint anchor')).toBe('pass');
        await expect(page.locator('#proof-result')).toContainText('is the state checkpoint');

        // Ed25519 in WebCrypto is not universal. Where it exists the page
        // completes the chain; where it does not it must say so rather
        // than report a pass it did not earn.
        const signature = await checkState(page, 'Register signature');
        if (signatures) {
            expect(signature).toBe('pass');
            await expect(page.locator('#proof-result .verdict')).toHaveText('Verified in this browser');
        } else {
            expect(signature).toBe('unknown');
            await expect(page.locator('#proof-result .verdict')).toHaveText('Partly verified');
            await expect(page.locator('#proof-result')).toContainText('cannot verify Ed25519');
        }
    });

    test('an unregistered key comes back with an absence proof, not a silence', async ({ page }) => {
        await verifyKey(page, 'vehicle', SEEDED.unregisteredVin);
        expect(await checkState(page, 'Merkle proof')).toBe('pass');
        await expect(page.locator('#proof-result .check.fail')).toHaveCount(0);
        await expect(page.locator('#proof-result')).toContainText('shows the entry absent');
        await expect(page.locator('#proof-result')).toContainText('Present');
        await expect(page.locator('#proof-result table')).toContainText('false');
    });

    test('the bundle shown is the whole artefact, not a summary of it', async ({ page }) => {
        await verifyKey(page, 'vehicle', SEEDED.vin);
        const bundle = page.locator('#proof-result pre').last();
        for (const field of ['"proof"', '"path"', '"root"', '"signature"', '"checkpoint"', '"key_id"']) {
            await expect(bundle).toContainText(field);
        }
    });

    test('a record version can be proved from its timeline', async ({ page }) => {
        await page.click('nav button[data-view="records"]');
        await page.locator('#record-list .entry', { hasText: SEEDED.vin }).click();
        await page.locator('#record-detail button', { hasText: 'Proof for this version' }).first().click();
        await expect(page.locator('#proof-result .verdict')).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('#proof-result h2')).toContainText('version 1 of record');
        expect(await checkState(page, 'Merkle proof')).toBe('pass');
        await expect(page.locator('#proof-result .check.fail')).toHaveCount(0);
    });
});

test.describe('a bundle altered in flight', () => {
    test.beforeEach(async ({ page }) => {
        await connectAndWait(page, TOKENS.registrar);
    });

    test('flipping the answer is caught by the proof itself', async ({ page }) => {
        // The most consequential lie a register could tell: claiming a
        // vehicle is not registered when it is. The proof contradicts it
        // without reference to the signature.
        await tamper(page, (body) => body.replace('"present":true', '"present":false'));
        await verifyKey(page, 'vehicle', SEEDED.vin);

        expect(await checkState(page, 'Merkle proof')).toBe('fail');
        await expect(page.locator('#proof-result')).toContainText(
            'the bundle says the entry is absent, the proof says otherwise',
        );
        await expect(page.locator('#proof-result .verdict')).toHaveText('Verification failed');
    });

    test('substituting the root is caught: the proof no longer folds to it', async ({ page }) => {
        await tamper(page, (body) =>
            body.replace(/"root":"[0-9a-f]{64}"/, `"root":"${'0'.repeat(64)}"`),
        );
        await verifyKey(page, 'vehicle', SEEDED.vin);

        expect(await checkState(page, 'Merkle proof')).toBe('fail');
        await expect(page.locator('#proof-result')).toContainText('folds to');
        await expect(page.locator('#proof-result .verdict')).toHaveText('Verification failed');
    });

    test('rewriting the row is caught by the signature, and only by it', async ({ page }) => {
        test.skip(!(await hasEd25519(page)), 'this browser cannot verify Ed25519 signatures');
        // The row is the register's assertion about what the proven entry
        // says. Nothing in the Merkle path covers the words, so this is
        // exactly the failure the signature exists to catch.
        await tamper(page, (body) => body.replace(SEEDED.vin, 'WVWZZZ1JZXW000999'));
        await verifyKey(page, 'vehicle', SEEDED.vin);

        expect(await checkState(page, 'Merkle proof')).toBe('pass');
        expect(await checkState(page, 'Register signature')).toBe('fail');
        await expect(page.locator('#proof-result')).toContainText('does not match the bundle');
        await expect(page.locator('#proof-result .verdict')).toHaveText('Verification failed');
    });

    test('swapping in another key does not make a forged signature verify', async ({ page }) => {
        test.skip(!(await hasEd25519(page)), 'this browser cannot verify Ed25519 signatures');
        await tamper(page, (body) => {
            const bundle = JSON.parse(body);
            bundle.signature = Buffer.alloc(64, 7).toString('base64');
            bundle.key_id = 'f'.repeat(64);
            return JSON.stringify(bundle);
        });
        await verifyKey(page, 'vehicle', SEEDED.vin);

        expect(await checkState(page, 'Register signature')).toBe('fail');
        await expect(page.locator('#proof-result .verdict')).toHaveText('Verification failed');
    });

    test('the anchor cannot be detached, because the signature covers it', async ({ page }) => {
        test.skip(!(await hasEd25519(page)), 'this browser cannot verify Ed25519 signatures');
        await tamper(page, (body) => {
            const bundle = JSON.parse(body);
            bundle.checkpoint = null;
            return JSON.stringify(bundle);
        });
        await verifyKey(page, 'vehicle', SEEDED.vin);

        // The page says plainly that there is no anchor, rather than
        // treating its absence as a pass. Unanchored is not disproved,
        // and the two are reported differently.
        expect(await checkState(page, 'Checkpoint anchor')).toBe('unknown');
        await expect(page.locator('#proof-result')).toContainText('carries no checkpoint');

        // And removing it is itself caught: the checkpoint is part of
        // what the register signed, so a bundle cannot be re-pointed at
        // a different state, or at none, after the fact.
        expect(await checkState(page, 'Register signature')).toBe('fail');
        await expect(page.locator('#proof-result .verdict')).toHaveText('Verification failed');
    });

    test('an anchor for a different state is not accepted as this one', async ({ page }) => {
        await tamper(page, (body) => {
            const bundle = JSON.parse(body);
            bundle.checkpoint.checkpoint.version += 1;
            return JSON.stringify(bundle);
        });
        await verifyKey(page, 'vehicle', SEEDED.vin);

        expect(await checkState(page, 'Checkpoint anchor')).toBe('unknown');
        await expect(page.locator('#proof-result')).toContainText('compare against a checkpoint you hold');
    });

    test('a truncated proof is refused, not treated as a shorter one', async ({ page }) => {
        await tamper(page, (body) =>
            body.replace(/"proof":"([0-9a-f]+)"/, (_, hex: string) => `"proof":"${hex.slice(0, -64)}"`),
        );
        await verifyKey(page, 'vehicle', SEEDED.vin);

        expect(await checkState(page, 'Merkle proof')).toBe('fail');
        await expect(page.locator('#proof-result .verdict')).toHaveText('Verification failed');
    });
});
