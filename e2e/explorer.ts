// Copyright (c) Privasys. Licensed under the AGPL-3.0.

import { expect, type Page } from '@playwright/test';

// Development tokens. The register accepts these only when
// REGISTER_DEV_AUTH is set, which it refuses to honour on the platform;
// their shape is `dev:<subject>:<display name>:<identity-provider roles>`
// and the role names keep their own colons.
export const TOKENS = {
    registrar: 'dev:registrar-1:Registrar:register:registrar',
    clerk: 'dev:clerk-1:Clerk:register:clerk',
    auditor: 'dev:auditor-1:Auditor:register:auditor',
    insurer: 'dev:insurer-1:Insurer:register:insurer',
    operator: 'dev:operator-1:Operator:register:operator',
    stranger: 'dev:nobody:Nobody:some:unrelated-role',
} as const;

// Records the pack seeds, which every test can rely on being there.
export const SEEDED = {
    vin: 'WVWZZZ1JZXW000001',
    otherVin: 'VF1RFB00X66000002',
    unregisteredVin: 'WVWZZZ1JZXW999999',
    ownerReference: 'PTY-0001',
    ownerName: 'SPECIMEN, Alice',
} as const;

/** Opens the explorer and connects with a token. */
export async function connect(page: Page, token: string, role = ''): Promise<void> {
    await page.goto('/explorer/');
    await page.fill('#token', token);
    await page.fill('#role', role);
    await page.click('#connect');
}

/**
 * Opens the explorer, connects, and waits until the pack has loaded.
 *
 * The wait is on the class list rather than the status line: connecting
 * immediately opens the history view, which reports its own count there,
 * so the "connected" message is gone by the time a test could read it.
 */
export async function connectAndWait(page: Page, token: string, role = ''): Promise<void> {
    await connect(page, token, role);
    await expect(page.locator('#record-class option').first()).toBeAttached({ timeout: 20_000 });
}

/** Switches to one of the explorer's views. */
export async function openView(page: Page, view: string): Promise<void> {
    await page.click(`nav button[data-view="${view}"]`);
    await expect(page.locator(`#view-${view}`)).toBeVisible();
}

/** Fetches and verifies a natural key in the proofs view. */
export async function verifyKey(page: Page, cls: string, key: string): Promise<void> {
    await openView(page, 'proofs');
    await page.selectOption('#proof-class', cls);
    await page.fill('#proof-form input[name="key"]', key);
    await page.click('#proof-form button[type="submit"]');
    await expect(page.locator('#proof-result .verdict')).toBeVisible({ timeout: 15_000 });
}

/**
 * Whether this browser can verify Ed25519 signatures.
 *
 * The page degrades honestly where it cannot, reporting the signature
 * check as unavailable rather than as a pass. Tests that are about the
 * signature ask the browser rather than assuming from its name, so the
 * suite keeps working when support arrives or goes away.
 */
export async function hasEd25519(page: Page): Promise<boolean> {
    return page.evaluate(async () => {
        try {
            await crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'Ed25519' }, false, ['verify']);
            return true;
        } catch {
            return false;
        }
    });
}

/** The state the page reports for one named verification check. */
export async function checkState(page: Page, name: string): Promise<string> {
    const row = page.locator('#proof-result .check', { hasText: name }).first();
    await expect(row).toBeVisible();
    const cls = (await row.getAttribute('class')) ?? '';
    for (const state of ['pass', 'fail', 'unknown']) {
        if (cls.split(/\s+/).includes(state)) return state;
    }
    return 'unknown';
}
