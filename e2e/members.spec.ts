// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// Membership, driven through the console.
//
// A person who signs in with their wallet is known to the register by a
// subject of its own, and holds whatever role somebody granted them
// here. The suite cannot run a wallet, so it stands in for one with
// development tokens that carry no identity-provider role at all: what
// those people may do afterwards is then down to the register's own
// grants, which is the path a deployment takes.

import { expect, test } from '@playwright/test';
import { TOKENS, connect, connectAndWait, openView } from './explorer';

// One newcomer per browser project: both projects run against the same
// register, and a grant made in the first is still there in the second.
const newcomer = (project: string) => `dev:newcomer-${project}`;

test('a person with no role is told so, and shown the name the register knows them by', async ({ page }, info) => {
    await connect(page, newcomer(`${info.project.name}-idle`));
    await expect(page.locator('#status-line.error')).toContainText('no register role');
    await expect(page.locator('#my-subject')).toHaveText(`newcomer-${info.project.name}-idle`);
});

test('an invitation makes its holder a member, once, and the history says who and why', async ({ page, browser }, info) => {
    // The operator issues an invitation for an auditor.
    await connectAndWait(page, TOKENS.operator);
    await openView(page, 'members');
    await page.selectOption('#invite-form select[name="role"]', 'auditor');
    await page.fill('#invite-form input[name="label"]', 'Court of auditors');
    await page.click('#invite-form button[type="submit"]');
    const link = (await page.locator('#invite-issued pre').innerText()).trim();
    expect(link).toMatch(/#\/join\/[0-9a-f]{16}\/[A-Za-z0-9_-]{43}$/);
    await expect(page.locator('#invite-list .entry', { hasText: 'Court of auditors' }).first()).toContainText('open');

    // Somebody else opens the link. The page takes it out of the address
    // bar before they have even signed in.
    const guest = await (await browser.newContext()).newPage();
    await guest.goto(link);
    await expect(guest).toHaveURL(/#\/$/);
    await guest.fill('#token', newcomer(info.project.name));
    await guest.click('#connect');
    await expect(guest.locator('#accept-invite')).toHaveText('Accept as Auditor');
    await guest.click('#accept-invite');

    // They are in, as what the invitation said and nothing more.
    await expect(guest.locator('nav button.active')).toHaveText('History');
    await expect(guest.locator('#identity .role')).toHaveText('Auditor');
    await expect(guest.locator('nav button[data-view="members"]')).toHaveCount(0);
    const entry = guest.locator('#log-list .entry', { hasText: 'Grant auditor to Court of auditors' }).first();
    await expect(entry).toContainText('invite.redeem');
    await entry.click();
    await expect(guest.locator('#log-detail')).toContainText(`newcomer-${info.project.name} acting as invitee`);

    // The link is spent: a third person gets nothing from it.
    const late = await (await browser.newContext()).newPage();
    await late.goto(link);
    await late.fill('#token', newcomer(`${info.project.name}-late`));
    await late.click('#connect');
    await expect(late.locator('#status-line.error')).toContainText('this invitation is not valid');
    await expect(late.locator('#accept-invite')).toHaveCount(0);

    // The operator sees the member and the used invitation.
    await openView(page, 'records');
    await openView(page, 'members');
    await expect(page.locator('#member-list .entry', { hasText: `newcomer-${info.project.name}` }).first()).toContainText('Auditor');
    await expect(page.locator('#invite-list .entry', { hasText: 'Court of auditors' }).first()).toContainText('used');
});

test('two roles the pack keeps apart cannot be granted to one person', async ({ page }, info) => {
    const sub = `duties-${info.project.name}`;
    await connectAndWait(page, TOKENS.operator);
    await openView(page, 'members');
    await page.fill('#grant-form input[name="sub"]', sub);
    await page.selectOption('#grant-form select[name="role"]', 'registrar');
    await page.fill('#grant-form input[name="reason"]', 'Head of registrations');
    await page.click('#grant-form button[type="submit"]');
    await expect(page.locator('#member-list .entry', { hasText: sub })).toHaveCount(1);

    await page.fill('#grant-form input[name="sub"]', sub);
    await page.selectOption('#grant-form select[name="role"]', 'clerk');
    await page.click('#grant-form button[type="submit"]');
    await expect(page.locator('#status-line.error')).toContainText('separation of duties');
    await expect(page.locator('#member-list .entry', { hasText: sub })).toHaveCount(1);
});
