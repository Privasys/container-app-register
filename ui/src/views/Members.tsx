// Who holds which role, and the invitations that are out.
//
// A person who signs in with their wallet is known to the register by a
// subject of its own, so their roles are granted here rather than read off
// a token. Every grant, invitation and withdrawal on this page is a signed
// transaction: it appears in the history with its author and its reason.

import { useCallback, useEffect, useState } from 'react';
import { useSession } from '../lib/session';
import type { Invite, Member, RoleSpec } from '../lib/types';
import { fmtTime, useRun, useStatus } from '../lib/ui';

export function Members({ active }: { active: boolean }) {
    const { transport, role, me } = useSession();
    const setStatus = useStatus();
    const run = useRun();
    const [members, setMembers] = useState<Member[]>([]);
    const [roles, setRoles] = useState<RoleSpec[]>([]);
    const [invites, setInvites] = useState<Invite[]>([]);
    // The link of the invitation just issued. The register serves its
    // secret once, so it is shown until the page moves on.
    const [issued, setIssued] = useState<{ link: string; label: string } | null>(null);

    const load = useCallback(
        () =>
            run(async () => {
                const [m, i] = await Promise.all([
                    transport.request<{ members: Member[]; roles: RoleSpec[] }>('GET', '/api/v1/members'),
                    transport.request<{ invites: Invite[] }>('GET', '/api/v1/invites')
                ]);
                setMembers(m.members);
                setRoles(m.roles);
                setInvites(i.invites);
                setStatus(`${new Set(m.members.map((x) => x.sub)).size} members`);
            }),
        [transport, run, setStatus]
    );

    useEffect(() => {
        if (active) void load();
    }, [active, role, load]);

    const title = (name: string) => roles.find((r) => r.name === name)?.title || name;

    const invite = (form: HTMLFormElement) =>
        run(async () => {
            const data = new FormData(form);
            const label = String(data.get('label') || '');
            const res = await transport.request<{ link: string }>('POST', '/api/v1/invites', {
                role: String(data.get('role')),
                label,
                valid_days: Number(data.get('valid_days') || 7)
            });
            // The register answers with the path; the page knows its origin.
            setIssued({ link: `${location.origin}${res.link}`, label });
            form.reset();
            await load();
        });

    const grant = (form: HTMLFormElement) =>
        run(async () => {
            const data = new FormData(form);
            await transport.request('POST', '/api/v1/members', {
                sub: String(data.get('sub')),
                role: String(data.get('role')),
                display: String(data.get('display') || ''),
                reason: String(data.get('reason') || '')
            });
            form.reset();
            await load();
        });

    const revoke = (m: Member) =>
        run(async () => {
            const reason = window.prompt(`Why is ${m.display || m.sub} no longer ${title(m.role)}? The reason is recorded.`);
            if (reason === null) return;
            await transport.request(
                'DELETE',
                `/api/v1/members/${encodeURIComponent(m.sub)}/${encodeURIComponent(m.role)}?reason=${encodeURIComponent(reason)}`
            );
            await load();
        });

    const withdraw = (inv: Invite) =>
        run(async () => {
            await transport.request('DELETE', `/api/v1/invites/${encodeURIComponent(inv.id)}`);
            await load();
        });

    const roleOptions = roles.map((r) => (
        <option key={r.name} value={r.name}>
            {r.title || r.name}
        </option>
    ));

    return (
        <section id="view-members" className={active ? 'view' : 'view hidden'}>
            <p className="note">
                Roles are granted here, by a person, for a reason. Each grant is a transaction in the history, and so
                is taking one away. Two roles the pack declares incompatible cannot be held by the same person.
            </p>

            <h3 className="heading">Invite someone</h3>
            <form
                id="invite-form"
                onSubmit={(e) => {
                    e.preventDefault();
                    void invite(e.currentTarget);
                }}
            >
                <select name="role" required>
                    {roleOptions}
                </select>
                <input name="label" placeholder="Who it is for" maxLength={96} required />
                <select name="valid_days" defaultValue="7">
                    <option value="1">Valid 1 day</option>
                    <option value="7">Valid 7 days</option>
                    <option value="30">Valid 30 days</option>
                </select>
                <button type="submit">Create invitation</button>
            </form>
            {issued && (
                <div id="invite-issued" className="detail">
                    <h2>Invitation for {issued.label}</h2>
                    <p className="note">
                        Send this link to them yourself. It works once, and it is shown only now: the register keeps a
                        hash of it, not the link.
                    </p>
                    <pre>{issued.link}</pre>
                    <p className="note">
                        <button onClick={() => void navigator.clipboard?.writeText(issued.link)}>Copy</button>{' '}
                        <button onClick={() => setIssued(null)}>Done</button>
                    </p>
                </div>
            )}

            <h3 className="heading">Members</h3>
            <div id="member-list" className="list">
                {members.length === 0 && <p className="note">Nobody has been granted a role here yet.</p>}
                {members.map((m) => (
                    <div className="entry static" key={`${m.sub}|${m.role}`}>
                        <span className="id">{title(m.role)}</span>
                        <span className="summary">
                            {m.display || '(no name)'}
                            <span className="kind">
                                {m.sub}
                                {m.sub === me.sub ? ' · you' : ''}
                            </span>
                        </span>
                        <span className="who">
                            {fmtTime(m.granted_at)} <button onClick={() => void revoke(m)}>Revoke</button>
                        </span>
                    </div>
                ))}
            </div>

            <h3 className="heading">Invitations</h3>
            <div id="invite-list" className="list">
                {invites.length === 0 && <p className="note">No invitations have been issued.</p>}
                {invites.map((inv) => (
                    <div className="entry static" key={inv.id}>
                        <span className="id">{title(inv.role)}</span>
                        <span className="summary">
                            {inv.label || '(unlabelled)'}
                            <span className="kind">
                                {inv.status}
                                {inv.status === 'open' ? ` until ${fmtTime(inv.expires_at)}` : ''}
                                {inv.status === 'used' ? ` by ${inv.used_by}` : ''}
                            </span>
                        </span>
                        <span className="who">
                            {fmtTime(inv.created_at)} {inv.status === 'open' && <button onClick={() => void withdraw(inv)}>Withdraw</button>}
                        </span>
                    </div>
                ))}
            </div>

            <h3 className="heading">Grant by subject</h3>
            <p className="note">
                For someone who has already signed in and sent you the subject the register showed them. An invitation
                is usually simpler.
            </p>
            <form
                id="grant-form"
                onSubmit={(e) => {
                    e.preventDefault();
                    void grant(e.currentTarget);
                }}
            >
                <input name="sub" placeholder="Subject" required />
                <select name="role" required>
                    {roleOptions}
                </select>
                <input name="display" placeholder="Name" maxLength={96} />
                <input name="reason" placeholder="Reason (recorded)" />
                <button type="submit">Grant</button>
            </form>
        </section>
    );
}
