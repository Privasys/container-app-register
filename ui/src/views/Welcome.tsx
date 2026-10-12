// What a person sees when they are signed in and hold no role here: who
// the register thinks they are, and the invitation they arrived with, if
// they arrived with one.

import { useEffect, useState } from 'react';
import { clearInvite, pendingInvite } from '../lib/invite';
import { useSession } from '../lib/session';
import { ApiError } from '../lib/transport';
import { fmtTime } from '../lib/ui';

interface Offer {
    role: string;
    role_title: string;
    label?: string;
    expires_at: number;
}

export function Welcome() {
    const { transport, me, refreshMe, signOut } = useSession();
    const [invite] = useState(pendingInvite);
    const [offer, setOffer] = useState<Offer | null>(null);
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        if (!invite) return;
        transport
            .request<Offer>('POST', `/api/v1/invites/${encodeURIComponent(invite.id)}/check`, { secret: invite.secret })
            .then(setOffer, (e: Error) => {
                clearInvite();
                setError(e.message);
            });
    }, [invite, transport]);

    const accept = async () => {
        if (!invite) return;
        setBusy(true);
        try {
            await transport.request('POST', `/api/v1/invites/${encodeURIComponent(invite.id)}/redeem`, { secret: invite.secret });
            clearInvite();
            await refreshMe();
        } catch (e) {
            const err = e as Error;
            setError(err instanceof ApiError && err.detail ? `${err.message}: ${err.detail}` : err.message);
            setBusy(false);
        }
    };

    return (
        <div className="gate gate-card">
            <div className="card">
                <img src="/brand/privasys-logo.mini.svg" alt="" className="mark" />
                <h1>{me.register.title || me.register.name}</h1>
                {offer ? (
                    <>
                        <p>
                            You have been invited to this register as <strong>{offer.role_title}</strong>
                            {offer.label ? ` (${offer.label})` : ''}.
                        </p>
                        <p className="note">
                            Accepting is recorded: the register's history will show that this invitation was used, by
                            the identity below, and when. The invitation expires {fmtTime(offer.expires_at)} UTC.
                        </p>
                        <button id="accept-invite" className="primary" disabled={busy} onClick={() => void accept()}>
                            Accept as {offer.role_title}
                        </button>
                    </>
                ) : (
                    <>
                        <p>You are signed in, and you hold no role in this register yet.</p>
                        <p className="note">
                            Ask whoever administers it for an invitation link, or send them the identifier below so
                            they can grant you a role directly. It is the name this register knows you by, and no
                            other service shares it.
                        </p>
                    </>
                )}
                <p className="label">Your identifier here</p>
                <pre id="my-subject">{me.sub}</pre>
                <p id="status-line" className="error">
                    {error || (me.status === 'refused' ? me.refusal : offer ? '' : 'no register role: nothing has been granted to this identity')}
                </p>
                <button onClick={signOut}>Sign out</button>
            </div>
        </div>
    );
}
