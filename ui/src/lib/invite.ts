// Invitation links: https://<host>/#/join/<id>/<secret>.
//
// The secret travels in the fragment, so it never reaches a server log. The
// link is captured before the router starts and removed from the address
// bar; it is kept in this tab's session storage until it is used or
// dismissed, so signing in (which may take a QR scan) does not lose it.

const KEY = 'register.invite';
const LINK = /^#\/join\/([A-Za-z0-9_]{1,64})\/([A-Za-z0-9_-]{20,128})$/;

export interface PendingInvite {
    id: string;
    secret: string;
}

/** Moves an invitation link out of the address bar into session storage. */
export function captureInvite(): void {
    const m = LINK.exec(location.hash);
    if (!m) return;
    try {
        sessionStorage.setItem(KEY, JSON.stringify({ id: m[1], secret: m[2] }));
    } catch {
        /* storage unavailable: the link is simply not remembered */
    }
    history.replaceState(null, '', `${location.pathname}${location.search}#/`);
}

export function pendingInvite(): PendingInvite | null {
    try {
        const raw = sessionStorage.getItem(KEY);
        const v = raw ? (JSON.parse(raw) as PendingInvite) : null;
        return v && typeof v.id === 'string' && typeof v.secret === 'string' ? v : null;
    } catch {
        return null;
    }
}

export function clearInvite(): void {
    try {
        sessionStorage.removeItem(KEY);
    } catch {
        /* nothing to clear */
    }
}

export function inviteLink(id: string, secret: string): string {
    return `${location.origin}/#/join/${id}/${secret}`;
}
