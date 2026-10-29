// How the browser talks to the register.
//
// On the platform every request is sealed end to end to the enclave through
// the Privasys session: the network, the gateway and the host only ever
// carry ciphertext, and the enclave tells the register who is calling. The
// session recovers itself when the enclave forgets it (idle, restart); the
// SessionProvider follows its liveness and runs the one-tap re-approval when
// the enclave needs the holder. A development instance takes a plain
// transport with a stand-in bearer token instead.

import type { SealedSession, SealedResponse } from './privasys';

export class ApiError extends Error {
    constructor(
        public status: number,
        message: string,
        public detail?: string
    ) {
        super(message);
        this.name = 'ApiError';
    }
}

export interface Transport {
    kind: 'sealed' | 'direct' | 'dev';
    /** The sealed session behind a sealed transport (its liveness is what
     *  the footer shows and what recovery follows). */
    session?: SealedSession;
    request<T>(method: string, path: string, body?: unknown): Promise<T>;
}

const REQUEST_TIMEOUT_MS = 30_000;
const decoder = new TextDecoder();

function parseBody(bytes: Uint8Array | undefined): unknown {
    const text = bytes && bytes.byteLength ? decoder.decode(bytes) : '';
    if (!text) return {};
    try {
        return JSON.parse(text);
    } catch {
        return { error: text };
    }
}

function errorOf(status: number, parsed: unknown): ApiError {
    const body = (parsed ?? {}) as { error?: string; detail?: string };
    return new ApiError(status, body.error || `HTTP ${status}`, body.detail);
}

/** The acting role rides in the query string: the register reads it from
 *  there as well as from a header, and a sealed request carries no headers
 *  of the page's own. */
function withRole(path: string, role: string): string {
    if (!role) return path;
    return `${path}${path.includes('?') ? '&' : '?'}role=${encodeURIComponent(role)}`;
}

export function sealedTransport(session: SealedSession, role: () => string): Transport {
    return {
        kind: 'sealed',
        session,
        async request<T>(method: string, path: string, body?: unknown): Promise<T> {
            const res = await new Promise<SealedResponse>((resolve, reject) => {
                const t = setTimeout(
                    () => reject(new ApiError(0, 'The register is not responding. It may be restarting.')),
                    REQUEST_TIMEOUT_MS
                );
                session.request(method, withRole(path, role()), body).then(
                    (r) => {
                        clearTimeout(t);
                        resolve(r);
                    },
                    (e: unknown) => {
                        clearTimeout(t);
                        reject(e instanceof Error ? e : new Error(String(e)));
                    }
                );
            });
            if (typeof res.status !== 'number') {
                throw new ApiError(0, 'The secure channel is not ready yet. Try again.');
            }
            const parsed = parseBody(res.body);
            if (res.status === 401 && !res.sealed) {
                // The enclave no longer knows this session and the SDK could
                // not rebind it silently just now; it keeps trying, and the
                // session's state says whether the holder is needed.
                throw new ApiError(401, 'The secure session is being re-established. Try again in a moment.');
            }
            if (res.status < 200 || res.status >= 300) throw errorOf(res.status, parsed);
            return parsed as T;
        }
    };
}

/** Seconds before expiry at which a cached app token is renewed. */
const TOKEN_RENEWAL_MARGIN_S = 60;

function tokenExpiry(token: string): number {
    try {
        const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))) as { exp?: number };
        return typeof payload.exp === 'number' ? payload.exp : 0;
    } catch {
        return 0;
    }
}

/** On a direct adopter name the page talks to its own origin over TLS that
 *  ends in the enclave. It carries a privasys.id token minted for this app;
 *  the runtime verifies it and tells the register who is calling, and how
 *  they signed in. The token is renewed from the auth frame shortly before
 *  it expires, and once more if the enclave refuses it. */
export function bearerTransport(mint: () => Promise<string>, role: () => string): Transport {
    let token = '';
    let expiresAt = 0;
    async function current(force = false): Promise<string> {
        const now = Math.floor(Date.now() / 1000);
        if (force || !token || expiresAt - now < TOKEN_RENEWAL_MARGIN_S) {
            token = await mint();
            expiresAt = tokenExpiry(token);
        }
        return token;
    }
    async function send(method: string, path: string, body: unknown, bearer: string): Promise<Response> {
        return fetch(withRole(path, role()), {
            method,
            headers: {
                Authorization: `Bearer ${bearer}`,
                ...(body !== undefined ? { 'Content-Type': 'application/json' } : {})
            },
            body: body !== undefined ? JSON.stringify(body) : undefined
        });
    }
    return {
        kind: 'direct',
        async request<T>(method: string, path: string, body?: unknown): Promise<T> {
            let res = await send(method, path, body, await current());
            if (res.status === 401) res = await send(method, path, body, await current(true));
            const parsed = parseBody(new Uint8Array(await res.arrayBuffer()));
            if (!res.ok) throw errorOf(res.status, parsed);
            return parsed as T;
        }
    };
}

export function devTransport(token: string, role: () => string): Transport {
    return {
        kind: 'dev',
        async request<T>(method: string, path: string, body?: unknown): Promise<T> {
            const res = await fetch(withRole(path, role()), {
                method,
                headers: {
                    Authorization: `Bearer ${token}`,
                    ...(body !== undefined ? { 'Content-Type': 'application/json' } : {})
                },
                body: body !== undefined ? JSON.stringify(body) : undefined
            });
            const parsed = parseBody(new Uint8Array(await res.arrayBuffer()));
            if (!res.ok) throw errorOf(res.status, parsed);
            return parsed as T;
        }
    };
}
