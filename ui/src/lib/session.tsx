// The signed-in session: the sign-in gate, the sealed transport, and who the
// caller is to this register.
//
// One AuthFrame for the life of the page. `connect()` does the whole job
// (silent restore, one-tap re-approval, or the full sign-in) and the sealed
// session it returns recovers itself when the enclave forgets it. This
// provider only follows the session's liveness: it shows the gate again,
// over the console, when the enclave needs the holder, and never tears the
// console down on a transport blip.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { authConfig, direct, sealed } from './config';
import type { AuthFrame, SealedSessionState } from './privasys';
import { ApiError, bearerTransport, devTransport, sealedTransport, type Transport } from './transport';
import type { Me } from './types';

interface SessionValue {
    transport: Transport;
    me: Me;
    /** The role requests are made under; empty takes the register's default. */
    role: string;
    setRole: (role: string) => void;
    /** Liveness of the sealed session (always ok on a development instance). */
    sessionState: SealedSessionState;
    refreshMe: () => Promise<void>;
    signOut: () => void;
}

const SessionContext = createContext<SessionValue | null>(null);

export function useSession(): SessionValue {
    const v = useContext(SessionContext);
    if (!v) throw new Error('useSession outside SessionProvider');
    return v;
}

const TOKEN_KEY = 'register.token';
const ROLE_KEY = 'register.role';

function stored(key: string): string {
    try {
        return sessionStorage.getItem(key) ?? '';
    } catch {
        return '';
    }
}

function store(key: string, value: string): void {
    try {
        if (value) sessionStorage.setItem(key, value);
        else sessionStorage.removeItem(key);
    } catch {
        /* storage unavailable: the choice lasts for this page only */
    }
}

const PITCH = {
    title: 'A register that can prove what it holds.',
    description:
        'Every change is a signed transaction with an author and a reason. Every record comes with a proof ' +
        'you can check in your own browser, against a root the register cannot quietly rewrite.',
    bullets: [
        'Sealed browser-to-enclave transport. The network and the host see only ciphertext.',
        'The page you are about to use is part of the measured build, and anyone can check which build that is.',
        'Sign in with the Privasys Wallet. No passwords.'
    ]
};

/** On a direct adopter name the page's own TLS ends in the enclave, and
 *  people sign in with an identity they already have. */
const DIRECT_PITCH = {
    title: 'A register that can prove what it holds.',
    description:
        'Every change is a signed transaction with an author and a reason. Every record comes with a proof ' +
        'you can check in your own browser, against a root the register cannot quietly rewrite.',
    bullets: [
        'Your connection ends inside the enclave: the network and the host see only ciphertext.',
        'The page you are about to use is part of the measured build, and anyone can check which build that is.',
        'Sign in with your work account.'
    ]
};

/** The register runs on the platform, under one of its two sign-in modes. */
const onPlatform = sealed || direct;

type Phase = 'dev-pick' | 'connecting' | 'ready' | 'error';

const OK: SealedSessionState = { status: 'ok' };

function describe(e: unknown): string {
    const err = e as Error & { code?: string; detail?: string };
    if (err.code === 'cancelled') return 'Sign-in was cancelled.';
    if (err.code === 'timeout') return 'The sign-in was not completed in time. Try again.';
    if (err instanceof ApiError && err.detail) return `${err.message}: ${err.detail}`;
    return err.message || 'The connection to the register failed.';
}

export function SessionProvider({ children }: { children: ReactNode }) {
    const gateRef = useRef<HTMLDivElement>(null);
    const frameRef = useRef<AuthFrame | null>(null);
    const connecting = useRef(false);
    const recovering = useRef(false);
    const roleRef = useRef(stored(ROLE_KEY));
    const [phase, setPhase] = useState<Phase>(onPlatform || stored(TOKEN_KEY) ? 'connecting' : 'dev-pick');
    const [error, setError] = useState('');
    const [transport, setTransport] = useState<Transport | null>(null);
    const [me, setMe] = useState<Me | null>(null);
    const [role, setRoleState] = useState(roleRef.current);
    const [attempt, setAttempt] = useState(0);
    const [sessionState, setSessionState] = useState<SealedSessionState>(OK);
    // The holder is being asked again (one tap in the wallet, or a new
    // sign-in): the gate shows over the console, which stays mounted.
    const [reapproving, setReapproving] = useState(false);

    const retry = useCallback(() => {
        setPhase('connecting');
        setAttempt((n) => n + 1);
    }, []);

    /** The one AuthFrame of this page, created on first use. */
    const frame = useCallback((): AuthFrame => {
        if (frameRef.current) return frameRef.current;
        const Frame = window.Privasys?.AuthFrame;
        if (!Frame) throw new Error('The Privasys sign-in client did not load. Reload the page.');
        const logoUrl = `${location.origin}/brand/privasys-logo.mini.svg`;
        const f = new Frame({
            apiBase: authConfig.apiBase,
            authOrigin: authConfig.authOrigin,
            rpId: authConfig.rpId,
            clientId: authConfig.clientId,
            appName: authConfig.appName,
            brokerUrl: authConfig.brokerUrl,
            // Signing in is all the register asks for. Who a person is to
            // the register is the role someone granted them here.
            scope: ['openid', 'offline_access'],
            container: gateRef.current ?? undefined,
            presentation: 'page',
            app: { displayName: 'Register', logoUrl },
            // On the platform hostname the wallet opens a sealed session to
            // the enclave. On a direct adopter name TLS already ends in the
            // enclave, so a federated sign-in suffices: the page then sends
            // an app token over its own origin and the runtime identifies
            // the caller.
            ...(direct
                ? { methods: ['social'] as const, pitch: { ...DIRECT_PITCH, logoUrl } }
                : {
                      sessionRelay: { appHost: authConfig.appHost },
                      methods: ['wallet'] as const,
                      pitch: { ...PITCH, logoUrl }
                  })
        });
        frameRef.current = f;
        return f;
    }, []);

    const fetchMe = useCallback((t: Transport) => t.request<Me>('GET', '/api/v1/me'), []);

    // First connection: sign in (or restore silently) and learn who we are.
    useEffect(() => {
        if (phase !== 'connecting' || connecting.current) return;
        connecting.current = true;
        let cancelled = false;
        (async () => {
            try {
                let t: Transport;
                if (sealed) {
                    const res = await frame().connect();
                    if (!res.session) throw new Error('The secure session could not be established.');
                    t = sealedTransport(res.session, () => roleRef.current);
                    setSessionState(res.session.state);
                } else if (direct) {
                    const f = frame();
                    await f.connect();
                    // The token names this page's own host as its audience;
                    // the runtime accepts it for this app alone.
                    t = bearerTransport(() => f.getTokenForAudience(location.host), () => roleRef.current);
                } else {
                    t = devTransport(stored(TOKEN_KEY), () => roleRef.current);
                }
                const who = await fetchMe(t);
                if (cancelled) return;
                setTransport(t);
                setMe(who);
                setPhase('ready');
            } catch (e) {
                if (cancelled) return;
                setError(describe(e));
                // A development token that was refused goes back to the
                // form it came from, which says why.
                setPhase(onPlatform ? 'error' : 'dev-pick');
            } finally {
                connecting.current = false;
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [phase, attempt, frame, fetchMe]);

    // The enclave needs the holder again (the app or platform changed, or
    // the Privasys ID session ended): run the gate on the same frame. The
    // session object, and so the transport, stays the same.
    const recover = useCallback(async () => {
        if (recovering.current) return;
        recovering.current = true;
        setReapproving(true);
        try {
            const res = await frame().connect({ container: gateRef.current ?? undefined });
            if (!res.session) throw new Error('The secure session could not be established.');
            setSessionState(res.session.state);
            if (transport) setMe(await fetchMe(transport));
        } catch (e) {
            setError(describe(e));
            setPhase('error');
        } finally {
            recovering.current = false;
            setReapproving(false);
        }
    }, [frame, transport, fetchMe]);

    // Follow the sealed session's liveness.
    useEffect(() => {
        const session = transport?.session;
        if (!session) return;
        setSessionState(session.state);
        return session.onState((s) => {
            setSessionState(s);
            if (s.status === 'reapproval-required' || s.status === 'signed-out') void recover();
        });
    }, [transport, recover]);

    const refreshMe = useCallback(async () => {
        if (transport) setMe(await fetchMe(transport));
    }, [transport, fetchMe]);

    const setRole = useCallback(
        (next: string) => {
            roleRef.current = next;
            store(ROLE_KEY, next);
            setRoleState(next);
            void refreshMe();
        },
        [refreshMe]
    );

    const signOut = useCallback(() => {
        store(ROLE_KEY, '');
        if (!onPlatform) {
            store(TOKEN_KEY, '');
            location.reload();
            return;
        }
        const f = frameRef.current;
        (f ? f.clearSession() : Promise.resolve()).finally(() => location.reload());
    }, []);

    const value = useMemo(
        () => (transport && me ? { transport, me, role, setRole, sessionState, refreshMe, signOut } : null),
        [transport, me, role, setRole, sessionState, refreshMe, signOut]
    );

    const gateShown = onPlatform && (phase !== 'ready' || reapproving);

    return (
        <>
            {/* The SDK renders its sign-in surface here. It stays mounted
                once signed in so nothing the SDK attached is torn down, and
                shows again, over the console, when the holder is needed. */}
            <div ref={gateRef} className={gateShown ? 'gate' : 'hidden'} />
            {sealed && phase === 'connecting' && (
                <div className="gate-hint">
                    Connecting to the register. If your phone shows a Privasys approval request, approve it there.
                </div>
            )}
            {direct && phase === 'connecting' && (
                <div className="gate-hint">Connecting to the register. Sign in with your work account when asked.</div>
            )}
            {phase === 'error' && (
                <div className="gate gate-card">
                    <div className="card">
                        <img src="/brand/privasys-logo.mini.svg" alt="" className="mark" />
                        <p>{error}</p>
                        <button className="primary" onClick={retry}>
                            Try again
                        </button>
                    </div>
                </div>
            )}
            {phase === 'dev-pick' && (
                <DevPicker
                    error={error}
                    onPick={(token, pickedRole) => {
                        store(TOKEN_KEY, token);
                        roleRef.current = pickedRole;
                        store(ROLE_KEY, pickedRole);
                        setRoleState(pickedRole);
                        setError('');
                        retry();
                    }}
                />
            )}
            {value && <SessionContext.Provider value={value}>{children}</SessionContext.Provider>}
        </>
    );
}

const PERSONAS = ['registrar', 'clerk', 'police', 'insurer', 'auditor', 'dpo', 'operator'];

/** The stand-in for sign-in on a development instance, which verifies
 *  nothing: it takes a token that names a subject and the identity-provider
 *  roles to pretend it carries. The register refuses to run this way on the
 *  platform. */
function DevPicker({ error, onPick }: { error: string; onPick: (token: string, role: string) => void }) {
    const [token, setToken] = useState(stored(TOKEN_KEY));
    const [role, setRole] = useState(stored(ROLE_KEY));
    return (
        <div className="gate gate-card">
            <form
                className="card"
                onSubmit={(e) => {
                    e.preventDefault();
                    if (token.trim()) onPick(token.trim(), role.trim());
                }}
            >
                <img src="/brand/privasys-logo.mini.svg" alt="" className="mark" />
                <h1>Register</h1>
                <p className="label">Development instance</p>
                <p className="note">
                    This register is not on the platform, so nobody signs in: it takes a stand-in token and believes
                    it. Pick a persona, or paste a token.
                </p>
                <div className="personas">
                    {PERSONAS.map((p) => (
                        <button type="button" key={p} onClick={() => onPick(`dev:${p}-1:${p[0].toUpperCase()}${p.slice(1)}:register:${p}`, '')}>
                            {p}
                        </button>
                    ))}
                </div>
                <input
                    id="token"
                    type="password"
                    placeholder="dev:<subject>:<name>:<roles>"
                    autoComplete="off"
                    spellCheck={false}
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                />
                <input
                    id="role"
                    type="text"
                    placeholder="Acting role (optional)"
                    autoComplete="off"
                    spellCheck={false}
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                />
                <button id="connect" className="primary">
                    Connect
                </button>
                {error && (
                    <p id="status-line" className="error">
                        {error}
                    </p>
                )}
            </form>
        </div>
    );
}
