// Types for the vendored Privasys auth client (window.Privasys), covering
// the surface the register uses.

export interface SealedResponse {
    status: number;
    headers: Record<string, string>;
    body: Uint8Array;
    sealed: boolean;
}

/** Liveness of the sealed session. `ok`: requests flow. `recovering`: the
 *  enclave forgot the session and the SDK is re-establishing it silently.
 *  `reapproval-required`: the enclave refused the stored voucher (the app or
 *  the platform changed), one tap in the wallet is needed. `signed-out`:
 *  the Privasys ID session ended. The last two are answered by calling
 *  `connect()` again on the same frame. */
export type SealedSessionStatus = 'ok' | 'recovering' | 'reapproval-required' | 'signed-out';

export interface SealedSessionState {
    status: SealedSessionStatus;
    reason?: string;
}

export interface SealedSession {
    sessionId: string;
    appHost: string;
    expiresAt: number;
    readonly state: SealedSessionState;
    onState(cb: (state: SealedSessionState) => void): () => void;
    request(method: string, path: string, body?: unknown, init?: RequestInit): Promise<SealedResponse>;
}

export interface ConnectResult {
    accessToken: string;
    session: SealedSession | null;
}

export interface AuthFrameConfig {
    apiBase: string;
    appName: string;
    rpId?: string;
    clientId?: string;
    authOrigin?: string;
    brokerUrl?: string;
    scope?: readonly string[];
    container?: HTMLElement;
    presentation?: 'modal' | 'inline' | 'page';
    methods?: readonly ('wallet' | 'passkey' | 'social')[];
    pitch?: { title?: string; description?: string; bullets?: string[]; logoUrl?: string };
    app?: { logoUrl?: string; displayName?: string };
    sessionRelay?: { appHost: string };
}

export interface AuthFrame {
    /** Silent restore, one-tap re-approval, or the full sign-in, whichever
     *  the situation needs. Call it again to recover a session whose state
     *  is `reapproval-required` or `signed-out`: the same session object
     *  keeps working afterwards. */
    connect(options?: { container?: HTMLElement }): Promise<ConnectResult>;
    /** An access token for one audience (an app's hostname or `app:<id>`),
     *  minted from the signed-in session; the runtime on a direct name
     *  accepts it for that app only. Requires a session: after `connect()`. */
    getTokenForAudience(audience: string): Promise<string>;
    clearSession(): Promise<void>;
    cancel(): void;
    destroy(): void;
}

declare global {
    interface Window {
        Privasys?: { AuthFrame: new (config: AuthFrameConfig) => AuthFrame };
    }
}
