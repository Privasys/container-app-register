import { useCallback, useEffect, useState } from 'react';
import { appVersion, sealed, verifyUrl } from './lib/config';
import { SessionProvider, useSession } from './lib/session';
import type { Pack } from './lib/types';
import { StatusContext, short, useRun, type StatusLine } from './lib/ui';
import { Checkpoints, Health, History, Proofs, Records, Retention, type Intent } from './views/Explorer';
import { Members } from './views/Members';
import { Welcome } from './views/Welcome';

export function App() {
    return (
        <SessionProvider>
            <Console />
        </SessionProvider>
    );
}

/** A person with a role gets the console; anyone else is told where they
 *  stand. */
function Console() {
    const { me } = useSession();
    return me.status === 'member' ? <Shell /> : <Welcome />;
}

const VIEWS: [string, string][] = [
    ['log', 'History'],
    ['records', 'Records'],
    ['proofs', 'Proofs'],
    ['checkpoints', 'Checkpoints'],
    ['retention', 'Retention'],
    ['health', 'Health']
];

const SESSION_NOTE: Record<string, string> = {
    recovering: 'Reconnecting to the enclave…',
    'reapproval-required': 'The register was updated. Approve it in your wallet to continue.',
    'signed-out': 'Your Privasys ID session ended. Sign in again to continue.'
};

function Shell() {
    const { me, role, setRole, signOut, sessionState, transport } = useSession();
    const [view, setView] = useState('log');
    const [intent, setIntent] = useState<Intent>(null);
    const [status, setStatusLine] = useState<StatusLine>({ text: 'connected', error: false });
    const [pack, setPack] = useState<Pack | null>(null);

    const setStatus = useCallback((text: string, error = false) => setStatusLine({ text, error }), []);
    const go = useCallback((next: string, nextIntent: Intent = null) => {
        setIntent(nextIntent);
        setView(next);
    }, []);

    const principal = me.principal!;
    const canManage = me.permissions?.includes('members') ?? false;
    const views = canManage ? [...VIEWS, ['members', 'Members'] as [string, string]] : VIEWS;
    const props = { pack, intent, go };

    return (
        <StatusContext.Provider value={setStatus}>
            <PackLoader onLoad={setPack} />
            <header>
                <h1>
                    <img src="/brand/privasys-logo.mini.svg" alt="" className="mark" />
                    {pack?.title || me.register.title || 'Register'}
                </h1>
                <div id="identity">
                    <span className="who" title={me.sub}>
                        {principal.display && principal.display !== me.sub ? principal.display : short(me.sub)}
                    </span>
                    {principal.roles.length > 1 ? (
                        <select id="acting-role" value={role || principal.acting_role} onChange={(e) => setRole(e.target.value)} title="The role you are acting under">
                            {principal.roles.map((r) => (
                                <option key={r} value={r}>
                                    {me.role_titles?.[r] || r}
                                </option>
                            ))}
                        </select>
                    ) : (
                        <span className="role">{me.role_titles?.[principal.acting_role] || principal.acting_role}</span>
                    )}
                    <button onClick={signOut}>Sign out</button>
                </div>
            </header>

            <nav>
                {views.map(([name, label]) => (
                    <button key={name} data-view={name} className={view === name ? 'active' : ''} onClick={() => go(name)}>
                        {label}
                    </button>
                ))}
            </nav>

            <main>
                <History active={view === 'log'} {...props} />
                <Records active={view === 'records'} {...props} />
                <Proofs active={view === 'proofs'} {...props} />
                <Checkpoints active={view === 'checkpoints'} {...props} />
                <Retention active={view === 'retention'} {...props} />
                <Health active={view === 'health'} {...props} />
                {canManage && <Members active={view === 'members'} />}
            </main>

            <footer>
                <span id="status-line" className={status.error ? 'error' : ''}>
                    {status.text}
                </span>
                <span className="foot">
                    {SESSION_NOTE[sessionState.status] && <span className="error">{SESSION_NOTE[sessionState.status]}</span>}
                    <span>{transport.kind === 'sealed' ? 'Sealed to the enclave' : 'Development instance, not sealed'}</span>
                    {sealed && verifyUrl && (
                        <a href={verifyUrl} target="_blank" rel="noreferrer">
                            Verify this register
                        </a>
                    )}
                    <span>{appVersion}</span>
                </span>
            </footer>
        </StatusContext.Provider>
    );
}

/** The pack decides what the console can show, so it is the register's own
 *  answer rather than anything written into the page. */
function PackLoader({ onLoad }: { onLoad: (pack: Pack) => void }) {
    const { transport, role } = useSession();
    const run = useRun();
    useEffect(() => {
        void run(async () => onLoad(await transport.request<Pack>('GET', '/api/v1/pack')));
    }, [transport, role, run, onLoad]);
    return null;
}
