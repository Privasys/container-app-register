// The explorer's views. Each is an ordinary client of the register's REST
// API: everything it shows, an auditor with the same role can fetch for
// themselves.

import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { useSession } from '../lib/session';
import type { Bundle, Check, HistoryEntry, ObjectSummary, Pack, RecordView, SignedCheckpoint, Transaction } from '../lib/types';
import { Json, Table, fmtTime, short, useRun, useStatus } from '../lib/ui';
import { verifyBundle } from '../lib/verify';

/** Something one view asks another to show. */
export type Intent = { kind: 'transaction'; txid: string } | { kind: 'record-proof'; id: string; version: number } | null;

interface ViewProps {
    active: boolean;
    pack: Pack | null;
    intent: Intent;
    go: (view: string, intent?: Intent) => void;
}

function formParams(e: FormEvent<HTMLFormElement> | HTMLFormElement): URLSearchParams {
    const form = e instanceof HTMLFormElement ? e : e.currentTarget;
    const params = new URLSearchParams();
    for (const [k, v] of new FormData(form).entries()) if (v) params.set(k, String(v));
    return params;
}

function Section({ name, active, children }: { name: string; active: boolean; children: ReactNode }) {
    return (
        <section id={`view-${name}`} className={active ? 'view' : 'view hidden'}>
            {children}
        </section>
    );
}

// -- history ---------------------------------------------------------------

export function History({ active, intent }: ViewProps) {
    const { transport, role } = useSession();
    const setStatus = useStatus();
    const run = useRun();
    const [filters, setFilters] = useState('');
    const [list, setList] = useState<Transaction[] | null>(null);
    const [detail, setDetail] = useState<Transaction | null>(null);

    const load = useCallback(
        (query: string) =>
            run(async () => {
                setList(null);
                setDetail(null);
                const params = new URLSearchParams(query);
                params.set('limit', '100');
                const data = await transport.request<{ transactions: Transaction[]; count: number }>('GET', `/api/v1/log?${params}`);
                setList(data.transactions);
                setStatus(`${data.count} transactions`);
            }),
        [transport, run, setStatus]
    );

    const show = useCallback(
        (txid: string) => run(async () => setDetail(await transport.request<Transaction>('GET', `/api/v1/log/${txid}`))),
        [transport, run]
    );

    useEffect(() => {
        if (!active) return;
        void load(filters).then(() => {
            if (intent?.kind === 'transaction') void show(intent.txid);
        });
        // Reloads on entering the view, on a new filter, and under a new role.
    }, [active, filters, role, intent, load, show]);

    return (
        <Section name="log" active={active}>
            <form
                id="log-filters"
                onSubmit={(e) => {
                    e.preventDefault();
                    const next = formParams(e).toString();
                    if (next === filters) void load(next);
                    else setFilters(next);
                }}
            >
                <input name="class" placeholder="Class" />
                <input name="object_id" placeholder="Record" />
                <input name="author" placeholder="Author" />
                <input name="role" placeholder="Role" />
                <input name="kind" placeholder="Kind" />
                <input name="ref_type" placeholder="Reference type" />
                <button type="submit">Filter</button>
            </form>
            <div id="log-list" className="list">
                {list && list.length === 0 && <p className="note">No transactions match.</p>}
                {list?.map((tx) => (
                    <div className="entry" key={tx.txid} onClick={() => void show(tx.txid)}>
                        <span className="id">{short(tx.txid)}</span>
                        <span className="summary">
                            {tx.envelope.message.split('\n')[0]}
                            <span className="kind">{tx.envelope.kind}</span>
                        </span>
                        <span className="who">
                            {tx.envelope.author.role} · {fmtTime(tx.envelope.timestamp)}
                        </span>
                    </div>
                ))}
            </div>
            <div id="log-detail" className="detail">
                {detail && <TransactionDetail tx={detail} />}
            </div>
        </Section>
    );
}

function TransactionDetail({ tx }: { tx: Transaction }) {
    const env = tx.envelope;
    const body = env.message.split('\n').slice(1).join('\n').trim();
    return (
        <>
            <h2>{env.message.split('\n')[0]}</h2>
            <p className="note">
                {env.kind} · {env.author.sub} acting as {env.author.role} · {fmtTime(env.timestamp)}
            </p>
            {body && <pre>{body}</pre>}
            <h3>State</h3>
            <Table
                rows={[
                    ['Transaction', tx.txid],
                    ['Sequence', String(tx.seq)],
                    ['Root before', tx.root_before],
                    ['Ledger version', `${tx.version_before} → ${tx.version_after}`]
                ]}
            />
            <p className="note">
                One commit. There is no "root after" here: a row cannot carry the root of the commit that writes it.
                The root this produced is in the lineage chain, under Checkpoints.
            </p>
            {tx.refs && tx.refs.length > 0 && (
                <>
                    <h3>References</h3>
                    <Table rows={tx.refs.map((r) => [r.type, r.target])} />
                </>
            )}
            <h3>Write set</h3>
            <Json value={tx.write_set} />
        </>
    );
}

// -- records ---------------------------------------------------------------

export function Records({ active, pack, go }: ViewProps) {
    const { transport, role } = useSession();
    const setStatus = useStatus();
    const run = useRun();
    const [filters, setFilters] = useState<string | null>(null);
    const [list, setList] = useState<ObjectSummary[] | null>(null);
    const [detail, setDetail] = useState<{ view: RecordView; history: HistoryEntry[] } | null>(null);

    const load = useCallback(
        (query: string) =>
            run(async () => {
                setList(null);
                setDetail(null);
                const data = await transport.request<{ records: ObjectSummary[]; count: number }>('GET', `/api/v1/records?${query}`);
                setList(data.records);
                setStatus(`${data.count} records`);
            }),
        [transport, run, setStatus]
    );

    // The first class in the pack is what the view opens on.
    const query = filters ?? (pack?.classes[0] ? `class=${encodeURIComponent(pack.classes[0].name)}` : null);

    useEffect(() => {
        if (active && query !== null) void load(query);
    }, [active, query, role, load]);

    const show = (id: string) =>
        run(async () => {
            const [view, history] = await Promise.all([
                transport.request<RecordView>('GET', `/api/v1/records/${id}`),
                transport.request<{ history: HistoryEntry[] }>('GET', `/api/v1/records/${id}/history`)
            ]);
            setDetail({ view, history: history.history });
        });

    return (
        <Section name="records" active={active}>
            <form
                id="record-filters"
                onSubmit={(e) => {
                    e.preventDefault();
                    const next = formParams(e).toString();
                    if (next === query) void load(next);
                    else setFilters(next);
                }}
            >
                <select name="class" id="record-class">
                    {pack?.classes.map((c) => (
                        <option key={c.name} value={c.name}>
                            {c.title || c.name}
                        </option>
                    ))}
                </select>
                <input name="q" placeholder="Natural key starts with" />
                <input name="status" placeholder="Status" />
                <button type="submit">Search</button>
            </form>
            <div id="record-list" className="list">
                {list && list.length === 0 && <p className="note">No records match.</p>}
                {list?.map((rec) => (
                    <div className="entry" key={rec.id} onClick={() => void show(rec.id)}>
                        <span className="id">{rec.natural_key || short(rec.id)}</span>
                        <span className="summary">
                            {rec.class}
                            <span className="kind">
                                {rec.status} · v{rec.head_version}
                            </span>
                        </span>
                        <span className="who">{fmtTime(rec.updated_at)}</span>
                    </div>
                ))}
            </div>
            <div id="record-detail" className="detail">
                {detail && <RecordDetail {...detail} go={go} />}
            </div>
        </Section>
    );
}

const cell = (v: unknown) => (v === null || v === undefined ? '—' : String(v));

function RecordDetail({ view, history, go }: { view: RecordView; history: HistoryEntry[]; go: ViewProps['go'] }) {
    const o = view.object;
    return (
        <>
            <h2>
                {o.class} {o.natural_key || o.id}
            </h2>
            <p className="note">
                {o.status} · version {o.head_version} · {o.id}
            </p>
            {o.erased && (
                <p className="note error">
                    The personal data of this record has been erased. The record, its versions and its proofs remain.
                </p>
            )}
            <h3>Current version</h3>
            <Json value={view.version.payload || {}} />
            {view.version.redacted && view.version.redacted.length > 0 && (
                <p className="note">Withheld from this role: {view.version.redacted.join(', ')}.</p>
            )}
            <h3>Timeline</h3>
            {history.map((entry) => {
                const tx = entry.transaction;
                return (
                    <div key={entry.version.version}>
                        <div className="entry" onClick={tx ? () => go('log', { kind: 'transaction', txid: tx.txid }) : undefined}>
                            <span className="id">v{entry.version.version}</span>
                            <span className="summary">
                                {tx ? tx.envelope.message.split('\n')[0] : '(no transaction)'}
                                <span className="kind">{tx ? tx.envelope.kind : ''}</span>
                            </span>
                            <span className="who">{fmtTime(entry.version.created_at)}</span>
                        </div>
                        {entry.diff && Object.keys(entry.diff).length > 0 && (
                            <table>
                                <tbody>
                                    {Object.entries(entry.diff).map(([field, [before, after]]) => (
                                        <tr key={field}>
                                            <th>{field}</th>
                                            <td>
                                                <span className="diff-del">{cell(before)}</span>
                                            </td>
                                            <td>
                                                <span className="diff-add">{cell(after)}</span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        )}
                        <div className="note">
                            <button onClick={() => go('proofs', { kind: 'record-proof', id: o.id, version: entry.version.version })}>
                                Proof for this version
                            </button>
                        </div>
                    </div>
                );
            })}
        </>
    );
}

// -- proofs ----------------------------------------------------------------

export function Proofs({ active, pack, intent }: ViewProps) {
    const { transport } = useSession();
    const run = useRun();
    const [busy, setBusy] = useState(false);
    const [result, setResult] = useState<{ bundle: Bundle; checks: Check[] } | null>(null);

    const verify = useCallback(
        (path: string) =>
            run(async () => {
                setBusy(true);
                setResult(null);
                try {
                    const [bundle, key] = await Promise.all([
                        transport.request<Bundle>('GET', path),
                        transport.request<{ public_key: string }>('GET', '/api/v1/checkpoints/key')
                    ]);
                    setResult({ bundle, checks: await verifyBundle(bundle, key.public_key) });
                } finally {
                    setBusy(false);
                }
            }),
        [transport, run]
    );

    useEffect(() => {
        if (active && intent?.kind === 'record-proof') {
            void verify(`/api/v1/proofs/records/${encodeURIComponent(intent.id)}/${intent.version}`);
        }
    }, [active, intent, verify]);

    return (
        <Section name="proofs" active={active}>
            <p className="note">
                A proof is checked here, in this page, against the root a signed checkpoint names. The recomputation
                needs nothing from the register beyond the bundle it handed you.
            </p>
            <form
                id="proof-form"
                onSubmit={(e) => {
                    e.preventDefault();
                    const form = new FormData(e.currentTarget);
                    void verify(
                        `/api/v1/proofs/natural-keys/${encodeURIComponent(String(form.get('class')))}/${encodeURIComponent(String(form.get('key')))}`
                    );
                }}
            >
                <select name="class" id="proof-class">
                    {pack?.classes
                        .filter((c) => c.natural_key)
                        .map((c) => (
                            <option key={c.name} value={c.name}>
                                {c.title || c.name}
                            </option>
                        ))}
                </select>
                <input name="key" placeholder="Natural key (VIN, plate…)" required />
                <button type="submit">Fetch and verify</button>
            </form>
            <div id="proof-result" className="detail">
                {busy && <p className="note">Fetching and verifying…</p>}
                {result && <ProofResult {...result} />}
            </div>
        </Section>
    );
}

function ProofResult({ bundle, checks }: { bundle: Bundle; checks: Check[] }) {
    const verdict = checks.every((c) => c.state === 'pass')
        ? { text: 'Verified in this browser', cls: 'pass' }
        : checks.some((c) => c.state === 'fail')
          ? { text: 'Verification failed', cls: 'fail' }
          : { text: 'Partly verified', cls: 'unknown' };
    return (
        <>
            <h2>{bundle.statement}</h2>
            <p>
                <span className={`verdict ${verdict.cls}`}>{verdict.text}</span>
            </p>
            {checks.map((c) => (
                <div className={`check ${c.state}`} key={c.name}>
                    <span className="mark">{c.state === 'pass' ? '✓' : c.state === 'fail' ? '✗' : '?'}</span>
                    <span>
                        <strong>{c.name}</strong> <span className="why">{c.why}</span>
                    </span>
                </div>
            ))}
            <h3>Statement</h3>
            <Table
                rows={[
                    ['Present', String(bundle.present)],
                    ['Ledger version', String(bundle.version)],
                    ['Root', bundle.root],
                    ['Position', bundle.path],
                    ['Signing key', bundle.key_id]
                ]}
            />
            {bundle.row !== undefined && bundle.row !== null && (
                <>
                    <h3>Row</h3>
                    <Json value={bundle.row} />
                </>
            )}
            <h3>Bundle</h3>
            <Json value={bundle} />
        </>
    );
}

// -- checkpoints, retention, health ----------------------------------------

interface Lineage {
    enabled: boolean;
    head: string;
    version: number;
}

export function Checkpoints({ active }: ViewProps) {
    const { transport, role } = useSession();
    const setStatus = useStatus();
    const run = useRun();
    const [key, setKey] = useState<{ key_id: string; alg: string } | null>(null);
    const [lineage, setLineage] = useState<Lineage | { error: string } | null>(null);
    const [list, setList] = useState<SignedCheckpoint[]>([]);

    useEffect(() => {
        if (!active) return;
        void run(async () => {
            setKey(await transport.request('GET', '/api/v1/checkpoints/key'));
            try {
                setLineage(await transport.request<Lineage>('GET', '/api/v1/audit/lineage'));
            } catch (e) {
                setLineage({ error: (e as Error).message });
            }
            const data = await transport.request<{ checkpoints: SignedCheckpoint[]; count: number }>('GET', '/api/v1/checkpoints?limit=100');
            setList(data.checkpoints);
            setStatus(`${data.count} checkpoints`);
        });
    }, [active, role, transport, run, setStatus]);

    return (
        <Section name="checkpoints" active={active}>
            <div id="checkpoint-key" className="note">
                {key && (
                    <div>
                        Verification key <code>{key.key_id}</code> ({key.alg}). Hold this, and the checkpoints below,
                        outside the register.
                    </div>
                )}
                {lineage && 'error' in lineage && <div className="error">Lineage unavailable: {lineage.error}</div>}
                {lineage && 'enabled' in lineage && lineage.enabled && (
                    <div>
                        Lineage head <code>{lineage.head}</code> at version {lineage.version}. Every commit extends a
                        chain over the root sequence, and the head is a leaf, so the live root commits to the whole
                        history behind it. Each checkpoint below carries the head at its version: fold the roots
                        between two of them and you have verified the lineage yourself.
                    </div>
                )}
                {lineage && 'enabled' in lineage && !lineage.enabled && (
                    <div className="error">
                        This register has no lineage chain. It was created before the chain existed, and the choice
                        cannot be changed after the fact.
                    </div>
                )}
            </div>
            <div id="checkpoint-list" className="list">
                {list.map((sc) => {
                    const cp = sc.checkpoint;
                    return (
                        <div className="entry" key={cp.version}>
                            <span className="id">v{cp.version}</span>
                            <span className="summary">
                                {cp.root}
                                <span className="kind">{cp.head ? `${cp.reason} · anchors lineage` : cp.reason}</span>
                            </span>
                            <span className="who">{fmtTime(cp.issued_at)}</span>
                        </div>
                    );
                })}
            </div>
        </Section>
    );
}

interface Horizon {
    policy_id: string;
    title: string;
    class: string;
    scope: string;
    window_days: number;
    horizon: number;
    eligible_versions: number;
    pruned_versions: number;
}

export function Retention({ active }: ViewProps) {
    const { transport, role } = useSession();
    const run = useRun();
    const [policies, setPolicies] = useState<Horizon[] | null>(null);

    useEffect(() => {
        if (!active) return;
        void run(async () => {
            setPolicies(null);
            setPolicies((await transport.request<{ policies: Horizon[] }>('GET', '/api/v1/retention')).policies);
        });
    }, [active, role, transport, run]);

    return (
        <Section name="retention" active={active}>
            <div id="retention-list" className="list">
                {policies && (
                    <table>
                        <tbody>
                            <tr>
                                {['Policy', 'Class', 'Scope', 'Window', 'Horizon', 'Eligible', 'Pruned'].map((h) => (
                                    <th key={h}>{h}</th>
                                ))}
                            </tr>
                            {policies.map((p) => (
                                <tr key={p.policy_id}>
                                    <td>
                                        <strong>{p.policy_id}</strong>
                                        <div className="why">{p.title}</div>
                                    </td>
                                    <td>{p.class}</td>
                                    <td>{p.scope}</td>
                                    <td>{p.window_days} days</td>
                                    <td>{fmtTime(p.horizon)}</td>
                                    <td>{String(p.eligible_versions)}</td>
                                    <td>{String(p.pruned_versions)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </Section>
    );
}

interface Status {
    name: string;
    pack: string;
    pack_version: string;
    image_digest?: string;
    commitment_key_source: string;
    root: string;
    ledger_version: number;
    transactions: number;
    objects: number;
    pending_tasks: number;
    pending_transactions: number;
    pruned_versions: number;
    destroyed_keys: number;
    last_checkpoint?: SignedCheckpoint;
}

export function Health({ active }: ViewProps) {
    const { transport, role } = useSession();
    const run = useRun();
    const [status, setStatus] = useState<Status | null>(null);

    useEffect(() => {
        if (!active) return;
        void run(async () => {
            setStatus(null);
            setStatus(await transport.request<Status>('GET', '/api/v1/status'));
        });
    }, [active, role, transport, run]);

    const rows: [string, ReactNode][] = status
        ? [
              ['Register', status.name],
              ['Pack', `${status.pack} ${status.pack_version}`],
              ['Measurement', status.image_digest || '(not on the platform)'],
              ['Commitment key', status.commitment_key_source],
              ['Root', status.root],
              ['Ledger version', String(status.ledger_version)],
              ['Transactions', String(status.transactions)],
              ['Records', String(status.objects)],
              ['Proposals awaiting action', String(status.pending_tasks)],
              ['Unapplied transactions', String(status.pending_transactions)],
              ['Pruned versions', String(status.pruned_versions)],
              ['Destroyed keys', String(status.destroyed_keys)]
          ]
        : [];
    if (status?.last_checkpoint) {
        const cp = status.last_checkpoint.checkpoint;
        rows.push(['Last checkpoint', `version ${cp.version} at ${fmtTime(cp.issued_at)}`]);
    }

    return (
        <Section name="health" active={active}>
            <div id="health-body" className="detail">
                {status && (
                    <>
                        <h2>Service</h2>
                        <Table rows={rows} />
                    </>
                )}
            </div>
        </Section>
    );
}
