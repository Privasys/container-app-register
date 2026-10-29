// The shapes the register's API returns, as far as the console reads them.

export interface Principal {
    sub: string;
    display?: string;
    tenant: string;
    roles: string[];
    acting_role: string;
    pii: boolean;
}

export interface Me {
    status: 'member' | 'no_role' | 'refused';
    sub: string;
    display?: string;
    tenant: string;
    refusal?: string;
    /** How the person signed in, on a direct name: `verified` by the wallet
     *  after it checked this enclave's attestation, or `unverified` for a
     *  passkey or federated sign-in. Absent on other legs. */
    assurance?: 'verified' | 'unverified';
    register: { name: string; pack: string; title?: string };
    principal?: Principal;
    permissions?: string[];
    role_titles?: Record<string, string>;
}

export interface PackClass {
    name: string;
    title?: string;
    natural_key?: string;
}

export interface Pack {
    name: string;
    title?: string;
    version?: string;
    classes: PackClass[];
}

export interface Envelope {
    kind: string;
    message: string;
    timestamp: number;
    author: { sub: string; display?: string; role: string };
}

export interface Transaction {
    txid: string;
    seq: number;
    envelope: Envelope;
    root_before: string;
    version_before: number;
    version_after: number;
    refs?: { type: string; target: string }[];
    write_set?: unknown;
}

export interface ObjectSummary {
    id: string;
    class: string;
    natural_key?: string;
    status: string;
    head_version: number;
    updated_at: number;
    erased?: boolean;
}

export interface RecordVersion {
    version: number;
    created_at: number;
    payload?: Record<string, unknown>;
    redacted?: string[];
}

export interface RecordView {
    object: ObjectSummary;
    version: RecordVersion;
}

export interface HistoryEntry {
    version: RecordVersion;
    transaction?: Transaction;
    diff?: Record<string, [unknown, unknown]>;
}

export interface Bundle {
    statement: string;
    present: boolean;
    version: number;
    root: string;
    path: string;
    key_id: string;
    row?: unknown;
}

export interface Check {
    name: string;
    state: 'pass' | 'fail' | 'unknown';
    why: string;
}

export interface SignedCheckpoint {
    checkpoint: { version: number; root: string; reason: string; issued_at: number; head?: string };
}

export interface RoleSpec {
    name: string;
    title?: string;
    permissions: string[];
    pii?: boolean;
    incompatible_with?: string[];
}

export interface Member {
    sub: string;
    role: string;
    display?: string;
    granted_by: string;
    granted_at: number;
}

export interface Invite {
    id: string;
    role: string;
    label?: string;
    created_by: string;
    created_at: number;
    expires_at: number;
    used_by?: string;
    used_at?: number;
    status: 'open' | 'used' | 'expired' | 'revoked';
}
