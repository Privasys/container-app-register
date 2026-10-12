// Small shared pieces: the status line every view reports through, and the
// formatting the console uses throughout.

import { createContext, useCallback, useContext, type ReactNode } from 'react';
import { ApiError } from './transport';

export const fmtTime = (unix?: number) => (unix ? new Date(unix * 1000).toISOString().replace('T', ' ').slice(0, 19) : '');
export const short = (hash?: string) => (hash ? hash.slice(0, 12) : '');

export interface StatusLine {
    text: string;
    error: boolean;
}

export const StatusContext = createContext<(text: string, error?: boolean) => void>(() => undefined);

/** Reports where a view got to, in the footer. */
export function useStatus() {
    return useContext(StatusContext);
}

/** Runs a loader and puts whatever it throws on the status line, with the
 *  register's own explanation when it gave one. */
export function useRun() {
    const setStatus = useStatus();
    return useCallback(
        async (fn: () => Promise<void>) => {
            try {
                await fn();
            } catch (e) {
                const err = e as Error;
                const detail = err instanceof ApiError ? err.detail : undefined;
                setStatus(detail ? `${err.message} — ${detail}` : err.message, true);
            }
        },
        [setStatus]
    );
}

export function Table({ rows }: { rows: [string, ReactNode][] }) {
    return (
        <table>
            <tbody>
                {rows.map(([k, v], i) => (
                    <tr key={i}>
                        <th>{k}</th>
                        <td>
                            <span className="hash">{v}</span>
                        </td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
}

export function Json({ value }: { value: unknown }) {
    return <pre>{JSON.stringify(value, null, 2)}</pre>;
}
