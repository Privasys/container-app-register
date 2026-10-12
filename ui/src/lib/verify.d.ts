import type { Bundle, Check } from './types';

/** Recomputes the root from the proof and checks the register's signature,
 *  in this browser. */
export function verifyBundle(bundle: Bundle, publicKeyB64: string): Promise<Check[]>;
export function verifyProof(bundle: Bundle): Promise<unknown>;
export function canonical(value: unknown): string;
export function bytesToHex(bytes: Uint8Array): string;
