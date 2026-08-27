// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// Starts a register for the end-to-end suite.
//
// The tests drive the real service, not a mock: the explorer's whole
// claim is that a reader can check a proof for themselves, and a mock
// server would be the one thing incapable of demonstrating it. So this
// builds the binary, wipes the data directory so the seeded content is
// the same every run, and runs it with development authentication on a
// port of its own.

import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const E2E_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(E2E_DIR, '..');
const PORT = process.env.REGISTER_E2E_PORT || '18143';
const DATA_DIR = path.join(E2E_DIR, '.register-data');

// A fresh volume every run. The suite asserts on the pack's seeded
// records, so a register carrying state from a previous run would make
// the tests report on the wrong thing.
rmSync(DATA_DIR, { recursive: true, force: true });

const binDir = mkdtempSync(path.join(tmpdir(), 'register-e2e-'));
const binary = path.join(binDir, process.platform === 'win32' ? 'register.exe' : 'register');

const build = spawnSync('go', ['build', '-o', binary, './cmd/register'], {
  cwd: REPO,
  stdio: 'inherit',
});
if (build.status !== 0) {
  console.error('e2e: could not build the register');
  process.exit(build.status ?? 1);
}

const child = spawn(binary, [], {
  cwd: REPO,
  stdio: 'inherit',
  env: {
    ...process.env,
    PORT,
    REGISTER_DATA_DIR: DATA_DIR,
    REGISTER_DEV_AUTH: '1',
    REGISTER_SELF_CONFIGURE: '1',
    REGISTER_PACK: path.join('packs', 'car-register', 'pack.json'),
    REGISTER_TENANT: 'gov',
    REGISTER_NAME: 'e2e-register',
  },
});

const shutdown = () => {
  child.kill();
  rmSync(binDir, { recursive: true, force: true });
};

for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => {
    shutdown();
    process.exit(0);
  });
}
process.on('exit', shutdown);

child.on('exit', (code) => process.exit(code ?? 0));
