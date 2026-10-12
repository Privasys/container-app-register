// Assembles the static public directory: the brand marks and the vendored
// Privasys auth client. Vite copies it into the build as it is.
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ui = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(ui, '.public');

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

cpSync(join(ui, 'brand'), join(out, 'brand'), { recursive: true });
cpSync(join(ui, 'brand', 'privasys-logo.mini.svg'), join(out, 'favicon.svg'));
cpSync(join(ui, 'vendor'), join(out, 'vendor'), { recursive: true, filter: (src) => !src.endsWith('.md') });
