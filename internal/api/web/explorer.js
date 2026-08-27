// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// The operator explorer. It is an ordinary client of the register's
// REST API: everything it shows, an auditor with the same token can
// fetch for themselves.

const state = {
  token: sessionStorage.getItem('register.token') || '',
  role: sessionStorage.getItem('register.role') || '',
  pack: null,
  verificationKey: null,
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of children) {
    if (child == null) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
};

function setStatus(text, isError) {
  const line = $('#status-line');
  line.textContent = text;
  line.className = isError ? 'error' : '';
}

async function api(path, options = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (state.role) headers['X-Register-Role'] = state.role;
  const resp = await fetch(path, Object.assign({}, options, { headers }));
  const text = await resp.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (_) { body = { error: text }; }
  if (!resp.ok) {
    const err = new Error((body && body.error) || `HTTP ${resp.status}`);
    err.detail = body && body.detail;
    err.status = resp.status;
    throw err;
  }
  return body;
}

const fmtTime = (unix) => (unix ? new Date(unix * 1000).toISOString().replace('T', ' ').slice(0, 19) : '');
const short = (hash) => (hash ? hash.slice(0, 12) : '');

// -- history ---------------------------------------------------------------

async function loadLog() {
  const form = $('#log-filters');
  const params = new URLSearchParams();
  for (const [k, v] of new FormData(form).entries()) if (v) params.set(k, v);
  params.set('limit', '100');
  const list = $('#log-list');
  list.replaceChildren();
  $('#log-detail').replaceChildren();
  const data = await api(`/api/v1/log?${params}`);
  if (!data.transactions.length) {
    list.append(el('p', { class: 'note', text: 'No transactions match.' }));
    return;
  }
  for (const tx of data.transactions) {
    list.append(el('div', { class: 'entry', onclick: () => showTransaction(tx.txid) },
      el('span', { class: 'id', text: short(tx.txid) }),
      el('span', { class: 'summary' },
        tx.envelope.message.split('\n')[0],
        el('span', { class: 'kind', text: tx.envelope.kind })),
      el('span', { class: 'who', text: `${tx.envelope.author.role} · ${fmtTime(tx.envelope.timestamp)}` }),
    ));
  }
  setStatus(`${data.count} transactions`);
}

async function showTransaction(txid) {
  const detail = $('#log-detail');
  detail.replaceChildren(el('p', { class: 'note', text: 'Loading…' }));
  const tx = await api(`/api/v1/log/${txid}`);
  const env = tx.envelope;
  const body = env.message.split('\n').slice(1).join('\n').trim();
  const nodes = [
    el('h2', { text: env.message.split('\n')[0] }),
    el('p', { class: 'note', text: `${env.kind} · ${env.author.sub} acting as ${env.author.role} · ${fmtTime(env.timestamp)}` }),
  ];
  if (body) nodes.push(el('pre', { text: body }));

  nodes.push(el('h3', { text: 'State' }));
  nodes.push(table([
    ['Transaction', tx.txid],
    ['Sequence', String(tx.seq)],
    ['Root before', tx.root_before],
    ['Root after', tx.root_after],
    ['Ledger version', `${tx.version_before} → ${tx.version_after}`],
  ]));

  if (tx.refs && tx.refs.length) {
    nodes.push(el('h3', { text: 'References' }));
    nodes.push(table(tx.refs.map((r) => [r.type, r.target])));
  }

  nodes.push(el('h3', { text: 'Write set' }));
  nodes.push(el('pre', { text: JSON.stringify(tx.write_set, null, 2) }));
  detail.replaceChildren(...nodes);
}

function table(rows) {
  return el('table', {}, ...rows.map(([k, v]) =>
    el('tr', {}, el('th', { text: k }), el('td', {}, el('span', { class: 'hash', text: String(v) })))));
}

// -- records ---------------------------------------------------------------

async function loadPack() {
  state.pack = await api('/api/v1/pack');
  for (const select of [$('#record-class'), $('#proof-class')]) {
    select.replaceChildren();
    const classes = select.id === 'proof-class'
      ? state.pack.classes.filter((c) => c.natural_key)
      : state.pack.classes;
    for (const c of classes) {
      select.append(el('option', { value: c.name, text: c.title || c.name }));
    }
  }
}

async function loadRecords() {
  const params = new URLSearchParams();
  for (const [k, v] of new FormData($('#record-filters')).entries()) if (v) params.set(k, v);
  const list = $('#record-list');
  list.replaceChildren();
  $('#record-detail').replaceChildren();
  const data = await api(`/api/v1/records?${params}`);
  if (!data.records.length) {
    list.append(el('p', { class: 'note', text: 'No records match.' }));
    return;
  }
  for (const rec of data.records) {
    list.append(el('div', { class: 'entry', onclick: () => showRecord(rec.id) },
      el('span', { class: 'id', text: rec.natural_key || short(rec.id) }),
      el('span', { class: 'summary' }, rec.class,
        el('span', { class: 'kind', text: `${rec.status} · v${rec.head_version}` })),
      el('span', { class: 'who', text: fmtTime(rec.updated_at) }),
    ));
  }
  setStatus(`${data.count} records`);
}

async function showRecord(id) {
  const detail = $('#record-detail');
  detail.replaceChildren(el('p', { class: 'note', text: 'Loading…' }));
  const [view, history] = await Promise.all([
    api(`/api/v1/records/${id}`),
    api(`/api/v1/records/${id}/history`),
  ]);
  const nodes = [
    el('h2', { text: `${view.object.class} ${view.object.natural_key || view.object.id}` }),
    el('p', { class: 'note', text: `${view.object.status} · version ${view.object.head_version} · ${view.object.id}` }),
  ];
  if (view.object.erased) {
    nodes.push(el('p', { class: 'note error',
      text: 'The personal data of this record has been erased. The record, its versions and its proofs remain.' }));
  }
  nodes.push(el('h3', { text: 'Current version' }));
  nodes.push(el('pre', { text: JSON.stringify(view.version.payload || {}, null, 2) }));
  if (view.version.redacted && view.version.redacted.length) {
    nodes.push(el('p', { class: 'note',
      text: `Withheld from this role: ${view.version.redacted.join(', ')}.` }));
  }

  nodes.push(el('h3', { text: 'Timeline' }));
  for (const entry of history.history) {
    const tx = entry.transaction;
    const line = el('div', { class: 'entry' },
      el('span', { class: 'id', text: `v${entry.version.version}` }),
      el('span', { class: 'summary' },
        tx ? tx.envelope.message.split('\n')[0] : '(no transaction)',
        el('span', { class: 'kind', text: tx ? tx.envelope.kind : '' })),
      el('span', { class: 'who', text: fmtTime(entry.version.created_at) }),
    );
    if (tx) line.addEventListener('click', () => { switchView('log'); showTransaction(tx.txid); });
    nodes.push(line);
    if (entry.diff && Object.keys(entry.diff).length) {
      const rows = Object.entries(entry.diff).map(([field, [before, after]]) =>
        el('tr', {},
          el('th', { text: field }),
          el('td', {}, el('span', { class: 'diff-del', text: before === null || before === undefined ? '—' : String(before) })),
          el('td', {}, el('span', { class: 'diff-add', text: after === null || after === undefined ? '—' : String(after) }))));
      nodes.push(el('table', {}, ...rows));
    }
    nodes.push(el('div', { class: 'note' },
      el('button', { text: 'Proof for this version',
        onclick: () => showRecordProof(id, entry.version.version) })));
  }
  detail.replaceChildren(...nodes);
}

// -- proofs ----------------------------------------------------------------

async function ensureVerificationKey() {
  if (!state.verificationKey) {
    const key = await api('/api/v1/checkpoints/key');
    state.verificationKey = key.public_key;
  }
  return state.verificationKey;
}

function renderChecks(container, bundle, checks) {
  const verdict = checks.every((c) => c.state === 'pass')
    ? { text: 'Verified in this browser', cls: 'pass' }
    : checks.some((c) => c.state === 'fail')
      ? { text: 'Verification failed', cls: 'fail' }
      : { text: 'Partly verified', cls: 'unknown' };

  const nodes = [
    el('h2', { text: bundle.statement }),
    el('p', {}, el('span', { class: `verdict ${verdict.cls}`, text: verdict.text })),
  ];
  for (const c of checks) {
    nodes.push(el('div', { class: `check ${c.state}` },
      el('span', { class: 'mark', text: c.state === 'pass' ? '✓' : c.state === 'fail' ? '✗' : '?' }),
      el('span', {}, el('strong', { text: c.name }), ' ', el('span', { class: 'why', text: c.why }))));
  }
  nodes.push(el('h3', { text: 'Statement' }));
  nodes.push(table([
    ['Present', String(bundle.present)],
    ['Ledger version', String(bundle.version)],
    ['Root', bundle.root],
    ['Position', bundle.path],
    ['Signing key', bundle.key_id],
  ]));
  if (bundle.row) {
    nodes.push(el('h3', { text: 'Row' }));
    nodes.push(el('pre', { text: JSON.stringify(bundle.row, null, 2) }));
  }
  nodes.push(el('h3', { text: 'Bundle' }));
  nodes.push(el('pre', { text: JSON.stringify(bundle, null, 2) }));
  container.replaceChildren(...nodes);
}

async function showNaturalKeyProof(cls, key) {
  const out = $('#proof-result');
  out.replaceChildren(el('p', { class: 'note', text: 'Fetching and verifying…' }));
  const [bundle, publicKey] = await Promise.all([
    api(`/api/v1/proofs/natural-keys/${encodeURIComponent(cls)}/${encodeURIComponent(key)}`),
    ensureVerificationKey(),
  ]);
  renderChecks(out, bundle, await RegisterVerify.verifyBundle(bundle, publicKey));
}

async function showRecordProof(id, version) {
  switchView('proofs');
  const out = $('#proof-result');
  out.replaceChildren(el('p', { class: 'note', text: 'Fetching and verifying…' }));
  const [bundle, publicKey] = await Promise.all([
    api(`/api/v1/proofs/records/${encodeURIComponent(id)}/${version}`),
    ensureVerificationKey(),
  ]);
  renderChecks(out, bundle, await RegisterVerify.verifyBundle(bundle, publicKey));
}

// -- checkpoints, retention, health ----------------------------------------

async function loadCheckpoints() {
  const key = await api('/api/v1/checkpoints/key');
  state.verificationKey = key.public_key;
  $('#checkpoint-key').replaceChildren(
    el('span', {}, 'Verification key ',
      el('code', { text: key.key_id }), ' (', key.alg, '). ',
      'Hold this, and the checkpoints below, outside the register.'));

  const data = await api('/api/v1/checkpoints?limit=100');
  const list = $('#checkpoint-list');
  list.replaceChildren();
  for (const sc of data.checkpoints) {
    const cp = sc.checkpoint;
    list.append(el('div', { class: 'entry' },
      el('span', { class: 'id', text: `v${cp.version}` }),
      el('span', { class: 'summary' }, cp.root,
        el('span', { class: 'kind', text: cp.reason })),
      el('span', { class: 'who', text: fmtTime(cp.issued_at) })));
  }
  setStatus(`${data.count} checkpoints`);
}

async function loadRetention() {
  const data = await api('/api/v1/retention');
  const list = $('#retention-list');
  list.replaceChildren(el('table', {},
    el('tr', {}, ...['Policy', 'Class', 'Scope', 'Window', 'Horizon', 'Eligible', 'Pruned']
      .map((h) => el('th', { text: h }))),
    ...data.policies.map((p) => el('tr', {},
      el('td', {}, el('strong', { text: p.policy_id }), el('div', { class: 'why', text: p.title })),
      el('td', { text: p.class }),
      el('td', { text: p.scope }),
      el('td', { text: `${p.window_days} days` }),
      el('td', { text: fmtTime(p.horizon) }),
      el('td', { text: String(p.eligible_versions) }),
      el('td', { text: String(p.pruned_versions) })))));
}

async function loadHealth() {
  const status = await api('/api/v1/status');
  const rows = [
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
    ['Destroyed keys', String(status.destroyed_keys)],
  ];
  if (status.last_checkpoint) {
    rows.push(['Last checkpoint',
      `version ${status.last_checkpoint.checkpoint.version} at ${fmtTime(status.last_checkpoint.checkpoint.issued_at)}`]);
  }
  $('#health-body').replaceChildren(el('h2', { text: 'Service' }), table(rows));
}

// -- wiring ----------------------------------------------------------------

const loaders = {
  log: loadLog,
  records: loadRecords,
  proofs: async () => {},
  checkpoints: loadCheckpoints,
  retention: loadRetention,
  health: loadHealth,
};

function switchView(name) {
  for (const button of document.querySelectorAll('nav button')) {
    button.classList.toggle('active', button.dataset.view === name);
  }
  for (const view of document.querySelectorAll('.view')) {
    view.classList.toggle('hidden', view.id !== `view-${name}`);
  }
  run(loaders[name]);
}

async function run(fn, ...args) {
  try {
    await fn(...args);
  } catch (err) {
    setStatus(err.detail ? `${err.message} — ${err.detail}` : err.message, true);
  }
}

function connect() {
  state.token = $('#token').value.trim();
  state.role = $('#role').value.trim();
  sessionStorage.setItem('register.token', state.token);
  sessionStorage.setItem('register.role', state.role);
  state.verificationKey = null;
  run(async () => {
    await loadPack();
    setStatus(`connected to ${state.pack.title || state.pack.name}`);
    switchView('log');
  });
}

document.addEventListener('DOMContentLoaded', () => {
  $('#token').value = state.token;
  $('#role').value = state.role;
  $('#connect').addEventListener('click', connect);
  for (const button of document.querySelectorAll('nav button')) {
    button.addEventListener('click', () => switchView(button.dataset.view));
  }
  $('#log-filters').addEventListener('submit', (e) => { e.preventDefault(); run(loadLog); });
  $('#record-filters').addEventListener('submit', (e) => { e.preventDefault(); run(loadRecords); });
  $('#proof-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    run(showNaturalKeyProof, form.get('class'), form.get('key'));
  });
  if (state.token) connect();
});
