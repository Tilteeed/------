import test from 'node:test';
import assert from 'node:assert/strict';
import { createReadinessPoll } from '../web/agent/ui-state.mjs';

test('polls once, expires while stalled, invalidates failures and stops without leaked timers', async () => {
  let now = 0, next = 0;
  const timers = new Map();
  const set = (fn, ms) => { const id = ++next; timers.set(id, { fn, at: now + ms }); return id; };
  const clear = id => timers.delete(id);
  const advance = async ms => {
    const end = now + ms;
    while (true) {
      const due = [...timers].filter(([, t]) => t.at <= end).sort((a,b) => a[1].at-b[1].at)[0];
      if (!due) break;
      now = due[1].at; timers.delete(due[0]); due[1].fn();
      await Promise.resolve(); await Promise.resolve();
    }
    now = end;
  };
  let calls = 0, resolve;
  const observations = [];
  const poll = createReadinessPoll({ setTimer: set, clearTimer: clear, interval: 5, maxAge: 15,
    refresh: () => { calls++; return new Promise((ok, fail) => { resolve = { ok, fail }; }); },
    invalidate: () => observations.push('unavailable') });
  poll.start(); poll.start();
  assert.equal(calls, 1);
  resolve.ok(); await Promise.resolve(); await Promise.resolve();
  await advance(5); assert.equal(calls, 2);
  await advance(10); assert.deepEqual(observations, ['unavailable']);
  assert.equal(calls, 2);
  resolve.fail(new Error('offline')); await Promise.resolve(); await Promise.resolve();
  assert.equal(observations.at(-1), 'unavailable');
  await advance(5); assert.equal(calls, 3);
  poll.stop(); assert.equal(timers.size, 0);
  resolve.ok(); await Promise.resolve(); await Promise.resolve();
  assert.equal(timers.size, 0);
});

test('initial stalled refresh expires the already displayed status', () => {
  let expire, invalid = 0;
  const poll = createReadinessPoll({ refresh: () => new Promise(() => {}),
    invalidate: () => invalid++, setTimer: (fn, ms) => { if (ms === 15000) expire = fn; return ms; }, clearTimer: () => {} });
  poll.start();
  assert.equal(typeof expire, 'function');
  expire();
  assert.equal(invalid, 1);
  poll.stop();
});


test('late success after expiry cannot restore displayed readiness', async () => {
  let expire, resolve, display = 'ready';
  const poll = createReadinessPoll({ maxAge: 15,
    setTimer: (fn, ms) => { if (ms === 15) expire = fn; return ms; }, clearTimer: () => {},
    invalidate: () => { display = 'unavailable'; },
    refresh: async current => { await new Promise(ok => { resolve = ok; }); if (current()) display = 'ready'; } });
  poll.start(); expire(); resolve();
  await Promise.resolve(); await Promise.resolve();
  assert.equal(display, 'unavailable');
  poll.stop();
});


test('stop aborts each request before a new session starts', async () => {
  const signals = [];
  const poll = createReadinessPoll({ refresh: (current, signal) => { signals.push(signal); return new Promise(() => {}); }, invalidate: () => {} });
  for (let i = 0; i < 3; i++) { poll.start(); poll.stop(); }
  assert.equal(signals.length, 3);
  assert.ok(signals.every(signal => signal?.aborted));
});

test('fresh response after expiry restores readiness', async () => {
  let display = 'initial', calls = 0;
  const poll = createReadinessPoll({ interval: 5, maxAge: 15, requestTimeout: 25,
    invalidate: () => { display = 'unavailable'; },
    refresh: async current => {
      if (++calls === 1) return new Promise(() => {});
      if (current()) display = 'model_present';
    } });
  poll.start();
  await new Promise(resolve => setTimeout(resolve, 60));
  poll.stop();
  assert.ok(calls >= 2);
  assert.equal(display, 'model_present');
});

test('hung requests time out and polling continues', async () => {
  let calls = 0, invalid = 0;
  const poll = createReadinessPoll({ interval: 5, maxAge: 50, requestTimeout: 10,
    refresh: () => { calls++; return new Promise(() => {}); }, invalidate: () => invalid++ });
  poll.start();
  await new Promise(resolve => setTimeout(resolve, 40));
  poll.stop();
  assert.ok(calls >= 2);
  assert.ok(invalid >= 1);
});


test('app request forwards poll cancellation to fetch', async () => {
  const { readFile } = await import('node:fs/promises');
  const source = await readFile(new URL('../web/agent/app.js', import.meta.url), 'utf8');
  const code = source.slice(source.indexOf('async function request('), source.indexOf('function applyDraft('));
  let received;
  const fetch = (url, options) => { received = options.signal; return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted')))); };
  const request = new Function('fetch', 'localStorage', 'apiRoot', code + '; return request;')(fetch, { getItem: () => 'token' }, '/api');
  const controller = new AbortController();
  const result = request('', 'GET', undefined, controller.signal);
  controller.abort();
  assert.ok(received.aborted);
  await assert.rejects(result);
});


test('poll auth errors revoke only the current session', async () => {
  const { readFile } = await import('node:fs/promises');
  const source = await readFile(new URL('../web/agent/app.js', import.meta.url), 'utf8');
  const code = source.slice(source.indexOf('const readinessPoll ='), source.indexOf('function operationGet('));
  const harness = new Function(`
    let identityEpoch = 1, authenticated = true, runtimeData = {}, errors = 0, rejectRequest, refresh;
    const createReadinessPoll = options => { refresh = options.refresh; return {}; };
    const request = () => new Promise((resolve, reject) => { rejectRequest = reject; });
    const showError = () => { errors++; };
    const invalidateModel = () => {};
    const modelUpdates = { begin: () => ({ apply: () => {} }) };
    const modelStatusLabel = x => x;
    const $ = () => ({ textContent: '' });
    ${code}
    return { run: current => refresh(current, new AbortController().signal),
      reject: e => rejectRequest(e), switchUser: () => identityEpoch++, errors: () => errors };
  `)();
  let result = harness.run(() => true);
  harness.reject({ status: 401 });
  await assert.rejects(result);
  assert.equal(harness.errors(), 1);
  result = harness.run(() => true);
  harness.switchUser();
  harness.reject({ status: 403 });
  await assert.rejects(result);
  assert.equal(harness.errors(), 1);
  result = harness.run(() => false);
  harness.reject({ status: 401 });
  await assert.rejects(result);
  assert.equal(harness.errors(), 1);
});


test('older manual response cannot overwrite a newer poll response', async () => {
  const { createModelUpdates } = await import('../web/agent/ui-state.mjs');
  let displayed;
  const updates = createModelUpdates({ apply: value => { displayed = value; }, isAuthorized: () => true });
  const manual = updates.begin();
  const poll = updates.begin();
  poll.apply('model_present');
  manual.apply('unavailable');
  assert.equal(displayed, 'model_present');
});


test('model updates reject expired and previous-session responses', async () => {
  const { createModelUpdates } = await import('../web/agent/ui-state.mjs');
  let displayed = 'unknown', time = 0, session = 1;
  const updates = createModelUpdates({ apply: value => { displayed = value; }, now: () => time, maxAge: 15,
    getSession: () => session, isAuthorized: () => true });
  const old = updates.begin();
  session++;
  old.apply('old user');
  assert.equal(displayed, 'unknown');
  const late = updates.begin();
  time = 15;
  late.apply('late');
  assert.equal(displayed, 'unknown');
});


test('accepted model status expires based on request start, even without poll activity', async () => {
  const { createModelUpdates } = await import('../web/agent/ui-state.mjs');
  let time = 0, expire, delay, display = 'unknown';
  const updates = createModelUpdates({ now: () => time, maxAge: 15, isAuthorized: () => true,
    setTimer: (fn, ms) => { expire = fn; delay = ms; return 1; }, clearTimer: () => {},
    apply: value => { display = value; }, invalidate: () => { display = 'unknown'; } });
  const response = updates.begin();
  time = 10; response.apply('present');
  assert.equal(delay, 5);
  time = 15; expire();
  assert.equal(display, 'unknown');
});


test('newer manual result defeats older poll, and invalidation rejects late replies', async () => {
  const { createModelUpdates } = await import('../web/agent/ui-state.mjs');
  let value = 'unknown', authorized = true;
  const updates = createModelUpdates({ apply: x => { value = x; }, isAuthorized: () => authorized,
    setTimer: () => 1, clearTimer: () => {} });
  const poll = updates.begin(), manual = updates.begin();
  manual.apply('model_missing');
  poll.apply('model_present');
  assert.equal(value, 'model_missing');
  const late = updates.begin();
  updates.invalidate();
  late.apply('model_present');
  assert.equal(value, 'model_missing');
  const revoked = updates.begin();
  authorized = false;
  revoked.apply('model_present');
  assert.equal(value, 'model_missing');
});


test('failed older refresh cannot invalidate a newer successful observation', async () => {
  const { createModelUpdates } = await import('../web/agent/ui-state.mjs');
  let display = 'unknown';
  const updates = createModelUpdates({ apply: x => { display = x; }, invalidate: () => { display = 'unknown'; }, isAuthorized: () => true, setTimer: () => 1, clearTimer: () => {} });
  const oldPoll = updates.begin(), manual = updates.begin();
  manual.apply('ready');
  oldPoll.fail();
  assert.equal(display, 'ready');
  updates.begin().fail();
  assert.equal(display, 'unknown');
});


test('action completion supersedes an in-flight poll and its later failure', async () => {
  const { createModelUpdates } = await import('../web/agent/ui-state.mjs');
  let display = 'unknown';
  const updates = createModelUpdates({ apply: x => { display = x; }, invalidate: () => { display = 'unknown'; }, isAuthorized: () => true, setTimer: () => 1, clearTimer: () => {} });
  const poll = updates.begin();
  updates.begin().apply('action result');
  poll.fail();
  assert.equal(display, 'action result');
  const manual = updates.begin();
  updates.begin().fail();
  manual.apply('obsolete');
  assert.equal(display, 'unknown');
});

test('poll invalidation is associated with the poll request, not a newer manual result', async () => {
  let failPoll, display = 'unknown';
  const { createModelUpdates } = await import('../web/agent/ui-state.mjs');
  const updates = createModelUpdates({ apply: x => { display = x; }, invalidate: () => { display = 'unknown'; }, isAuthorized: () => true, setTimer: () => 1, clearTimer: () => {} });
  const poll = createReadinessPoll({ makeInvalidation: () => { const update = updates.begin(); return () => update.fail(); },
    invalidate: () => { display = 'unknown'; }, refresh: () => new Promise((_, reject) => { failPoll = reject; }) });
  poll.start();
  updates.begin().apply('manual');
  failPoll(new Error('offline'));
  await new Promise(resolve => setTimeout(resolve, 0));
  poll.stop();
  assert.equal(display, 'manual');
});
