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
