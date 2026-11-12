import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { modelStatusLabel } from '../web/agent/ui-state.mjs';

const source = await readFile(new URL('../web/agent/app.js', import.meta.url), 'utf8');

test('runtime rendering never presents an unverified model as present', () => {
  const code = source.slice(source.indexOf('function renderRuntime('), source.indexOf('function notice('));
  const elements = new Map();
  const render = new Function('$', 'modelStatusLabel', `let runtimeData = { model: 'model_present' }, capabilities, connected;
    const observeGeneration = () => {}, runtimeView = () => ({}), renderRetained = () => {}, controls = () => {};
    ${code}; return renderRuntime;`)(id => {
      if (!elements.has(id)) elements.set(id, {});
      return elements.get(id);
    }, modelStatusLabel);
  render({ runtime: { state: 'running', model: 'model_present' } });
  assert.equal(elements.get('model-state').textContent, modelStatusLabel('model_present'));
  assert.match(elements.get('model-state').textContent, /ответ не подтверждён/i);
});

test('poll starts only after authentication and resumes after page restoration', () => {
  const load = source.slice(source.indexOf('async function load()'), source.indexOf("$('settings-form').addEventListener"));
  assert.match(load, /authenticated = true;[\s\S]*readinessPoll\.start\(\)/);
  assert.match(source, /pageshow[^\n]*readinessPoll\.start\(\)/);
  assert.match(source, /pagehide[^\n]*pageEpoch\s*\+=\s*1/);
  const action = source.slice(source.indexOf('async function submitAction('), source.lastIndexOf("$('refresh-pairing')"));
  assert.match(action, /pageEpoch !== actionPageEpoch/);
});


test('inventory label does not imply a fresh probe or inference', () => {
  assert.match(modelStatusLabel('model_present'), /списк/i);
  assert.match(modelStatusLabel('model_present'), /ответ не подтверждён/i);
});

test('runtime polling updates and invalidates gateway as well as inventory', () => {
  const setup = source.slice(source.indexOf('const modelUpdates'), source.indexOf('function request('));
  assert.match(setup, /gateway-state/);
  assert.match(setup, /data\.runtime\?\.gateway/);
  assert.match(setup, /makeInvalidation/);
});

test('action observation is ordered after POST and failed refresh invalidates its own observation', () => {
  const action = source.slice(source.indexOf('async function submitAction('), source.lastIndexOf("$('refresh-pairing')"));
  assert.match(action, /await request\('\/actions'[\s\S]*modelUpdates\.begin\(\)/);
  assert.doesNotMatch(action.slice(0, action.indexOf("await request('/actions'")), /modelUpdates\.begin\(\)/);
  const manual = source.slice(source.indexOf("$('refresh-runtime').addEventListener"), source.lastIndexOf("$('reload')"));
  assert.match(manual, /modelUpdate\.fail\(\)/);
});
