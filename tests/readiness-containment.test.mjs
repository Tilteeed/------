import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { modelStatusLabel } from '../web/agent/ui-state.mjs';

const source = await readFile(new URL('../web/agent/app.js', import.meta.url), 'utf8');

test('runtime rendering never presents an unverified model as present', () => {
  const code = source.slice(source.indexOf('function renderRuntime('), source.indexOf('function notice('));
  const elements = new Map();
  const render = new Function('$', 'modelStatusLabel', `let runtimeData, capabilities, connected;
    const observeGeneration = () => {}, runtimeView = () => ({}), renderRetained = () => {}, controls = () => {};
    ${code}; return renderRuntime;`)(id => {
      if (!elements.has(id)) elements.set(id, {});
      return elements.get(id);
    }, modelStatusLabel);
  render({ runtime: { state: 'running', model: 'model_present' } });
  assert.match(elements.get('model-state').textContent, /не подтвержден/i);
  assert.doesNotMatch(elements.get('model-state').textContent, /найдена/i);
});

test('application does not start readiness polling', () => {
  assert.doesNotMatch(source, /readinessPoll\.start\s*\(/);
});
