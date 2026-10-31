import test from 'node:test';
import assert from 'node:assert/strict';
import * as ui from '../web/agent/ui-state.mjs';

test('errors map auth, forbidden, revision conflict and missing runtime honestly', () => {
  assert.equal(ui.errorView(401, { detail: 'Expired' }).state, 'no-auth');
  assert.equal(ui.errorView(401).href, '/auth?redirect=%2Fagent');
  assert.equal(ui.errorView(403).state, 'forbidden');
  assert.match(ui.errorView(409).message, /Перечитайте/);
  assert.match(ui.errorView(503, { detail: { code: 'runtime_not_connected', message: 'offline' } }).message, /Docker/);
  assert.equal(ui.errorView(400, { detail: 'Неверное имя' }).message, 'Неверное имя');
  assert.equal(ui.errorView(400, { detail: { message: 'Ошибка поля' } }).message, 'Ошибка поля');
  assert.match(ui.errorView(422, { detail: [{ type: 'bad' }] }).message, /Проверьте/);
  assert.match(ui.errorView(0).message, /соединение/);
});

test('draft state distinguishes an empty account from persisted settings, not provisioning', () => {
  assert.deepEqual(ui.draftView(null), { state: 'empty', name: '', instructions: '', revision: 0, message: 'Настроек пока нет. Сохраните черновик — это не создаст агента.' });
  const view = ui.draftView({ id: 'd1', name: '<script>', instructions: 'Точно как введено', revision: 4, updated_at: 123 });
  assert.equal(view.state, 'saved');
  assert.equal(view.name, '<script>');
  assert.equal(view.instructions, 'Точно как введено');
  assert.equal(view.revision, 4);
  assert.match(view.message, /не применены/);
});

test('settings payload contains only editable settings and validates limits without truncating', () => {
  assert.deepEqual(ui.settingsPayload('Личный', 'Инструкция', 0), { settings: { name: 'Личный', instructions: 'Инструкция' }, revision: 0 });
  assert.equal(ui.settingsPayload('я'.repeat(80), 'x'.repeat(8000), 12).revision, 12);
  assert.equal(ui.settingsPayload('😀'.repeat(80), '', 0).settings.name.length, 160);
  for (const [name, instructions, revision] of [['', '', 0], ['   ', '', 0], ['я'.repeat(81), '', 0], ['a', 'x'.repeat(8001), 0], ['a', '', -1], ['a', '', 1.2], ['a', '', '0']]) {
    assert.throws(() => ui.settingsPayload(name, instructions, revision));
  }
});

test('runtime never claims an agent is running without a connection', () => {
  for (const runtime of [null, {}, { state: 'not_connected' }, { state: 'running' }]) {
    assert.deepEqual(ui.runtimeView(runtime), {
      label: 'Не подключён',
      description: 'Docker и среда выполнения не подключены. Агент не создан и не запущен.',
    });
  }
  assert.equal(ui.runtimeView({ state: 'purging' }, true).label, 'Удаление данных');
  assert.equal(ui.runtimeView({ state: 'purged' }, true).label, 'Полностью удалён');
});
