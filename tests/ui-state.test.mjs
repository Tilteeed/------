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

test('control UI status accepts only the HTTPS origin for the current instance', () => {
  const instance = 'a'.repeat(32);
  const origin = `https://${instance}.agents.example.test`;
  assert.deepEqual(ui.controlUiStatus({ available: true, origin }, instance), { available: true, origin });
  for (const response of [
    { available: false, origin },
    { available: true, origin: `http://${instance}.agents.example.test` },
    { available: true, origin: `https://${'b'.repeat(32)}.agents.example.test` },
    { available: true, origin: `https://user@${instance}.agents.example.test` },
    { available: true, origin: `${origin}/path` },
    { available: true, origin: `${origin}?target=elsewhere` },
  ]) {
    assert.deepEqual(ui.controlUiStatus(response, instance), { available: false, origin: null });
  }
});

test('control UI launch tickets are accepted only for the status origin and short TTL', () => {
  const origin = `https://${'c'.repeat(32)}.agents.example.test`;
  const launch = { launch_ticket: 'A'.repeat(43), origin, expires_in: 60 };
  assert.deepEqual(ui.controlUiLaunch(launch, origin), { ticket: launch.launch_ticket, origin });
  for (const invalid of [
    { ...launch, origin: `https://${'d'.repeat(32)}.agents.example.test` },
    { ...launch, launch_ticket: 'bad' },
    { ...launch, expires_in: 61 },
    { ...launch, expires_in: 0 },
  ]) {
    assert.equal(ui.controlUiLaunch(invalid, origin), null);
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
  assert.deepEqual(ui.runtimeView({ state: 'preparing', pending_restore_key: 'restore-1' }, true), {
    label: 'Восстановление',
    description: 'Повторно подключаем сохранённые данные к тому же экземпляру; черновик не применяется.',
  });
  assert.deepEqual(ui.runtimeView({ state: 'failed', pending_restore_key: 'restore-1' }, true), {
    label: 'Восстановление не завершено',
    description: 'Сохранённые данные не удалены. Продолжите восстановление или удалите экземпляр с сохранением данных.',
  });
});
