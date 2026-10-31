import { draftView, errorView, runtimeView, settingsPayload } from './ui-state.mjs';

const $ = (id) => document.getElementById(id);
const apiRoot = '/api/v1/agent-platform/me';
let revision = 0;
let authenticated = false;
let busy = false;
let eventsBusy = false;
let conflict = false;
let dirty = false;
let identityEpoch = 0;
let currentUser = '';
let runtimeData = { state: 'not_connected' };
let capabilities = {};
let connected = false;
const operationMemory = new Map();
let sessionStorageAvailable = true;

function operationGet(key) {
  if (operationMemory.has(key)) return operationMemory.get(key);
  let value = null;
  if (sessionStorageAvailable) {
    try { value = sessionStorage.getItem(key); }
    catch { sessionStorageAvailable = false; }
  }
  operationMemory.set(key, value);
  return value;
}

function operationSet(key, value) {
  operationMemory.set(key, value);
  if (sessionStorageAvailable) {
    try {
      if (value === null) sessionStorage.removeItem(key);
      else sessionStorage.setItem(key, value);
    } catch { sessionStorageAvailable = false; }
  }
}

function observeGeneration(runtime) {
  if (!currentUser || ['unavailable', 'not_connected'].includes(runtime.state)) return;
  let generation;
  if (runtime.state === 'removed' || runtime.state === 'purged' || runtime.instance_id === null) generation = 'none';
  else if (typeof runtime.instance_id === 'string' && runtime.instance_id) generation = runtime.instance_id;
  else return; // Missing/ambiguous observations do not prove absence.
  const generationKey = `agent-generation:${currentUser}`;
  const previous = operationGet(generationKey);
  if (previous !== null && previous !== 'none' && previous !== generation) {
    const prefix = `agent-operation:${currentUser}:`;
    const keys = new Set(operationMemory.keys());
    if (sessionStorageAvailable) {
      try {
        // Copy before deleting: Storage indices change on removeItem.
        for (let i = 0; i < sessionStorage.length; i += 1) keys.add(sessionStorage.key(i));
      } catch { sessionStorageAvailable = false; }
    }
    for (const key of keys) {
      if (typeof key === 'string' && key.startsWith(prefix)) operationSet(key, null);
    }
  }
  operationSet(generationKey, generation);
}

function renderRetained(items) {
  const panel = $('retained-panel');
  const list = $('retained-list');
  const entries = Array.isArray(items) ? items : [];
  panel.hidden = entries.length === 0;
  list.replaceChildren();
  for (const item of entries) {
    const row = document.createElement('li');
    const description = document.createElement('span');
    const gib = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 })
      .format(item.disk_bytes / (1024 ** 3));
    description.textContent = `${item.name} — ${gib} ГиБ; ${item.state === 'purging' ? 'очистка ожидает повтора' : 'данные сохранены'}`;
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = item.pending_purge_key ? 'Продолжить удаление' : 'Удалить данные и квоту';
    button.setAttribute('aria-label', `Полностью удалить данные агента ${item.name}`);
    button.disabled = !authenticated || busy || dirty || conflict || revision < 1 || !connected;
    button.addEventListener('click', () => submitAction(button, 'purge', item.instance_id,
      item.pending_purge_key, item.pending_purge_revision));
    row.append(description, button);
    list.append(row);
  }
}

function renderRuntime(data) {
  runtimeData = data.runtime || { state: 'unavailable' };
  observeGeneration(runtimeData);
  capabilities = data.capabilities || {};
  connected = !['not_connected', 'unavailable'].includes(runtimeData.state);
  const view = runtimeView(runtimeData, connected || runtimeData.state === 'unavailable');
  $('runtime-badge').textContent = view.label;
  $('runtime-title').textContent = view.label;
  $('runtime-description').textContent = view.description;
  $('gateway-state').textContent = runtimeData.gateway === 'ready' ? 'Готов' : 'Не готов / не подтверждён';
  $('metrics-state').textContent = capabilities.metrics ? 'Окно CPU готово' : 'Нет свежих данных / прогрев';
  renderRetained(data.retained);
  controls();
}

function notice(state, message, href) {
  $('notice').dataset.state = state;
  $('notice-text').textContent = message;
  $('login').hidden = !href;
  if (href) $('login').setAttribute('href', href);
}

function controls() {
  $('settings-fields').disabled = !authenticated || busy;
  $('save').disabled = conflict || !dirty;
  $('reload').disabled = busy;
  $('refresh-runtime').disabled = !authenticated || busy;
  $('refresh-events').disabled = !authenticated || busy || eventsBusy;
  for (const button of document.querySelectorAll('[data-action]')) {
    const action = button.dataset.action;
    const exists = Boolean(runtimeData.instance_id) && !['removed', 'purged'].includes(runtimeData.state);
    const purgePending = Boolean(runtimeData.pending_purge_key);
    const needsAdmission = ['create', 'start', 'restart'].includes(action);
    button.disabled = !authenticated || busy || dirty || conflict || revision < 1 || !connected
      || (needsAdmission && !capabilities.provisioning)
      || (purgePending && action !== 'purge')
      || (action === 'create' ? (exists && !runtimeData.pending_create_key) : !exists)
      || (action === 'start' && runtimeData.state === 'running')
      || (action === 'stop' && runtimeData.state === 'stopped');
    if (action === 'create') {
      button.textContent = runtimeData.pending_create_key ? 'Продолжить создание' : 'Создать';
      button.title = runtimeData.pending_create_key ? `Будет использован исходный снимок настроек версии ${runtimeData.pending_create_revision}` : '';
    }
    if (action === 'purge') {
      button.textContent = runtimeData.pending_purge_key ? 'Продолжить удаление данных' : 'Удалить данные и квоту';
      button.title = runtimeData.pending_purge_key ? `Будет повторена операция версии ${runtimeData.pending_purge_revision}` : '';
    }
  }
  for (const button of document.querySelectorAll('#retained-list button')) {
    button.disabled = !authenticated || busy || dirty || conflict || revision < 1 || !connected;
  }
  $('main').setAttribute('aria-busy', String(busy));
  $('save').textContent = busy ? 'Подождите…' : 'Сохранить настройки';
}

function revoke() {
  authenticated = false;
  identityEpoch += 1;
  currentUser = '';
  connected = false;
  runtimeData = { state: 'not_connected' };
  capabilities = {};
  dirty = false;
  $('identity').textContent = 'Учётная запись не подтверждена';
  $('agent-name').value = '';
  $('instructions').value = '';
  $('revision').textContent = 'Версия не загружена';
  $('events-list').replaceChildren();
  $('events-status').textContent = 'События недоступны без подтверждённого доступа.';
  renderRetained([]);
  renderRuntime({ runtime: { state: 'not_connected' } });
  $('runtime-description').textContent = 'Доступ не подтверждён. Состояние экземпляра не загружено.';
}

function showError(error) {
  const view = errorView(error.status || 0, error.body);
  if (error.status === 401 || error.status === 403) revoke();
  if (error.status === 409 && (!error.body?.detail?.code || error.body.detail.code === 'revision_conflict')) conflict = true;
  notice(view.state, view.message, view.href);
  controls();
}

async function request(path = '', method = 'GET', payload) {
  let token;
  try { token = localStorage.getItem('token'); } catch { /* Treat unavailable storage as signed out. */ }
  if (!token) throw { status: 401 };
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 130000);
  try {
    const response = await fetch(`${apiRoot}${path}`, {
      method,
      mode: 'same-origin',
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-store',
      headers: { Authorization: `Bearer ${token}`, ...(payload ? { 'Content-Type': 'application/json' } : {}) },
      ...(payload ? { body: JSON.stringify(payload) } : {}),
      signal: controller.signal,
    });
    let body;
    try { body = await response.json(); } catch { /* Preserve HTTP status for non-JSON errors. */ }
    if (!response.ok) throw { status: response.status, body };
    if (!body || typeof body !== 'object') throw { status: 0 };
    return body;
  } finally {
    clearTimeout(timeout);
  }
}

function applyDraft(draft) {
  if (draft !== null) settingsPayload(draft?.name, draft?.instructions, draft?.revision);
  const view = draftView(draft);
  revision = view.revision;
  $('agent-name').value = view.name;
  $('instructions').value = view.instructions;
  $('revision').textContent = `Версия ${revision}`;
  dirty = false;
  conflict = false;
  notice(view.state, view.message);
}

async function loadEvents() {
  if (!authenticated || eventsBusy) return;
  const epoch = identityEpoch;
  eventsBusy = true;
  controls();
  $('events-status').textContent = 'Загружаем события…';
  try {
    const data = await request('/events');
    if (!authenticated || epoch !== identityEpoch) return;
    if (!Array.isArray(data.events)) throw { status: 0 };
    const fragment = document.createDocumentFragment();
    for (const event of data.events) {
      const item = document.createElement('li');
      const title = document.createElement('span');
      const labels = { settings_saved: 'Настройки сохранены', settings_updated: 'Настройки обновлены', draft_created: 'Черновик сохранён' };
      title.textContent = Object.hasOwn(labels, event.kind) ? labels[event.kind] : String(event.kind ?? 'Событие');
      const time = document.createElement('time');
      const date = new Date(typeof event.created_at === 'number' ? event.created_at * 1000 : event.created_at);
      if (event.created_at != null && Number.isFinite(date.getTime())) {
        time.dateTime = date.toISOString();
        time.textContent = new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(date);
      } else time.textContent = 'Дата не указана';
      item.append(title, time);
      fragment.append(item);
    }
    $('events-list').replaceChildren(fragment);
    $('events-status').textContent = data.events.length ? 'История сохранений из БД. Это не журнал работы агента.' : 'Событий пока нет.';
  } catch (error) {
    if (epoch !== identityEpoch) return;
    $('events-status').textContent = errorView(error.status || 0, error.body).message;
    if (error.status === 401 || error.status === 403) showError(error);
  } finally {
    eventsBusy = false;
    controls();
  }
}

async function load() {
  if (busy) return;
  if (dirty && !window.confirm('Перечитать настройки с сервера? Несохранённые изменения будут потеряны.')) return;
  const epoch = identityEpoch;
  busy = true;
  controls();
  notice('loading', 'Загружаем настройки…');
  try {
    const data = await request();
    if (epoch !== identityEpoch) return;
    if (!data.user || typeof data.user.id !== 'string' || typeof data.user.name !== 'string') throw { status: 0 };
    applyDraft(data.draft);
    authenticated = true;
    identityEpoch += 1;
    currentUser = data.user.id;
    $('identity').textContent = data.user.name;
    renderRuntime(data);
    void loadEvents();
  } catch (error) {
    // A failed initial read must never enable saving against an invented revision.
    if (epoch !== identityEpoch) return;
    authenticated = false;
    showError(error);
  } finally {
    busy = false;
    controls();
  }
}

$('settings-form').addEventListener('input', () => {
  dirty = true;
  if (!conflict) notice('editing', 'Есть несохранённые изменения. Они ещё не записаны в БД.');
  controls();
});
$('settings-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!authenticated || busy || conflict || !dirty) return;
  let payload;
  try { payload = settingsPayload($('agent-name').value, $('instructions').value, revision); }
  catch (error) { notice('error', error.message); return; }
  const epoch = identityEpoch;
  busy = true;
  controls();
  notice('loading', 'Сохраняем настройки в БД…');
  try {
    const data = await request('/settings', 'PUT', payload);
    if (epoch !== identityEpoch) return;
    if (!data.draft) throw { status: 0 };
    applyDraft(data.draft);
    void loadEvents();
  } catch (error) { if (epoch === identityEpoch) showError(error); }
  finally { busy = false; controls(); }
});
async function submitAction(button, action, targetInstanceId = null, savedPurgeKey = null, savedPurgeRevision = null) {
  if (button.disabled || busy || !authenticated) return;
  if (action === 'remove' && !window.confirm('Удалить контейнер? Данные будут сохранены. Для следующего экземпляра потребуется дополнительный дисковый бюджет.')) return;
  if (action === 'purge' && !window.confirm('Безвозвратно удалить контейнер и все его сохранённые данные, затем освободить дисковую квоту? Это действие нельзя отменить.')) return;
  const epoch = identityEpoch;
  if (action === 'purge' && !targetInstanceId) targetInstanceId = runtimeData.instance_id;
  const currentPurge = action === 'purge' && targetInstanceId === runtimeData.instance_id;
  const pendingKey = action === 'create' ? runtimeData.pending_create_key
    : (currentPurge ? runtimeData.pending_purge_key : savedPurgeKey);
  const pendingRevision = action === 'create' ? runtimeData.pending_create_revision
    : (currentPurge ? runtimeData.pending_purge_revision : savedPurgeRevision);
  const resuming = ['create', 'purge'].includes(action) && typeof pendingKey === 'string'
    && Number.isSafeInteger(pendingRevision) && pendingRevision > 0;
  const requestRevision = resuming ? pendingRevision : revision;
  const targetSuffix = targetInstanceId ? `:${targetInstanceId}` : '';
  const storageKey = `agent-operation:${currentUser}:${requestRevision}:${action}${targetSuffix}`;
  let key = resuming ? pendingKey : operationGet(storageKey);
  if (!key) {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    key = Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
    operationSet(storageKey, key);
  }
  busy = true;
  controls();
  button.disabled = true;
  notice('loading', 'Supervisor выполняет операцию. Не закрывайте страницу…');
  try {
    const payload = { action, idempotency_key: key, settings_revision: requestRevision };
    if (action === 'purge') payload.instance_id = targetInstanceId || runtimeData.instance_id;
    const data = await request('/actions', 'POST', payload);
    if (epoch !== identityEpoch) return;
    renderRuntime(data);
    // Failed/ambiguous requests retain the same key so a retry cannot duplicate effects.
    if (data.operation?.status === 'succeeded' || data.operation?.status === 'completed') {
      operationSet(storageKey, null);
    }
    notice('saved', 'Ответ supervisor получен. Состояние контейнера показано справа.');
  } catch (error) {
    if (epoch === identityEpoch) {
      if (error.body?.detail?.code === 'instance_retired') {
        operationSet(storageKey, null);
        notice('error', 'Операция относится к удалённому экземпляру. Обновите состояние и повторите действие.');
      } else {
        showError(error);
        if (error.status === 503) {
          try {
            const latest = await request();
            if (epoch === identityEpoch) renderRuntime(latest);
          } catch { /* Keep the original operation error visible if refresh also fails. */ }
        }
      }
    }
  } finally {
    busy = false;
    controls();
    if (button.isConnected && !button.matches('[data-action]')) {
      button.disabled = !authenticated || dirty || conflict || revision < 1 || !connected;
    }
  }
}

for (const button of document.querySelectorAll('[data-action]')) {
  button.addEventListener('click', () => submitAction(button, button.dataset.action));
}
$('refresh-runtime').addEventListener('click', async () => {
  if (!authenticated || busy) return;
  const epoch = identityEpoch;
  busy = true;
  controls();
  try {
    const data = await request();
    if (epoch === identityEpoch) renderRuntime(data);
  } catch (error) { if (epoch === identityEpoch) showError(error); }
  finally { busy = false; controls(); }
});
$('reload').addEventListener('click', load);
$('refresh-events').addEventListener('click', loadEvents);
window.addEventListener('beforeunload', (event) => {
  if (dirty) { event.preventDefault(); event.returnValue = ''; }
});
window.addEventListener('storage', (event) => {
  if (event.key === 'token' || event.key === null) {
    revoke();
    notice('no-auth', 'Сессия изменилась. Перечитайте настройки для подтверждения доступа.', '/auth?redirect=%2Fagent');
    controls();
  }
});
void load();
