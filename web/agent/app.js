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
let workspaceBusy = 0;
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
  const hasCurrent = Boolean(runtimeData.instance_id)
    && !['removed', 'purged', 'not_connected', 'unavailable'].includes(runtimeData.state);
  panel.hidden = entries.length === 0;
  list.replaceChildren();
  for (const item of entries) {
    const row = document.createElement('li');
    const description = document.createElement('span');
    const gib = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 })
      .format(item.disk_bytes / (1024 ** 3));
    description.textContent = `${item.name} — ${gib} ГиБ; ${item.state === 'purging' ? 'очистка ожидает повтора' : 'данные сохранены'}`;
    const actions = document.createElement('div');
    actions.className = 'retained-actions';
    const files = document.createElement('button');
    files.type = 'button';
    files.textContent = 'Просмотреть файлы';
    files.dataset.retainedAction = 'files';
    files.dataset.retainedState = item.state;
    files.dataset.pendingPurge = String(Boolean(item.pending_purge_key));
    files.disabled = !authenticated || busy || !connected || item.state !== 'removed' || Boolean(item.pending_purge_key);
    const restore = document.createElement('button');
    restore.type = 'button';
    restore.textContent = 'Восстановить агента';
    restore.dataset.retainedAction = 'restore';
    restore.setAttribute('aria-label', `Восстановить агента ${item.name} с его сохранёнными данными`);
    restore.disabled = !authenticated || busy || dirty || conflict || revision < 1 || !connected
      || item.state !== 'removed' || Boolean(item.pending_purge_key) || hasCurrent;
    restore.addEventListener('click', () => submitAction(restore, 'restore', item.instance_id));
    const purge = document.createElement('button');
    purge.type = 'button';
    purge.textContent = item.pending_purge_key ? 'Продолжить удаление' : 'Удалить данные и квоту';
    purge.dataset.retainedAction = 'purge';
    purge.setAttribute('aria-label', `Полностью удалить данные агента ${item.name}`);
    purge.disabled = !authenticated || busy || dirty || conflict || revision < 1 || !connected;
    purge.addEventListener('click', () => submitAction(purge, 'purge', item.instance_id,
      item.pending_purge_key, item.pending_purge_revision));
    actions.append(files, restore, purge);

    const browser = document.createElement('section');
    browser.className = 'workspace-browser';
    browser.hidden = true;
    browser.setAttribute('aria-label', `Файлы рабочей папки ${item.name}`);
    files.addEventListener('click', async () => {
      if (browser.hidden) {
        browser.hidden = false;
        files.textContent = 'Скрыть файлы';
        await loadWorkspace(item.instance_id, '', browser, identityEpoch);
      } else {
        browser.hidden = true;
        files.textContent = 'Просмотреть файлы';
      }
    });
    row.append(description, actions, browser);
    list.append(row);
  }
}

function workspaceErrorMessage(error) {
  const code = error.body?.detail?.code;
  const messages = {
    file_not_found: 'Файл или папка не найдены.',
    file_changed: 'Файл изменился во время чтения. Обновите список и повторите запрос.',
    file_too_large: 'Файл превышает лимит скачивания 16 МиБ.',
    invalid_file_path: 'Недопустимый путь к файлу.',
    preview_not_supported: 'Этот файл не является небольшим UTF-8 текстом. Его можно скачать.',
    workspace_unavailable: 'Сохранённая рабочая папка не прошла проверку.',
  };
  return messages[code] || errorView(error.status || 0, error.body).message;
}

function formatFileSize(bytes) {
  if (!Number.isSafeInteger(bytes) || bytes < 0) return 'размер неизвестен';
  if (bytes < 1024) return `${bytes} Б`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} КиБ`;
  return `${(bytes / (1024 ** 2)).toFixed(1)} МиБ`;
}

async function loadWorkspace(instanceId, directory, browser, epoch, offset = 0) {
  workspaceBusy += 1;
  controls();
  browser.replaceChildren();
  browser.setAttribute('aria-busy', 'true');
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.textContent = 'Загружаем рабочую папку…';
  browser.append(status);
  try {
    const query = new URLSearchParams({ directory, offset: String(offset) });
    const data = await request(`/retained/${encodeURIComponent(instanceId)}/files?${query}`);
    if (epoch !== identityEpoch || !browser.isConnected || browser.hidden) return;
    if (!data || data.directory !== directory || !Array.isArray(data.entries)
        || (data.next_offset !== null && !Number.isSafeInteger(data.next_offset))) throw { status: 0 };
    browser.replaceChildren();
    const nav = document.createElement('nav');
    nav.setAttribute('aria-label', 'Путь в рабочей папке');
    const root = document.createElement('button');
    root.type = 'button';
    root.textContent = 'Корень';
    root.dataset.workspaceAction = 'navigate';
    root.addEventListener('click', () => loadWorkspace(instanceId, '', browser, epoch));
    nav.append(root);
    const parts = directory ? directory.split('/') : [];
    let accumulated = '';
    for (const part of parts) {
      accumulated = accumulated ? `${accumulated}/${part}` : part;
      const target = accumulated;
      const crumb = document.createElement('button');
      crumb.type = 'button';
      crumb.textContent = part;
      crumb.dataset.workspaceAction = 'navigate';
      crumb.addEventListener('click', () => loadWorkspace(instanceId, target, browser, epoch));
      nav.append(crumb);
    }
    browser.append(nav);
    if (directory) {
      const back = document.createElement('button');
      back.type = 'button';
      back.textContent = 'Назад';
      back.dataset.workspaceAction = 'navigate';
      back.addEventListener('click', () => loadWorkspace(instanceId, parts.slice(0, -1).join('/'), browser, epoch));
      browser.append(back);
    }
    const list = document.createElement('ul');
    for (const entry of data.entries) {
      if (!entry || typeof entry.name !== 'string' || !['file', 'directory'].includes(entry.kind)) continue;
      const item = document.createElement('li');
      const label = document.createElement('span');
      label.textContent = entry.kind === 'directory' ? `${entry.name}/` : `${entry.name} — ${formatFileSize(entry.size)}`;
      item.append(label);
      if (entry.kind === 'directory') {
        const open = document.createElement('button');
        open.type = 'button';
        open.textContent = 'Открыть';
        open.dataset.workspaceAction = 'navigate';
        open.addEventListener('click', () => loadWorkspace(instanceId,
          directory ? `${directory}/${entry.name}` : entry.name, browser, epoch));
        item.append(open);
      } else {
        const fileActions = document.createElement('div');
        fileActions.className = 'file-actions';
        const preview = document.createElement('button');
        preview.type = 'button';
        preview.textContent = 'Просмотр';
        preview.dataset.workspaceAction = 'file';
        preview.addEventListener('click', () => previewWorkspaceFile(instanceId,
          directory ? `${directory}/${entry.name}` : entry.name, browser, epoch));
        const download = document.createElement('button');
        download.type = 'button';
        download.textContent = 'Скачать';
        download.dataset.workspaceAction = 'file';
        download.addEventListener('click', () => downloadWorkspaceFile(instanceId,
          directory ? `${directory}/${entry.name}` : entry.name, browser, epoch));
        fileActions.append(preview, download);
        item.append(fileActions);
      }
      list.append(item);
    }
    browser.append(list);
    if (offset > 0) {
      const previous = document.createElement('button');
      previous.type = 'button';
      previous.textContent = 'Предыдущие файлы';
      previous.dataset.workspaceAction = 'navigate';
      previous.addEventListener('click', () => loadWorkspace(instanceId, directory, browser, epoch,
        Math.max(0, offset - 50)));
      browser.append(previous);
    }
    if (data.next_offset !== null) {
      const next = document.createElement('button');
      next.type = 'button';
      next.textContent = 'Следующие файлы';
      next.dataset.workspaceAction = 'navigate';
      next.addEventListener('click', () => loadWorkspace(instanceId, directory, browser, epoch,
        data.next_offset));
      browser.append(next);
    }
    status.textContent = data.entries.length ? 'Содержимое только рабочей папки. Скрытые файлы и credentials исключены.' : 'Папка пуста.';
    browser.append(status);
  } catch (error) {
    if (epoch === identityEpoch && browser.isConnected) status.textContent = workspaceErrorMessage(error);
    if (error.status === 401 || error.status === 403) showError(error);
  } finally {
    workspaceBusy = Math.max(0, workspaceBusy - 1);
    browser.setAttribute('aria-busy', 'false');
    controls();
  }
}

async function previewWorkspaceFile(instanceId, path, browser, epoch) {
  workspaceBusy += 1;
  controls();
  const previewBox = document.createElement('section');
  previewBox.className = 'workspace-preview';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.textContent = 'Загружаем текстовый просмотр…';
  previewBox.append(status);
  browser.append(previewBox);
  try {
    const query = new URLSearchParams({ path });
    const data = await request(`/retained/${encodeURIComponent(instanceId)}/files/preview?${query}`);
    if (epoch !== identityEpoch || !previewBox.isConnected || browser.hidden) return;
    if (typeof data.text !== 'string') throw { status: 0 };
    const pre = document.createElement('pre');
    pre.textContent = data.text;
    previewBox.replaceChildren(pre);
  } catch (error) {
    if (epoch === identityEpoch && previewBox.isConnected) status.textContent = workspaceErrorMessage(error);
    if (error.status === 401 || error.status === 403) showError(error);
  } finally {
    workspaceBusy = Math.max(0, workspaceBusy - 1);
    controls();
  }
}

async function downloadWorkspaceFile(instanceId, path, browser, epoch) {
  let token;
  try { token = localStorage.getItem('token'); } catch { /* Treat unavailable storage as signed out. */ }
  if (!token || !authenticated || busy) return;
  workspaceBusy += 1;
  controls();
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.textContent = `Скачиваем ${path.split('/').pop()}…`;
  browser.append(status);
  try {
    const query = new URLSearchParams({ path });
    const response = await fetch(`${apiRoot}/retained/${encodeURIComponent(instanceId)}/files/download?${query}`, {
      method: 'GET', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
      let body;
      try { body = await response.json(); } catch { /* Keep status-only error. */ }
      throw { status: response.status, body };
    }
    if (response.headers.get('content-type')?.split(';', 1)[0].toLowerCase() !== 'application/octet-stream') throw { status: 0 };
    const blob = await response.blob();
    if (epoch !== identityEpoch || !browser.isConnected || browser.hidden) return;
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = path.split('/').pop();
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    status.textContent = `Скачан файл ${link.download}.`;
  } catch (error) {
    if (epoch === identityEpoch && status.isConnected) status.textContent = workspaceErrorMessage(error);
    if (error.status === 401 || error.status === 403) showError(error);
  } finally {
    workspaceBusy = Math.max(0, workspaceBusy - 1);
    controls();
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
  const workspaceLocked = busy || workspaceBusy > 0;
  $('settings-fields').disabled = !authenticated || workspaceLocked;
  $('save').disabled = conflict || !dirty || workspaceLocked;
  $('reload').disabled = workspaceLocked;
  $('refresh-runtime').disabled = !authenticated || workspaceLocked;
  $('refresh-events').disabled = !authenticated || workspaceLocked || eventsBusy;
  for (const button of document.querySelectorAll('[data-action]')) {
    const action = button.dataset.action;
    const exists = Boolean(runtimeData.instance_id) && !['removed', 'purged'].includes(runtimeData.state);
    const purgePending = Boolean(runtimeData.pending_purge_key);
    const restorePending = Boolean(runtimeData.pending_restore_key);
    const needsAdmission = ['create', 'start', 'restart'].includes(action);
    button.disabled = !authenticated || workspaceLocked || dirty || conflict || revision < 1 || !connected
      || (needsAdmission && !capabilities.provisioning)
      || (purgePending && action !== 'purge')
      || (restorePending && ['create', 'start', 'stop', 'restart'].includes(action))
      || (action === 'restore' && !restorePending)
      || (action === 'create' ? (exists && !runtimeData.pending_create_key) : !exists)
      || (action === 'start' && runtimeData.state === 'running')
      || (action === 'stop' && runtimeData.state === 'stopped');
    if (action === 'create') {
      button.textContent = runtimeData.pending_create_key ? 'Продолжить создание' : 'Создать';
      button.title = runtimeData.pending_create_key ? `Будет использован исходный снимок настроек версии ${runtimeData.pending_create_revision}` : '';
    }
    if (action === 'restore') {
      button.hidden = !restorePending;
      button.textContent = 'Продолжить восстановление';
      button.title = restorePending ? `Будет повторено восстановление версии ${runtimeData.pending_restore_revision}` : '';
    }
    if (action === 'purge') {
      button.textContent = runtimeData.pending_purge_key ? 'Продолжить удаление данных' : 'Удалить данные и квоту';
      button.title = runtimeData.pending_purge_key ? `Будет повторена операция версии ${runtimeData.pending_purge_revision}` : '';
    }
  }
  for (const button of document.querySelectorAll('#retained-list [data-retained-action]')) {
    if (button.dataset.retainedAction === 'files') {
      button.disabled = !authenticated || workspaceLocked || !connected
        || button.dataset.retainedState !== 'removed' || button.dataset.pendingPurge === 'true';
    } else {
      button.disabled = !authenticated || workspaceLocked || dirty || conflict || revision < 1 || !connected;
    }
  }
  for (const button of document.querySelectorAll('[data-workspace-action]')) {
    button.disabled = !authenticated || workspaceLocked || !connected;
  }
  $('main').setAttribute('aria-busy', String(workspaceLocked));
  $('save').textContent = workspaceLocked ? 'Подождите…' : 'Сохранить настройки';
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
async function submitAction(button, action, targetInstanceId = null, savedOperationKey = null, savedOperationRevision = null) {
  if (button.disabled || busy || !authenticated) return;
  if (action === 'remove' && !window.confirm('Удалить контейнер? Данные будут сохранены. Для следующего экземпляра потребуется дополнительный дисковый бюджет.')) return;
  if (action === 'purge' && !window.confirm('Удалить контейнер, файлы экземпляра, runtime-снимок и его секреты, затем освободить дисковую квоту? Черновик настроек кабинета сохранится. Действие нельзя отменить.')) return;
  const epoch = identityEpoch;
  if (['purge', 'restore'].includes(action) && !targetInstanceId) targetInstanceId = runtimeData.instance_id;
  const currentTarget = targetInstanceId === runtimeData.instance_id;
  const pendingKey = action === 'create' ? runtimeData.pending_create_key
    : (action === 'purge' && currentTarget ? runtimeData.pending_purge_key
      : (action === 'restore' && currentTarget ? runtimeData.pending_restore_key : savedOperationKey));
  const pendingRevision = action === 'create' ? runtimeData.pending_create_revision
    : (action === 'purge' && currentTarget ? runtimeData.pending_purge_revision
      : (action === 'restore' && currentTarget ? runtimeData.pending_restore_revision : savedOperationRevision));
  const resuming = ['create', 'purge', 'restore'].includes(action) && typeof pendingKey === 'string'
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
    if (['purge', 'restore'].includes(action)) payload.instance_id = targetInstanceId || runtimeData.instance_id;
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
