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
  $('refresh-events').disabled = !authenticated || busy || eventsBusy;
  $('main').setAttribute('aria-busy', String(busy));
  $('save').textContent = busy ? 'Подождите…' : 'Сохранить настройки';
}

function revoke() {
  authenticated = false;
  identityEpoch += 1;
  dirty = false;
  $('identity').textContent = 'Учётная запись не подтверждена';
  $('agent-name').value = '';
  $('instructions').value = '';
  $('revision').textContent = 'Версия не загружена';
  $('events-list').replaceChildren();
  $('events-status').textContent = 'События недоступны без подтверждённого доступа.';
}

function showError(error) {
  const view = errorView(error.status || 0, error.body);
  if (error.status === 401 || error.status === 403) revoke();
  if (error.status === 409) conflict = true;
  notice(view.state, view.message, view.href);
  controls();
}

async function request(path = '', method = 'GET', payload) {
  let token;
  try { token = localStorage.getItem('token'); } catch { /* Treat unavailable storage as signed out. */ }
  if (!token) throw { status: 401 };
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
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
    $('identity').textContent = data.user.name;
    const runtime = runtimeView(data.runtime);
    $('runtime-badge').textContent = runtime.label;
    $('runtime-description').textContent = runtime.description;
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
