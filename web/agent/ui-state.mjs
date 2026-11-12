export function settingsPayload(name, instructions, revision) {
  if (typeof name !== 'string' || !name.trim() || [...name].length > 80) throw new Error('Укажите имя: от 1 до 80 символов, не только пробелы.');
  if (typeof instructions !== 'string' || [...instructions].length > 8000) throw new Error('Инструкции должны содержать не более 8000 символов.');
  if (!Number.isSafeInteger(revision) || revision < 0) throw new Error('Перечитайте настройки: версия недействительна.');
  return { settings: { name, instructions }, revision };
}

export function controlUiStatus(data, instanceId) {
  const unavailable = { available: false, origin: null };
  if (typeof instanceId !== 'string' || !/^[0-9a-f]{32}$/.test(instanceId)
      || data?.available !== true || typeof data.origin !== 'string' || data.origin.length > 300) return unavailable;
  try {
    const value = new URL(data.origin);
    if (value.protocol !== 'https:' || value.username || value.password
        || value.origin !== data.origin || value.pathname !== '/'
        || value.search || value.hash || !value.hostname.startsWith(`${instanceId}.`)) return unavailable;
    return { available: true, origin: data.origin };
  } catch {
    return unavailable;
  }
}

export function controlUiLaunch(data, expectedOrigin) {
  if (typeof expectedOrigin !== 'string' || data?.origin !== expectedOrigin
      || typeof data.launch_ticket !== 'string' || !/^[A-Za-z0-9_-]{40,64}$/.test(data.launch_ticket)
      || !Number.isInteger(data.expires_in) || data.expires_in < 1 || data.expires_in > 60) return null;
  return { ticket: data.launch_ticket, origin: expectedOrigin };
}

export function draftView(draft) {
  return draft === null
    ? { state: 'empty', name: '', instructions: '', revision: 0, message: 'Настроек пока нет. Сохраните черновик — это не создаст агента.' }
    : { state: 'saved', name: draft.name, instructions: draft.instructions, revision: draft.revision, message: 'Настройки сохранены в БД, но не применены к агенту.' };
}

export function errorView(status, body) {
  if (status === 401) return { state: 'no-auth', message: 'Войдите в Open WebUI, чтобы открыть настройки агента.', href: '/auth?redirect=%2Fagent' };
  if (status === 403) return { state: 'forbidden', message: 'Доступ запрещён. Для этой учётной записи настройки недоступны.' };
  if (status === 409) return { state: 'conflict', message: typeof body?.detail?.message === 'string' ? body.detail.message : 'Настройки изменены в другой вкладке. Перечитайте сохранённую версию перед повторным сохранением.' };
  if (status === 503 && !body?.detail?.message) return { state: 'unavailable', message: 'Среда выполнения недоступна: Docker не подключён. Обновите состояние: результат операции может быть неизвестен.' };
  if (status === 503 && body?.detail?.code === 'runtime_not_connected') return { state: 'unavailable', message: 'Среда выполнения недоступна: Docker не подключён.' };
  const detail = body?.detail;
  const message = typeof detail === 'string' ? detail : (!Array.isArray(detail) && typeof detail?.message === 'string' ? detail.message : null);
  return { state: 'error', message: message || (status === 422 ? 'Проверьте имя и инструкции: сервер отклонил настройки.' : 'Не удалось выполнить запрос. Проверьте соединение и повторите попытку.') };
}

export function runtimeView(runtime, connected = false) {
  if (!connected) return {
    label: 'Не подключён',
    description: 'Docker и среда выполнения не подключены. Агент не создан и не запущен.',
  };
  if (runtime?.pending_restore_key) {
    if (runtime.state === 'failed') return {
      label: 'Восстановление не завершено',
      description: 'Сохранённые данные не удалены. Продолжите восстановление или удалите экземпляр с сохранением данных.',
    };
    return {
      label: 'Восстановление',
      description: 'Повторно подключаем сохранённые данные к тому же экземпляру; черновик не применяется.',
    };
  }
  const states = {
    absent: ['Не создан', 'Supervisor подключён. Можно создать персональный экземпляр после сохранения настроек.'],
    not_created: ['Не создан', 'Supervisor подключён. Сохраните настройки и создайте экземпляр.'],
    running: ['Запущен', 'Контейнер работает. Готовность Gateway показана отдельно; модель и чат пока не подключены.'],
    stopped: ['Остановлен', 'Контейнер остановлен. Персональные данные сохранены.'],
    paused: ['Приостановлен', 'Контейнер заморожен. Можно запустить, остановить или перезапустить его.'],
    restarting: ['Перезапускается', 'Docker сообщает о перезапуске. Обновите состояние через несколько секунд.'],
    created: ['Создан', 'Контейнер создан, но пока не запущен.'],
    preparing: ['Подготовка', 'Supervisor готовит персональное хранилище и проверяет квоты.'],
    reserved: ['Зарезервирован', 'Запрос сохранён. Работающий контейнер ещё не подтверждён.'],
    failed: ['Ошибка', 'Операция не завершена. Данные и резерв сохранены; обновите состояние и повторите запрос.'],
    removed: ['Удалён', 'Контейнер удалён, персональные данные сохранены и продолжают занимать дисковый бюджет.'],
    purging: ['Удаление данных', 'Контейнер удалён. Полное удаление данных или освобождение квоты ещё не подтверждено; повторите операцию.'],
    purged: ['Полностью удалён', 'Контейнер и его данные удалены, а дисковая квота освобождена.'],
    unavailable: ['Нет связи', 'Supervisor недоступен. Состояние контейнера неизвестно — это не подтверждение его остановки.'],
  };
  const value = states[runtime?.state] || ['Состояние уточняется', 'Получен ответ supervisor. Обновите состояние через несколько секунд.'];
  return { label: value[0], description: value[1] };
}

export function modelStatusLabel(status) {
  return ({configured: 'Модель настроена; проверка не выполнена', unavailable: 'Сервис модели недоступен', model_missing: 'Модель не найдена в последнем полученном списке', model_present: 'Модель есть в последнем полученном списке; ответ не подтверждён'})[status] || 'Не подключена / не подтверждена';
}
export function createReadinessPoll({ refresh, invalidate, makeInvalidation = () => invalidate, interval = 5000, maxAge = 15000,
  requestTimeout = 10000, setTimer = setTimeout, clearTimer = clearTimeout, now = () => Date.now() }) {
  let active = false, generation = 0, freshness = 0, next = null, expiry = null, pending = null;
  function armExpiry(invalidateRequest) {
    if (expiry !== null) clearTimer(expiry);
    expiry = setTimer(() => { expiry = null; freshness += 1; invalidateRequest(); }, maxAge);
  }
  async function run(epoch) {
    const invalidateRequest = makeInvalidation();
    if (expiry === null) armExpiry(invalidateRequest);
    const version = freshness, controller = new AbortController(), deadline = now() + maxAge;
    const current = () => active && epoch === generation && version === freshness
      && !controller.signal.aborted && now() < deadline;
    let timeout;
    const timedOut = new Promise((_, reject) => {
      timeout = setTimer(() => { controller.abort(); reject(new Error('readiness timeout')); }, requestTimeout);
    });
    pending = { controller, timeout };
    try {
      await Promise.race([refresh(current, controller.signal), timedOut]);
      if (!current()) return;
      armExpiry(invalidateRequest);
    } catch {
      if (!active || epoch !== generation) return;
      if (expiry !== null) clearTimer(expiry);
      expiry = null;
      freshness += 1;
      invalidateRequest();
    } finally {
      clearTimer(timeout);
      if (pending?.controller === controller) pending = null;
      if (active && epoch === generation) next = setTimer(() => { next = null; void run(epoch); }, interval);
    }
  }
  return {
    start() {
      if (!active) {
        active = true; generation += 1;
        void run(generation);
      }
    },
    stop() {
      active = false; generation += 1;
      if (next !== null) clearTimer(next);
      if (expiry !== null) clearTimer(expiry);
      if (pending !== null) { clearTimer(pending.timeout); pending.controller.abort(); pending = null; }
      next = expiry = null;
    },
  };
}


export function createModelUpdates({ apply, isAuthorized, invalidate = () => {}, getSession = () => null,
  maxAge = 15000, now = () => Date.now(), setTimer = setTimeout, clearTimer = clearTimeout }) {
  let serial = 0, accepted = 0, generation = 0, expiry = null;
  function reset() {
    generation++;
    if (expiry !== null) clearTimer(expiry);
    expiry = null;
  }
  return {
    begin() {
      const id = ++serial, version = generation, session = getSession(), deadline = now() + maxAge;
      const valid = () => version === generation && session === getSession() && id >= accepted && isAuthorized();
      return { fail() {
        if (!valid()) return false;
        accepted = id;
        reset();
        invalidate();
        return true;
      }, apply(value) {
        if (!valid() || now() >= deadline) return false;
        accepted = id;
        if (expiry !== null) clearTimer(expiry);
        expiry = setTimer(() => { expiry = null; generation++; invalidate(); }, deadline - now());
        apply(value);
        return true;
      } };
    },
    invalidate: reset,
  };
}
