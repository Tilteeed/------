export function settingsPayload(name, instructions, revision) {
  if (typeof name !== 'string' || !name.trim() || [...name].length > 80) throw new Error('Укажите имя: от 1 до 80 символов, не только пробелы.');
  if (typeof instructions !== 'string' || [...instructions].length > 8000) throw new Error('Инструкции должны содержать не более 8000 символов.');
  if (!Number.isSafeInteger(revision) || revision < 0) throw new Error('Перечитайте настройки: версия недействительна.');
  return { settings: { name, instructions }, revision };
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
