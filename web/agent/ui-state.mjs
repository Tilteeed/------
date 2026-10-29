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
  if (status === 409) return { state: 'conflict', message: 'Настройки изменены в другой вкладке. Перечитайте сохранённую версию перед повторным сохранением.' };
  if (status === 503) return { state: 'unavailable', message: 'Среда выполнения недоступна: Docker не подключён. Агент не создан и не запущен.' };
  const detail = body?.detail;
  const message = typeof detail === 'string' ? detail : (!Array.isArray(detail) && typeof detail?.message === 'string' ? detail.message : null);
  return { state: 'error', message: message || (status === 422 ? 'Проверьте имя и инструкции: сервер отклонил настройки.' : 'Не удалось выполнить запрос. Проверьте соединение и повторите попытку.') };
}

// This integration deliberately has no connected lifecycle yet.
export function runtimeView() {
  return {
    label: 'Не подключён',
    description: 'Docker и среда выполнения не подключены. Агент не создан и не запущен.',
  };
}
