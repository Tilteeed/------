# Промпт для новой сессии

Скопируй текст ниже в новую сессию. Он не выдаёт новых разрешений на ранее заблокированные операции.

---

Продолжаем практический проект диплома в папке:
`C:/Users/SystemX/Downloads/Диплом/Практика/Вебчик`.

**Сначала прочитай `docs/HANDOFF.md`, `docs/ROADMAP.md`, `docs/verification.md` и `docs/SUPERVISOR_RUN.md`, затем сверь Git и исходники.** Последняя локальная сверка: `main`, HEAD `2afe2b5b4da9d5ea1dde1acdac8da015fe591eb7`, с незакоммиченными restore/UI изменениями; сеть не проверялась. Пользовательский Linux-VM отчёт относится к base commit `2afe2b5`, не к текущим незакоммиченным изменениям.

Базовый lifecycle и purge report относятся к `2afe2b5`. Пользователь позже сообщил, что текущая серия функциональных проверок Stage 3 уже завершена и переходят к разработке; не повторять её как следующий шаг. Подробные результаты более поздней проверки не приложены, поэтому точные дополнительные VM-утверждения не добавляю. Новая локальная workspace-browser реализация покрывает только workspace view/download и требует целевой browser/VM acceptance после согласованной доставки.

В текущей копии реализованы restore retained instance и local workspace browser (list/preview/download) для `state/workspace`: owner-scoped, no-follow на Linux, скрытые файлы, credentials/secrets и служебное state не выдаются; preview ограничен 256 KiB, download — 16 MiB. Targeted synthetic tests проходят; `scripts/smoke_runtime.py` и VM/browser acceptance новых изменений не выполнялись. Полноценный model/chat/Gateway integration остаётся следующей стадией.

Не устанавливай Docker на Windows, не подключайся по SSH и не запускай неизменившийся `hermes verify` по кругу. Не публикуй, не делай privileged setup/start, не меняй квоты/ВМ и не удаляй действующие данные без отдельного согласия. Лабораторные UUID/пути/бюджеты не переносить. Порог 50% — общее правило проекта; сохраняй lab/final semantics.

Выбранный продуктовый сценарий Stage 5: платформа поддерживает локальный model endpoint и внешний provider как альтернативы; backend на развёртывании выбирает администратор, пользователи общаются со своим отдельным OpenClaw. Конкретный inference server/provider/model ID и сетевой маршрут ещё не определены. Нужен owner-scoped server-side chat bridge; не подключать глобальный OpenWebUI напрямую к общему Gateway и не передавать Gateway/provider credentials в браузер.

---

Для нового scope отдельно согласуй конкретные системные/VM операции, публикацию и необратимое удаление данных.
