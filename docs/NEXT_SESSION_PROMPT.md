# Промпт для новой сессии

Скопируй текст ниже в новую сессию. Он не выдаёт новых разрешений на ранее заблокированные операции.

---

Продолжаем практический проект диплома в папке:
`C:/Users/SystemX/Downloads/Диплом/Практика/Вебчик`.

**Сначала прочитай `docs/HANDOFF.md`, `docs/ROADMAP.md`, `docs/verification.md` и `docs/SUPERVISOR_RUN.md`, затем сверь Git и исходники.** Последняя локальная сверка: `main`, HEAD `e3533e99b36ac9265426c36f1ee2b3c9f14303cf`, с незакоммиченными исправлениями purge; сеть не проверялась. Пользовательская VM-приёмка относится к `4494d7575b0c7534076684e6d8547477b527a42f`, не требование откатывать изменения.

Базовый create/health/lifecycle/remove-retain на ВМ принят пользователем для `4494d757`. Текущий локальный код после него не развёрнут, поэтому стадия 3 для текущей версии не закрыта.

В текущей копии исправлены purge blockers: существующая volume SQLite открывается `rw` без создания; Linux tree traversal привязан к directory FDs; instance snapshot/token/create payload scrub-ятся до освобождения дискового резерва, checkpoint failure оставляет reservation и retry. Локальные supervisor tests, API tests, UI syntax/state tests и `scripts/smoke_runtime.py` прошли. Smoke использует real HTTP/SQLite и fake Docker/XFS/metrics; Linux dirfd/XFS/Docker/browser behavior не подтверждены. Cleanup partial failed-create journal отдельно не проверен.

Не устанавливай Docker на Windows, не подключайся по SSH и не запускай неизменившийся `hermes verify` по кругу. Не публикуй, не делай privileged setup/start, не меняй квоты/ВМ и не удаляй действующие данные без отдельного согласия. Лабораторные UUID/пути/бюджеты не переносить. Порог 50% — общее правило проекта; сохраняй lab/final semantics.

Следующий результат — короткая приёмка актуального кода на Linux-ВМ по `docs/SUPERVISOR_RUN.md`, после отдельного согласия на публикацию/доставку и privileged start. Обычная приёмка: create из кабинета, фактическое состояние, stop/start/restart, remove-retain и новое создание; **не нажимать purge**. Реальный purge/EDQUOT требует отдельного согласия и нового disposable набора данных. Не удалять SQLite ради сброса binding; LLM/chat/Telegram — последующие этапы.

---

Для нового scope отдельно согласуй конкретные системные/VM операции, публикацию и необратимое удаление данных.
