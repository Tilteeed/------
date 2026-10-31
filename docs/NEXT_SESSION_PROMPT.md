# Промпт для новой сессии

Скопируй текст ниже в новую сессию. Он не выдаёт новых разрешений на ранее заблокированные операции.

---

Продолжаем практический проект диплома в папке:
`C:/Users/SystemX/Downloads/Диплом/Практика/Вебчик`.

**Сначала прочитай `docs/HANDOFF.md`, `docs/ROADMAP.md`, `docs/verification.md` и `docs/SUPERVISOR_RUN.md`, затем сверь Git и исходники.** Последняя локальная сверка: `main`, HEAD `25d3afafcfc54c1a29a3d0f618569410c15c5300`, незакоммиченные изменения; `origin/main` — только локальный ref, сеть не проверялась. Пользовательская VM-приёмка относится к `4494d7575b0c7534076684e6d8547477b527a42f`, это не требование откатить изменения.

Базовый create/health/lifecycle/remove-retain на ВМ принят пользователем для `4494d757`. Текущий локальный код после него не развёрнут, поэтому стадия 3 для текущей версии не закрыта.

В текущей копии добавлен owner-scoped explicit purge retained-набора с retry/exact replay. Один локальный `scripts/smoke_runtime.py` прошёл: настоящие HTTP/SQLite, fake Docker/XFS/metrics; проверены lifecycle, replay после изменения draft, stale отказ, recovery pending create, owner separation, remove-retain, новое создание, отказ чужому purge и повтор после синтетического сбоя. Это не проверка браузерного JS, Docker, OpenClaw, AF_UNIX или XFS. Partial failed-create cleanup на реальном storage и purge на ВМ не подтверждены.

Не устанавливай Docker на Windows, не подключайся по SSH и не запускай неизменившийся `hermes verify` по кругу. Не публикуй, не делай privileged setup/start, не меняй квоты/ВМ и не удаляй действующие данные без отдельного согласия. Лабораторные UUID/пути/бюджеты не переносить. Порог 50% — общее правило проекта; сохраняй lab/final semantics.

Следующий результат — короткая приёмка актуального кода на Linux-ВМ по `docs/SUPERVISOR_RUN.md`, после отдельного согласия на публикацию/доставку и privileged start. Обычная приёмка: create из кабинета, фактическое состояние, stop/start/restart, remove-retain и новое создание; **не нажимать purge**. Реальный purge/EDQUOT требует отдельного согласия и нового disposable набора данных. Не удалять SQLite ради сброса binding; LLM/chat/Telegram — последующие этапы.

---

Для нового scope отдельно согласуй конкретные системные/VM операции, публикацию и необратимое удаление данных.
